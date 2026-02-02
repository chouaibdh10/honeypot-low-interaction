import argparse
import logging
import signal
import socket
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class HoneypotConfig:
    # Par dfaut on coute en local pour viter des restrictions Windows (WinError 10013)
    host: str = "127.0.0.1"
    port: int = 2222
    backlog: int = 50
    client_timeout_s: float = 10.0
    recv_buf: int = 1024
    banner: str = "Debian GNU/Linux 11"
    creds_log_path: Path = Path("honeypot_creds.log")
    event_log_path: Path = Path("honeypot.log")
    simulate_delay_s: float = 0.3

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _safe_recv_line(client: socket.socket, bufsize: int) -> str:
    data = client.recv(bufsize)
    return data.decode("utf-8", errors="replace").strip()


def _setup_logging(event_log_path: Path) -> logging.Logger:
    logger = logging.getLogger("honeypot")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        fmt="%(asctime)sZ | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    file_handler = logging.FileHandler(event_log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


def _log_creds(creds_log_path: Path, ip: str, username: str, password: str) -> None:
    # Format simple + horodatage, facile  parser
    entry = f"{_utc_now_iso()} | IP={ip} | USER={username} | PASS={password}\n"
    creds_log_path.parent.mkdir(parents=True, exist_ok=True)
    with creds_log_path.open("a", encoding="utf-8", newline="") as f:
        f.write(entry)


def _handle_client(client: socket.socket, addr, config: HoneypotConfig, logger: logging.Logger) -> None:
    ip = addr[0]
    logger.info("Connexion entrante: ip=%s port=%s", ip, addr[1])

    try:
        client.settimeout(config.client_timeout_s)

        # 1) Bannire + login
        client.sendall((config.banner + "\nlogin: ").encode("utf-8"))
        username = _safe_recv_line(client, config.recv_buf)
        time.sleep(config.simulate_delay_s)

        # 2) Password
        client.sendall(b"password: ")
        password = _safe_recv_line(client, config.recv_buf)
        time.sleep(config.simulate_delay_s)

        _log_creds(config.creds_log_path, ip=ip, username=username, password=password)
        logger.info("Tentative capture: ip=%s user=%r", ip, username)

        # 3) Refus pour ne pas donner accs
        client.sendall(b"Login incorrect\n")
    except socket.timeout:
        logger.info("Timeout client: ip=%s", ip)
    except ConnectionError as e:
        logger.info("Connexion interrompue: ip=%s err=%s", ip, e)
    except Exception as e:
        logger.exception("Erreur avec %s: %s", ip, e)
    finally:
        try:
            client.close()
        except Exception:
            pass


def run_advanced_honeypot(config: Optional[HoneypotConfig] = None) -> None:
    config = config or HoneypotConfig()
    logger = _setup_logging(config.event_log_path)

    stop_event = threading.Event()

    def _request_stop(*_args):
        stop_event.set()

    try:
        signal.signal(signal.SIGINT, _request_stop)
        signal.signal(signal.SIGTERM, _request_stop)
    except Exception:
        # Windows/threads: certains signaux peuvent  etre indisponibles
        pass

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((config.host, config.port))
        except PermissionError as e:
            logger.error(
                "Impossible d'couter sur %s:%s (%s). "
                "Sur Windows: essayez --host 127.0.0.1 (local), un autre --port, "
                "ou autorisez Python dans le pare-feu / lancez en admin.",
                config.host,
                config.port,
                e,
            )
            raise
        server.listen(config.backlog)
        server.settimeout(1.0)  # permet de vrifier stop_event rgulirement

        logger.info("Honeypot lanc: host=%s port=%s", config.host, config.port)

        threads: list[threading.Thread] = []
        try:
            while not stop_event.is_set():
                try:
                    client, addr = server.accept()
                except socket.timeout:
                    continue

                t = threading.Thread(
                    target=_handle_client,
                    args=(client, addr, config, logger),
                    daemon=True,
                )
                t.start()
                threads.append(t)
        finally:
            stop_event.set()
            logger.info("Arrat demand, fermeture du serveur...")
            # Threads en daemon: pas obligatoire de join, mais on tente un join court
            for t in threads[-100:]:
                t.join(timeout=0.2)

def _parse_args() -> HoneypotConfig:
    parser = argparse.ArgumentParser(description="Low-interaction SSH-like honeypot (TCP)")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Adresse d'coute (dfaut: 127.0.0.1, local)",
    )
    parser.add_argument("--port", type=int, default=2222, help="Port d'coute (dfaut: 2222)")
    parser.add_argument("--backlog", type=int, default=50, help="Backlog listen() (dfaut: 50)")
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Timeout client en secondes (dfaut: 10)",
    )
    parser.add_argument(
        "--banner",
        default="Debian GNU/Linux 11",
        help="Bannire affiche (dfaut: Debian GNU/Linux 11)",
    )
    parser.add_argument(
        "--creds-log",
        default="honeypot_creds.log",
        help="Fichier log des identifiants (dfaut: honeypot_creds.log)",
    )
    parser.add_argument(
        "--event-log",
        default="honeypot.log",
        help="Fichier log des vnements (dfaut: honeypot.log)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.3,
        help="Dlai de simulation (secondes) entre prompts (dfaut: 0.3)",
    )
    args = parser.parse_args()

    return HoneypotConfig(
        host=args.host,
        port=args.port,
        backlog=args.backlog,
        client_timeout_s=args.timeout,
        banner=args.banner,
        creds_log_path=Path(args.creds_log),
        event_log_path=Path(args.event_log),
        simulate_delay_s=args.delay,
    )


if __name__ == "__main__":
    run_advanced_honeypot(_parse_args())