import socket
HOST = "127.0.0.1"  # local uniquement (plus simple sur Windows)
PORT = 2222
BACKLOG = 10
RECV_BUF = 1024
BANNER = "Debian GNU/Linux 11"
CREDS_LOG = "honeypot_creds.log"


def run_honeypot() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((HOST, PORT))
    except PermissionError as e:
        print(f"[!] Erreur: impossible d'\u00e9couter sur {HOST}:{PORT} ({e})")
        print("    Astuces: change HOST/PORT, ou autorise Python dans le pare-feu.")
        raise
    except OSError as e:
        print(f"[!] Erreur bind {HOST}:{PORT}: {e}")
        print("    Astuce: le port est peut-\u00eatre d\u00e9j\u00e0 utilis\u00e9. Change PORT.")
        raise

    server.listen(BACKLOG)
    print(f"[+] Honeypot lanc\u00e9 sur {HOST}:{PORT}")

    try:
        while True:
            client, addr = server.accept()
            ip = addr[0]
            print(f"[!] Connexion entrante: {ip}")

            try:
                client.sendall((BANNER + "\nlogin: ").encode("utf-8"))
                username = client.recv(RECV_BUF).decode("utf-8", errors="replace").strip()

                client.sendall(b"password: ")
                password = client.recv(RECV_BUF).decode("utf-8", errors="replace").strip()

                line = f"IP: {ip} | User: {username} | Pass: {password}\n"
                print(" -> Tentative captur\u00e9e:", line.strip())

                with open(CREDS_LOG, "a", encoding="utf-8") as f:
                    f.write(line)

                client.sendall(b"Login incorrect\n")
            except Exception as e:
                print(f"[!] Erreur avec {ip}: {e}")
            finally:
                try:
                    client.close()
                except Exception:
                    pass
    except KeyboardInterrupt:
        print("\n[+] Arr\u00eat (Ctrl+C)")
    finally:
        try:
            server.close()
        except Exception:
            pass


if __name__ == "__main__":
    run_honeypot()