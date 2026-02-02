# Honeypot Low Interaction

Ce projet est un honeypot réseau basique écrit en Python. Il simule un faux service SSH sur le port 2222 afin de piéger les attaquants et de collecter les identifiants utilisés lors des tentatives de connexion.

## Fonctionnement

- Le script lance un serveur TCP qui écoute (par défaut) sur `127.0.0.1:2222` (local uniquement).
- Lorsqu'un client se connecte, il affiche une bannière et demande un login puis un mot de passe.
- Les tentatives sont enregistrées dans deux fichiers :
  - `honeypot_creds.log` : identifiants saisis (avec horodatage UTC)
  - `honeypot.log` : événements (connexions, timeouts, erreurs)
- Après la saisie, le script simule un échec de connexion (`Login incorrect`) puis ferme la connexion.

## Utilisation

### Prérequis

- Python 3.9+ recommandé.

### Lancer le honeypot

1. Exécutez le script Python :
   ```bash
   python code.py
   ```
2. Le honeypot sera accessible sur `127.0.0.1:2222`.
3. Les tentatives de connexion seront affichées dans la console et enregistrées dans `honeypot_creds.log`.

### Options utiles

- Changer le port et l'adresse d'écoute :
  ```bash
  python code.py --host 127.0.0.1 --port 2222
  ```

### Exposer sur le réseau (attention)

- Pour accepter des connexions depuis d'autres machines du rseau :
  ```bash
  python code.py --host 0.0.0.0 --port 2222
  ```
- Sous Windows, il peut etre ncessaire d'autoriser Python dans le pare-feu (sinon erreur du type `WinError 10013`).
- Changer la bannière affichée :
  ```bash
  python code.py --banner "Debian GNU/Linux 11"
  ```
- Ajuster le timeout client (secondes) :
  ```bash
  python code.py --timeout 10
  ```
- Changer les fichiers de logs :
  ```bash
  python code.py --creds-log honeypot_creds.log --event-log honeypot.log
  ```

### Arrêt

- Appuyez sur `Ctrl+C` pour arrêter proprement le serveur.

## Tester en local (sans exposer Internet)

- Depuis la même machine, vous pouvez tester une connexion TCP simple :
  - Windows (si Telnet est activé) :
    ```bash
    telnet 127.0.0.1 2222
    ```
  - Ou avec le client SSH (si installé) :
    ```bash
    ssh -p 2222 test@127.0.0.1
    ```

## Avertissement

Ce honeypot est à but éducatif et ne doit pas être utilisé sur des systèmes de production ou exposé sur Internet sans précautions. Il ne protège pas contre les attaques, mais permet de surveiller les tentatives d'intrusion.
