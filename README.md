# Honeypot Low Interaction

Ce projet est un honeypot réseau basique écrit en Python. Il simule un faux service SSH sur le port 2222 afin de piéger les attaquants et de collecter les identifiants utilisés lors des tentatives de connexion.

## Fonctionnement

- Le script lance un serveur TCP qui écoute (par défaut) sur `127.0.0.1:2222` (local uniquement).
- Lorsqu'un client se connecte, il affiche une bannière et demande un login puis un mot de passe.
- Les identifiants saisis sont enregistrés dans `honeypot_creds.log`.
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

### Changer l'adresse / le port

Dans [code.py](code.py), modifiez les constantes en haut du fichier :

- `HOST` (par défaut `127.0.0.1`)
- `PORT` (par défaut `2222`)

### Exposer sur le réseau (attention)

- Pour accepter des connexions depuis d'autres machines du réseau, changez `HOST` en `0.0.0.0` dans [code.py](code.py).
- Sous Windows, il peut être nécessaire d'autoriser Python dans le pare-feu (sinon erreur du type `WinError 10013`).

### Arrêt

- Appuyez sur `Ctrl+C` pour arrêter proprement le serveur.

## Tester en local (sans exposer Internet)

1. Lancez le serveur (la fenêtre doit rester ouverte) :
   ```bash
   python code.py
   ```
   Vous devez voir :
   ```
   [+] Honeypot lancé sur 127.0.0.1:2222
   ```

2. Dans un autre terminal, connectez-vous en TCP :

   - Linux/WSL (recommandé) :
     ```bash
     nc 127.0.0.1 2222
     ```
     Si `nc` n'est pas installé :
     ```bash
     sudo apt update
     sudo apt install -y netcat-openbsd
     ```

   - Windows (si Telnet est activé) :
     ```bash
     telnet 127.0.0.1 2222
     ```

3. Tapez un login puis un mot de passe (n'importe quoi). Le serveur répondra `Login incorrect`.

4. Vérifiez les identifiants capturés dans `honeypot_creds.log`.

### Pourquoi `ssh` peut ne pas fonctionner ?

Ce honeypot est "low-interaction" : il n'implémente pas le vrai protocole SSH.
Il simule seulement une conversation texte `login/password` sur un socket TCP.
Donc `ssh -p 2222 ...` peut échouer ou se fermer immédiatement, ce qui est normal.

## Avertissement

Ce honeypot est à but éducatif et ne doit pas être utilisé sur des systèmes de production ou exposé sur Internet sans précautions. Il ne protège pas contre les attaques, mais permet de surveiller les tentatives d'intrusion.
