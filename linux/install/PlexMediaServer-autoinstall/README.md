# Plex Media Server — Auto-install (Linux)

Script Bash interactif et fiable pour installer **Plex Media Server** automatiquement :
- **Debian/Ubuntu** via dépôt officiel **APT**
- **Fedora/RHEL/CentOS** via dépôt officiel **DNF/YUM**

Le script installe Plex, démarre le service et (optionnel) ouvre le port `32400/tcp`.

## Prérequis
- Linux avec **systemd** (`systemctl`)
- Accès root (`sudo`)
- Connexion Internet

## Installation / Exécution
Depuis le dossier où se trouve le script :

```bash
chmod +x plex-autoinstall.sh
sudo ./plex-autoinstall.sh
