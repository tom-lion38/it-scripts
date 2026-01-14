# Plex Media Server — Auto-install (Linux)

Script Bash “one-shot” pour installer **Plex Media Server** proprement et automatiquement sur Linux, puis **démarrer le service** et (optionnel) **ouvrir le port 32400/tcp** sur le firewall.

Objectif : tu lances, tu réponds à 1–2 questions, et tu finis avec Plex accessible via navigateur.

---

## Ce que le script fait exactement

### 1) Détection de la distribution (via gestionnaire de paquets)
Le script détecte automatiquement comment installer Plex selon ta distro :

- **Debian / Ubuntu** → `apt`
- **Fedora / RHEL / CentOS / Rocky / Alma** → `dnf` ou `yum`

Si aucun de ces gestionnaires n’est trouvé, le script s’arrête (pour éviter les installations “bancales”).

### 2) Ajout du dépôt officiel Plex
Plex se met à jour via un dépôt officiel :

- **Debian/Ubuntu**
  - Télécharge la clé de signature Plex et la stocke dans `/etc/apt/keyrings/plex.gpg`
  - Ajoute la source APT dans `/etc/apt/sources.list.d/plexmediaserver.list`
  - Fait un `apt-get update`

- **Fedora/RHEL**
  - Crée `/etc/yum.repos.d/plex.repo`
  - Configure `gpgcheck=1` + la clé officielle Plex
  - Utilise ensuite `dnf`/`yum` pour installer

### 3) Installation du paquet
Le script installe le paquet officiel :
- `plexmediaserver`

### 4) Démarrage du service (systemd)
Le script active et démarre automatiquement :
- `plexmediaserver`

Donc après reboot, Plex redémarre tout seul.

### 5) Firewall (optionnel)
Le script te demande si tu veux ouvrir :
- **32400/tcp** (interface web Plex)

Il gère automatiquement :
- **UFW** (Ubuntu/Debian souvent)
- **firewalld** (RHEL/Fedora souvent)

Si aucun des deux n’est installé, il te prévient et te laisse gérer manuellement.

---

## Prérequis (important)

### Prérequis techniques
- Linux avec **systemd** (`systemctl` doit exister)
- Accès root : `sudo`
- Connexion Internet (repo Plex + installation paquets)

### Réseau / accès
- Pour accéder à Plex depuis un autre PC/téléphone sur ton LAN : il faut connaître l’IP du serveur
- Si tu veux accéder depuis l’extérieur : ça se gère **dans Plex** (Remote Access) + port forwarding/NAT (hors scope du script)
