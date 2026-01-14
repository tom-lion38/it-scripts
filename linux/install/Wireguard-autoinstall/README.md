# WireGuard — Auto-install (Debian/Ubuntu)

Script Bash interactif pour installer et configurer un **serveur WireGuard** sur Debian/Ubuntu, avec génération de **profils clients** prêts à importer.

Objectif : tu lances → tu réponds → WireGuard tourne → tu repars avec des fichiers `.conf` (et QR si dispo).

---

## Ce que le script fait exactement

### 1) Vérifications
Le script vérifie :
- exécution en **root** (`sudo`)
- présence de `apt-get` (Debian/Ubuntu)
- présence de `systemctl` (systemd)
- présence de `ip` (iproute2)

### 2) Installation des paquets
Il installe :
- `wireguard` (kernel module + outils)
- `iptables`, `iproute2`
- `netfilter-persistent` + `iptables-persistent` (pour rendre les règles iptables persistantes)
- `curl` (détection d’IP publique)
- (optionnel) `qrencode` si disponible, pour afficher un QR dans le terminal

### 3) Détection réseau
Le script détecte :
- l’interface réseau par défaut (celle qui sort sur Internet)
- l’IP locale
- essaie de détecter une IP publique pour te proposer un endpoint par défaut

### 4) Routage IPv4
Active et rend persistant :
- `net.ipv4.ip_forward=1`
via :
- `/etc/sysctl.d/99-wireguard-ipforward.conf`

### 5) Création du serveur WireGuard
- Génère une paire de clés serveur (privée/publique)
- Crée `/etc/wireguard/wg0.conf`
- Définit :
  - `Address` du serveur (ex: `10.8.0.1/24`)
  - `ListenPort` (ex: `51820`)
  - `PrivateKey` du serveur
- Ajoute des règles `PostUp` / `PostDown` pour le NAT et le forwarding

### 6) NAT / Forwarding (iptables)
Le script :
- ajoute une règle **MASQUERADE** pour que les clients sortent sur Internet via le serveur
- ajoute les règles FORWARD nécessaires
- sauvegarde via `netfilter-persistent save`

### 7) Génération des clients
Pour chaque client :
- génère une paire de clés client
- ajoute un bloc `[Peer]` dans `wg0.conf`
- génère un fichier client :
  - `/root/wireguard-clients/<client>.conf`
- affiche un QR si `qrencode` est installé (pratique mobile)

---

## Prérequis

- Debian / Ubuntu
- accès root (`sudo`)
- accès Internet
- si serveur derrière une box/NAT : redirection de port UDP vers le serveur

---

## Installation / Exécution

```bash
chmod +x wireguard-autoinstall.sh
sudo ./wireguard-autoinstall.sh
