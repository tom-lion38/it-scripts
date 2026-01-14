# OpenVPN — Auto-install (Debian/Ubuntu)

Script Bash interactif pour installer et configurer un **serveur OpenVPN** sur Debian/Ubuntu, puis générer **un premier profil client `.ovpn`** prêt à importer.

Objectif : tu lances → tu réponds aux questions → le serveur démarre → tu récupères ton fichier client.

---

## Ce que le script fait exactement

### 1) Vérifications de base
Le script vérifie :
- que tu es **root** (`sudo`)
- que le device TUN existe : **`/dev/net/tun`**
  - indispensable pour OpenVPN (souvent un souci en VM si TUN est désactivé)
- que `apt-get` est présent (script prévu pour Debian/Ubuntu)
- et affiche un avertissement si l’OS n’est pas Debian/Ubuntu

### 2) Détection réseau
Le script détecte :
- l’interface réseau par défaut (celle qui sort sur Internet)
- l’IP locale de cette interface
- essaie aussi de détecter l’**IP publique** (si possible), pour te proposer un défaut intelligent

### 3) Installation des paquets
Le script installe automatiquement :
- `openvpn`
- `easy-rsa`
- `iptables`
- `iproute2`
- `ca-certificates`
- `curl`
- `netfilter-persistent` + `iptables-persistent` (pour **sauvegarder iptables après reboot**)

### 4) Activation du routage IPv4
Le script active le forwarding :
- `net.ipv4.ip_forward=1`

Et le rend **persistant** via :
- `/etc/sysctl.d/99-openvpn-ipforward.conf`

### 5) Génération de la PKI (certificats)
Le script initialise Easy-RSA et génère :
- la CA (Certificate Authority)
- le certificat serveur
- le certificat du premier client
- les clés privées associées
- un fichier **`tls-crypt.key`** (chiffre/authentifie le canal de contrôle TLS)

Tout est stocké dans :
- `/etc/openvpn/pki`

### 6) Configuration du serveur OpenVPN
Le script écrit :
- `/etc/openvpn/server/server.conf`

Inclut :
- protocole UDP/TCP
- port
- réseau VPN (CIDR → converti en masque)
- push de route par défaut (tout le trafic passe dans le VPN)
- push DNS (Cloudflare/Google/Quad9/OpenDNS ou DNS du serveur)
- chiffrement (AES-GCM + SHA256 + TLS min 1.2)

### 7) NAT / Firewall (iptables)
Le script ajoute des règles iptables pour :
- faire du **NAT** (MASQUERADE) du réseau VPN vers ton interface WAN
- autoriser le forwarding tun0 ↔ interface WAN

Puis sauvegarde les règles via :
- `netfilter-persistent save`

### 8) Firewall UFW (optionnel)
Si tu acceptes et si UFW est installé, le script ajoute :
- une règle `allow <port>/<proto>`

Si UFW est inactif, il te prévient (il n’active pas UFW de force).

### 9) Démarrage du service
Le script active et démarre :
- `openvpn-server@server`

### 10) Génération du profil client `.ovpn`
Le script génère un fichier client complet (certificat + clé + tls-crypt intégrés) dans :
- `/root/openvpn-clients/<client>.ovpn`

---

## Prérequis (important)

### Technique
- Debian / Ubuntu
- systemd (normal sur Debian/Ubuntu)
- accès root (`sudo`)
- TUN activé (`/dev/net/tun`)

### Réseau
- Si le serveur est derrière une box : il faudra faire une **redirection de port** vers le serveur
  - ex : UDP 1194 → IP du serveur
- Si tu utilises un domaine (DuckDNS, etc.) : mets-le comme `REMOTE_HOST`
