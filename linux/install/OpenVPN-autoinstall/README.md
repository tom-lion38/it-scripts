# OpenVPN autoinstall (Debian/Ubuntu)

Script Bash interactif pour installer et configurer un serveur OpenVPN sur Debian/Ubuntu (logique testée Debian 12).
Il installe OpenVPN + Easy-RSA, génère les certificats, configure le serveur, ajoute le NAT iptables, et crée un profil client `.ovpn`.

## Prérequis
- Debian / Ubuntu
- Accès root (`sudo`)
- Support TUN disponible : `/dev/net/tun` (souvent OK, sinon ta VM est triste)

## Installation / Exécution
Depuis ce dossier :

```bash
chmod +x openvpn-server-installer.sh
sudo ./openvpn-server-installer.sh
