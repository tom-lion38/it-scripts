# it-scripts

Mes scripts d'installation pour monter vite un service sur une machine neuve. Je les
ai écrits pour mon lab, en essayant de les garder assez génériques pour qu'ils
servent à d'autres.

Ils sont interactifs : ils posent des questions, montrent ce qu'ils vont faire et
demandent confirmation avant les étapes risquées. Lis quand même le script avant
de le lancer, surtout sur une machine qui compte.

## Linux

Prévus pour Debian et Ubuntu. Celui de Plex marche aussi sur Fedora, RHEL et
dérivés.

| Dossier | Ce que ça installe |
| :-- | :-- |
| [linux/install/OpenVPN-autoinstall](linux/install/OpenVPN-autoinstall) | Serveur OpenVPN avec sa PKI Easy-RSA, NAT, et un premier profil client `.ovpn` |
| [linux/install/Wireguard-autoinstall](linux/install/Wireguard-autoinstall) | Serveur WireGuard, NAT, profils clients `.conf` et QR code |
| [linux/install/SMB-autoinstall](linux/install/SMB-autoinstall) | Partage Samba sur une partition ou un dossier existant (ou sur un disque vide, avec confirmation) |
| [linux/install/PlexMediaServer-autoinstall](linux/install/PlexMediaServer-autoinstall) | Plex Media Server depuis le dépôt officiel de Plex (apt ou dnf/yum) |

## Windows

| Dossier | Ce que ça installe |
| :-- | :-- |
| [windows/install/Wireguard-autoinstall](windows/install/Wireguard-autoinstall) | Serveur WireGuard sur Windows, en PowerShell |

## Pour Proxmox

Les scripts propres à Proxmox (post-installation, création de CT, sauvegardes,
alertes) sont dans un dépôt à part :
[proxmox-scripts](https://github.com/tom-lion38/proxmox-scripts).

## Ce qu'il n'y a pas ici

Aucun mot de passe, aucune clé, aucune adresse de mon réseau. Les valeurs que tu
vois dans les exemples sont génériques, à remplacer par les tiennes.
