# Samba (SMB), installation et configuration automatiques (Debian/Ubuntu)

Script Bash interactif pour **installer et configurer Samba** (SMB) sur Debian/Ubuntu, avec une approche “zéro question après” :
- installation des paquets
- choix du stockage (partition existante / dossier / création partition sur disque vide)
- montage persistant (fstab par UUID) si besoin
- configuration Samba propre + backups
- création d’utilisateurs Samba (mot de passe saisi au clavier, jamais dans le script)
- création de partages multiples (permissions correctes, groupe, setgid)
- option firewall UFW

---

## Ce que fait le script (en clair)

### 1) Installation
Installe :
- `samba` (service SMB)
- `smbclient` (outil de test)
- `cifs-utils` (utile côté montage SMB si besoin)
- `acl` + `attr` (droits/ACL propres)

### 2) Choix du stockage (3 modes)
Le script te propose **3 modes** :

#### Mode 1 (sans risque) : utiliser une partition existante déjà formatée
- tu choisis une partition (ex: `/dev/sdb1`)
- le script la **monte** dans un dossier (ex: `/srv/storage`)
- il ajoute une entrée dans `/etc/fstab` via UUID (persistant après reboot)
- puis il crée tes dossiers de partage dedans

Recommandé si tu as déjà préparé ton disque ou ta partition.

#### Mode 2 (sans risque) : utiliser un dossier existant
- tu donnes un chemin (ex: `/srv/shares`)
- aucun montage, aucun formatage
- le script partage ce dossier (et ses sous-dossiers)

Recommandé si ton stockage est déjà monté (ZFS, LVM, RAID, etc.).

#### Mode 3 (avancé, dangereux) : créer et formater une partition sur un disque VIDE
- tu choisis un **disque** (ex: `/dev/sdb`)
- le script refuse si le disque a déjà des partitions (sécurité)
- il crée une table GPT + 1 partition :
  - soit de la taille que tu veux (GiB)
  - soit tout le disque
- il formate en `ext4` ou `xfs`
- il monte + ajoute `fstab` via UUID

Attention : ce mode écrit sur le disque. Si tu te trompes de disque, tu pleures. Le script demande une confirmation.

---

## Prérequis
- Debian / Ubuntu
- accès root (`sudo`)
- `systemd` (normalement OK)
- un accès LAN fonctionnel

---

## Installation / Exécution

```bash
chmod +x smb-autosetup.sh
sudo ./smb-autosetup.sh
