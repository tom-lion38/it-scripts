#!/usr/bin/env bash
# smb-autosetup.sh
# Interactive Samba (SMB) installer + storage setup for Debian/Ubuntu.
# Features:
# - Lists disks/partitions (lsblk)
# - Option A (safe): use an existing partition or existing folder (no formatting)
# - Option B (advanced): create + format a new partition on an empty disk (DANGEROUS if misused)
# - Mounts it persistently via /etc/fstab (UUID)
# - Configures Samba + creates shares + creates Samba users
#
# Run: sudo bash smb-autosetup.sh

set -Eeuo pipefail

#############
# Formatting
#############
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'
info(){ echo -e "${BLU}[INFO]${NC} $*"; }
ok(){   echo -e "${GRN}[OK]${NC}   $*"; }
warn(){ echo -e "${YLW}[WARN]${NC} $*"; }
die(){  echo -e "${RED}[ERR]${NC}  $*" >&2; exit 1; }
trap 'die "Erreur ligne $LINENO: $BASH_COMMAND"' ERR

need_root(){ [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Lance en root (sudo)."; }
has_cmd(){ command -v "$1" >/dev/null 2>&1; }

prompt() {
  local var="$1" msg="$2" def="${3:-}" ans=""
  if [[ -n "$def" ]]; then
    read -r -p "$msg [$def]: " ans
    ans="${ans:-$def}"
  else
    read -r -p "$msg: " ans
  fi
  printf -v "$var" '%s' "$ans"
}

prompt_yn() {
  local var="$1" msg="$2" def="${3:-y}" ans=""
  while true; do
    read -r -p "$msg [y/n] (défaut: $def): " ans
    ans="${ans:-$def}"
    case "$ans" in
      y|Y) printf -v "$var" 'y'; return 0 ;;
      n|N) printf -v "$var" 'n'; return 0 ;;
      *) echo "Réponds y ou n." ;;
    esac
  done
}

is_valid_name() { [[ "$1" =~ ^[a-zA-Z0-9._-]+$ ]]; }
is_valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( "$1" >= 1 && "$1" <= 65535 )); }

########################
# OS / Package handling
########################
require_apt() {
  has_cmd apt-get || die "apt-get introuvable. Ce script vise Debian/Ubuntu."
}

install_pkgs() {
  info "Installation des paquets Samba…"
  apt-get update -y >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    samba smbclient cifs-utils acl attr \
    >/dev/null
  ok "Paquets installés."
}

########################
# Disk / Mount utilities
########################
lsblk_table() {
  # Show useful view
  lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,LABEL,MODEL -e7
}

list_disks() {
  # Only real disks
  lsblk -dn -o NAME,SIZE,MODEL,TYPE | awk '$4=="disk"{printf "/dev/%s|%s|%s\n",$1,$2,$3}'
}

list_partitions() {
  # partitions with full path
  lsblk -pn -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT | awk '$3=="part"{print}'
}

is_mounted() {
  local dev="$1"
  findmnt -rn --source "$dev" >/dev/null 2>&1
}

device_has_partitions() {
  local disk="$1"
  # if any child partitions exist
  lsblk -n "$disk" -o TYPE | grep -q '^part$'
}

device_has_filesystem_or_signature() {
  local dev="$1"
  blkid "$dev" >/dev/null 2>&1
}

mk_mountpoint() {
  local mp="$1"
  mkdir -p "$mp"
  chmod 755 "$mp"
}

uuid_of() {
  local dev="$1"
  blkid -s UUID -o value "$dev"
}

fstype_of() {
  local dev="$1"
  blkid -s TYPE -o value "$dev" 2>/dev/null || true
}

ensure_not_in_use() {
  local dev="$1"
  is_mounted "$dev" && die "$dev est déjà monté. Démonte-le avant (umount) ou choisis un autre."
}

create_partition_on_empty_disk() {
  local disk="$1" size_gib="$2"
  ensure_not_in_use "$disk"

  device_has_partitions "$disk" && die "$disk a déjà des partitions. Refus (sécurité)."

  warn "ATTENTION: on va écrire une table de partitions sur $disk."
  prompt_yn GO "Confirme que tu veux partitionner $disk (risque de perte de données) ?" "n"
  [[ "$GO" == "y" ]] || die "Annulé."

  info "Création table GPT sur $disk…"
  parted -s "$disk" mklabel gpt >/dev/null

  # Create partition: from 1MiB to size or 100%
  if [[ -n "$size_gib" ]]; then
    [[ "$size_gib" =~ ^[0-9]+$ ]] || die "Taille invalide (GiB attendu)."
    info "Création partition de ${size_gib}GiB…"
    parted -s -a optimal "$disk" mkpart primary ext4 1MiB "${size_gib}GiB" >/dev/null
  else
    info "Création partition sur tout l'espace disque…"
    parted -s -a optimal "$disk" mkpart primary ext4 1MiB 100% >/dev/null
  fi

  partprobe "$disk" >/dev/null || true
  sleep 1

  # Find first partition path
  local part
  part="$(lsblk -pn -o NAME,TYPE "$disk" | awk '$2=="part"{print $1; exit}')"
  [[ -n "$part" ]] || die "Impossible de trouver la partition créée sur $disk."

  ok "Partition créée : $part"
  echo "$part"
}

format_partition() {
  local part="$1" fstype="$2" label="${3:-}"
  ensure_not_in_use "$part"

  if device_has_filesystem_or_signature "$part"; then
    warn "$part semble déjà contenir une signature (filesystem)."
    prompt_yn GO "Confirme le FORMATAGE de $part (efface TOUT) ?" "n"
    [[ "$GO" == "y" ]] || die "Annulé."
  fi

  case "$fstype" in
    ext4)
      info "Formatage ext4…"
      if [[ -n "$label" ]]; then
        mkfs.ext4 -F -L "$label" "$part" >/dev/null
      else
        mkfs.ext4 -F "$part" >/dev/null
      fi
      ;;
    xfs)
      info "Formatage XFS…"
      if [[ -n "$label" ]]; then
        mkfs.xfs -f -L "$label" "$part" >/dev/null
      else
        mkfs.xfs -f "$part" >/dev/null
      fi
      ;;
    *)
      die "FSType non supporté: $fstype (utilise ext4 ou xfs)."
      ;;
  esac
  ok "Formatage terminé."
}

mount_persistently() {
  local part="$1" mp="$2"
  mk_mountpoint "$mp"

  local uuid fstype
  uuid="$(uuid_of "$part")"
  fstype="$(fstype_of "$part")"
  [[ -n "$uuid" && -n "$fstype" ]] || die "Impossible de lire UUID/FSTYPE de $part."

  info "Montage immédiat…"
  mount "$part" "$mp"

  info "Ajout dans /etc/fstab (UUID)…"
  local line="UUID=$uuid $mp $fstype defaults,noatime 0 2"

  # Avoid duplicates
  if grep -q "UUID=$uuid" /etc/fstab; then
    warn "Une entrée fstab pour UUID=$uuid existe déjà. Je ne duplique pas."
  else
    echo "$line" >> /etc/fstab
  fi

  ok "Montage OK : $mp"
}

########################
# Samba config + shares
########################
backup_smb_conf() {
  local src="/etc/samba/smb.conf"
  local dst="/etc/samba/smb.conf.bak.$(date +%Y%m%d-%H%M%S)"
  cp -a "$src" "$dst"
  ok "Backup smb.conf : $dst"
}

write_global_conf_minimal() {
  local workgroup="$1" server_string="$2"

  backup_smb_conf

  info "Écriture configuration Samba (global)…"
  cat > /etc/samba/smb.conf <<EOF
[global]
   workgroup = $workgroup
   server string = $server_string
   server role = standalone server

   # Réseau / compat
   map to guest = Bad User
   dns proxy = no

   # Logs
   log file = /var/log/samba/log.%m
   max log size = 1000
   logging = file
   panic action = /usr/share/samba/panic-action %d

   # Perf raisonnable
   socket options = TCP_NODELAY IPTOS_LOWDELAY

   # Sécurité (par défaut: utilisateurs)
   security = user
   passdb backend = tdbsam

   # Permissions POSIX/ACL (utile si tu veux des droits propres)
   vfs objects = acl_xattr
   map acl inherit = yes
   store dos attributes = yes
EOF

  ok "Global écrit."
}

ensure_samba_group() {
  if ! getent group smbshare >/dev/null; then
    groupadd --system smbshare
    ok "Groupe créé : smbshare"
  else
    ok "Groupe déjà présent : smbshare"
  fi
}

create_system_user_if_needed() {
  local u="$1"
  if id "$u" >/dev/null 2>&1; then
    ok "Utilisateur système existe : $u"
  else
    info "Création utilisateur système (sans shell) : $u"
    useradd -M -s /usr/sbin/nologin "$u"
    ok "Utilisateur créé : $u"
  fi
}

add_samba_user() {
  local u="$1"
  info "Ajout utilisateur Samba : $u"
  # smbpasswd prompts for password interactively (no password stored in script)
  smbpasswd -a "$u"
  smbpasswd -e "$u" >/dev/null
  ok "Utilisateur Samba prêt : $u"
}

create_share_dir() {
  local dir="$1"
  mkdir -p "$dir"
  chown root:smbshare "$dir"
  chmod 2770 "$dir"     # setgid to keep group on new files
  ok "Dossier share prêt : $dir"
}

append_share_to_conf() {
  local share_name="$1" path="$2" browseable="$3" ro="$4" guest="$5" valid_users_csv="$6"

  info "Ajout partage [$share_name]…"
  {
    echo
    echo "[$share_name]"
    echo "   path = $path"
    echo "   browseable = $browseable"
    echo "   read only = $ro"
    echo "   guest ok = $guest"
    echo "   create mask = 0660"
    echo "   directory mask = 2770"
    echo "   force group = smbshare"
    echo "   inherit permissions = yes"
    echo "   valid users = $valid_users_csv"
  } >> /etc/samba/smb.conf

  ok "Partage ajouté : $share_name"
}

test_samba_conf() {
  info "Validation config Samba (testparm)…"
  testparm -s >/dev/null
  ok "Config Samba valide."
}

enable_and_restart_samba() {
  info "Activation/démarrage Samba…"
  systemctl enable --now smbd >/dev/null
  systemctl enable --now nmbd >/dev/null || true
  systemctl restart smbd >/dev/null
  systemctl restart nmbd >/dev/null || true
  systemctl --no-pager --full status smbd | sed -n '1,12p' || true
  ok "Samba démarré."
}

open_firewall_ufw_samba() {
  if has_cmd ufw; then
    info "Ouverture firewall UFW (profil Samba)…"
    ufw allow 'Samba' >/dev/null || true
    ok "Règle UFW ajoutée."
  else
    warn "UFW absent. Si firewall actif, ouvre les ports SMB (137/138 UDP, 139/445 TCP)."
  fi
}

########################
# Main flow
########################
need_root
require_apt
has_cmd lsblk || die "lsblk requis."
has_cmd testparm || true

echo
info "Vue disques/partitions (lecture seule) :"
lsblk_table
echo

install_pkgs

# Choose storage mode
echo
echo "Choisis le mode de stockage :"
echo "  1) (SAFE) Utiliser une partition existante déjà formatée (on la monte + on crée les partages)"
echo "  2) (SAFE) Utiliser un dossier existant (pas de montage, juste partage Samba)"
echo "  3) (ADV) Créer + formater une nouvelle partition sur un disque VIDE (DANGEREUX)"
read -r -p "Ton choix [1]: " MODE
MODE="${MODE:-1}"
[[ "$MODE" =~ ^[1-3]$ ]] || die "Choix invalide."

MOUNT_POINT=""
SHARE_ROOT=""

case "$MODE" in
  1)
    echo
    info "Partitions détectées :"
    list_partitions
    echo
    prompt PART "Chemin de la partition à utiliser (ex: /dev/sdb1)"
    [[ -b "$PART" ]] || die "Partition invalide: $PART"
    ensure_not_in_use "$PART"

    # Ensure it has filesystem
    if ! device_has_filesystem_or_signature "$PART"; then
      die "$PART n'a pas de filesystem détecté. Utilise le mode 3 (format) ou formate manuellement."
    fi

    prompt MOUNT_POINT "Point de montage (ex: /srv/storage)" "/srv/storage"
    mount_persistently "$PART" "$MOUNT_POINT"
    SHARE_ROOT="$MOUNT_POINT"
    ;;
  2)
    prompt SHARE_ROOT "Chemin du dossier à partager (ex: /srv/shares)" "/srv/shares"
    mkdir -p "$SHARE_ROOT"
    ;;
  3)
    echo
    info "Disques détectés :"
    list_disks | nl -w2 -s') '
    echo
    prompt DISK "Chemin du disque (ex: /dev/sdb)"
    [[ -b "$DISK" ]] || die "Disque invalide: $DISK"

    if device_has_partitions "$DISK"; then
      die "$DISK contient déjà des partitions. Refus (sécurité). Choisis un disque vide, ou fais ça à la main."
    fi

    prompt SIZE_GIB "Taille de la partition en GiB (vide = tout le disque)" ""
    prompt FSTYPE "Filesystem (ext4 ou xfs)" "ext4"
    prompt LABEL "Label filesystem (optionnel)" "STORAGE"

    NEW_PART="$(create_partition_on_empty_disk "$DISK" "$SIZE_GIB")"
    format_partition "$NEW_PART" "$FSTYPE" "$LABEL"

    prompt MOUNT_POINT "Point de montage (ex: /srv/storage)" "/srv/storage"
    mount_persistently "$NEW_PART" "$MOUNT_POINT"
    SHARE_ROOT="$MOUNT_POINT"
    ;;
esac

# Samba global config
echo
prompt WORKGROUP "Workgroup (réseau Windows)" "WORKGROUP"
prompt SERVER_STRING "Nom affiché (server string)" "Samba Server"

write_global_conf_minimal "$WORKGROUP" "$SERVER_STRING"
ensure_samba_group

# Users setup
echo
info "Création des utilisateurs Samba (au moins 1)."
declare -a USERS=()
while true; do
  prompt U "Nom d'utilisateur (lettres/chiffres/._-) ou vide pour finir" ""
  [[ -z "$U" ]] && break
  is_valid_name "$U" || { echo "Nom invalide."; continue; }

  create_system_user_if_needed "$U"
  usermod -aG smbshare "$U"
  add_samba_user "$U"
  USERS+=("$U")
done
(( ${#USERS[@]} > 0 )) || die "Aucun utilisateur créé. Impossible de sécuriser les partages."

VALID_USERS_CSV="$(IFS=' '; echo "${USERS[*]}")"

# Shares loop
echo
info "Création des partages Samba."
info "Chemin racine proposé : $SHARE_ROOT"
while true; do
  prompt SHARE_NAME "Nom du partage (ex: Media) ou vide pour finir" ""
  [[ -z "$SHARE_NAME" ]] && break
  is_valid_name "$SHARE_NAME" || { echo "Nom invalide."; continue; }

  prompt SUBDIR "Sous-dossier dans $SHARE_ROOT (ex: media) ou '.' pour racine" "media"
  if [[ "$SUBDIR" == "." ]]; then
    SHARE_PATH="$SHARE_ROOT"
  else
    SHARE_PATH="$SHARE_ROOT/$SUBDIR"
  fi

  prompt_yn BROWSE "Visible dans l'explorateur réseau ?" "y"
  prompt_yn READONLY "Lecture seule ?" "n"
  prompt_yn GUEST "Autoriser invité (guest) ?" "n"

  # Convert y/n to yes/no expected by smb.conf
  BROWSE_VAL=$([[ "$BROWSE" == "y" ]] && echo "yes" || echo "no")
  RO_VAL=$([[ "$READONLY" == "y" ]] && echo "yes" || echo "no")
  GUEST_VAL=$([[ "$GUEST" == "y" ]] && echo "yes" || echo "no")

  create_share_dir "$SHARE_PATH"
  append_share_to_conf "$SHARE_NAME" "$SHARE_PATH" "$BROWSE_VAL" "$RO_VAL" "$GUEST_VAL" "$VALID_USERS_CSV"

  prompt_yn AGAIN "Ajouter un autre partage ?" "y"
  [[ "$AGAIN" == "y" ]] || break
done

test_samba_conf
enable_and_restart_samba

prompt_yn DO_UFW "Ouvrir automatiquement le firewall UFW (profil Samba) si présent ?" "y"
[[ "$DO_UFW" == "y" ]] && open_firewall_ufw_samba || true

# Show access info
iface="$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)"
ip_local=""
[[ -n "${iface:-}" ]] && ip_local="$(ip -4 addr show "$iface" 2>/dev/null | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1 || true)"

echo
ok "Terminé."
info "Partages Samba configurés dans: /etc/samba/smb.conf"
info "IP serveur (LAN) : ${ip_local:-<IP_DU_SERVEUR>}"
info "Accès Windows : \\\\${ip_local:-IP_DU_SERVEUR}\\NOM_DU_PARTAGE"
info "Lister partages (depuis serveur) : smbclient -L localhost -U ${USERS[0]}"
info "Logs : journalctl -u smbd --no-pager -n 120"
