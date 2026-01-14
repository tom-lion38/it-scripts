#!/usr/bin/env bash
# plex-autoinstall.sh
# Auto-installe Plex Media Server sur Linux (Debian/Ubuntu via APT, Fedora/RHEL/CentOS via DNF/YUM).
# Run: sudo bash plex-autoinstall.sh
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

prompt_yn() {
  local var="$1" msg="$2" def="${3:-y}" ans=""
  while true; do
    read -r -p "$msg [y/n] (défaut: $def): " ans
    ans="${ans:-$def}"
    case "$ans" in y|Y) printf -v "$var" 'y'; return 0 ;; n|N) printf -v "$var" 'n'; return 0 ;; *) echo "Réponds y ou n." ;; esac
  done
}

######################
# Detection / Network
######################
detect_pkg_mgr() {
  if has_cmd apt-get; then echo "apt"; return; fi
  if has_cmd dnf; then echo "dnf"; return; fi
  if has_cmd yum; then echo "yum"; return; fi
  die "Gestionnaire de paquets non supporté (apt/dnf/yum requis)."
}

get_default_iface() {
  ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}
get_primary_ip() {
  local iface="$1"
  ip -4 addr show "$iface" 2>/dev/null | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1
}

######################
# APT (Debian/Ubuntu)
######################
apt_setup_repo() {
  info "Configuration du dépôt Plex (APT)…"
  apt-get update -y >/dev/null
  apt-get install -y ca-certificates curl gnupg >/dev/null

  mkdir -p /etc/apt/keyrings
  local keyring="/etc/apt/keyrings/plex.gpg"
  local list="/etc/apt/sources.list.d/plexmediaserver.list"

  if [[ ! -s "$keyring" ]]; then
    info "Téléchargement de la clé de signature Plex…"
    curl -fsSL https://downloads.plex.tv/plex-keys/PlexSign.key | gpg --dearmor -o "$keyring"
    chmod 0644 "$keyring"
    ok "Clé Plex installée: $keyring"
  else
    ok "Clé Plex déjà présente: $keyring"
  fi

  if [[ ! -s "$list" ]] || ! grep -q "downloads\.plex\.tv/repo/deb" "$list"; then
    info "Ajout de la source APT Plex…"
    cat > "$list" <<EOF
deb [signed-by=$keyring] https://downloads.plex.tv/repo/deb public main
EOF
    chmod 0644 "$list"
    ok "Source APT créée: $list"
  else
    ok "Source APT déjà présente: $list"
  fi

  apt-get update -y >/dev/null
  ok "Dépôt APT prêt."
}

apt_install_plex() {
  info "Installation de Plex Media Server (APT)…"
  DEBIAN_FRONTEND=noninteractive apt-get install -y plexmediaserver >/dev/null
  ok "Plex installé."
}

######################
# DNF/YUM (Fedora/RHEL)
######################
rpm_setup_repo() {
  info "Configuration du dépôt Plex (DNF/YUM)…"
  local repo="/etc/yum.repos.d/plex.repo"

  # Repo officiel Plex (public releases)
  cat > "$repo" <<'EOF'
[PlexRepo]
name=PlexRepo
baseurl=https://downloads.plex.tv/repo/rpm/$basearch/
enabled=1
gpgkey=https://downloads.plex.tv/plex-keys/PlexSign.key
gpgcheck=1
EOF
  chmod 0644 "$repo"
  ok "Repo RPM créé: $repo"
}

rpm_install_plex() {
  local mgr="$1"
  info "Installation de Plex Media Server ($mgr)…"
  if [[ "$mgr" == "dnf" ]]; then
    dnf -y install plexmediaserver >/dev/null
  else
    yum -y install plexmediaserver >/dev/null
  fi
  ok "Plex installé."
}

######################
# Firewall helpers
######################
open_firewall() {
  local port="32400"
  if has_cmd ufw; then
    info "Ouverture du port $port/tcp via UFW…"
    ufw allow "${port}/tcp" >/dev/null || true
    ok "Règle UFW ajoutée."
    return
  fi
  if has_cmd firewall-cmd; then
    info "Ouverture du port $port/tcp via firewalld…"
    firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null || true
    firewall-cmd --reload >/dev/null || true
    ok "Règle firewalld ajoutée."
    return
  fi
  warn "Aucun firewall géré automatiquement (ufw/firewalld). Si tu as un firewall, ouvre 32400/tcp."
}

######################
# Service
######################
start_service() {
  info "Activation et démarrage de Plex…"
  systemctl enable --now plexmediaserver >/dev/null
  systemctl --no-pager --full status plexmediaserver | sed -n '1,14p' || true
  ok "Service Plex démarré (si pas d'erreur ci-dessus)."
}

#############
# Main
#############
need_root
has_cmd systemctl || die "systemd requis (systemctl introuvable)."

PKG_MGR="$(detect_pkg_mgr)"
DO_FW="y"
prompt_yn DO_FW "Ouvrir automatiquement le port 32400/tcp (UFW ou firewalld si présent) ?" "y"

case "$PKG_MGR" in
  apt)
    apt_setup_repo
    apt_install_plex
    ;;
  dnf|yum)
    rpm_setup_repo
    rpm_install_plex "$PKG_MGR"
    ;;
esac

[[ "$DO_FW" == "y" ]] && open_firewall || true
start_service

iface="$(get_default_iface || true)"
ip_local=""
[[ -n "${iface:-}" ]] && ip_local="$(get_primary_ip "$iface" || true)"

echo
ok "Terminé."
info "Accès interface Plex (local LAN) : http://${ip_local:-<IP_DU_SERVEUR>}:32400/web"
info "Logs : journalctl -u plexmediaserver --no-pager -n 120"
