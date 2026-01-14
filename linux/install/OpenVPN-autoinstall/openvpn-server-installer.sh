#!/usr/bin/env bash
# openvpn-autoinstall.sh
# Interactive OpenVPN server installer for Debian/Ubuntu.
# Generates server config + PKI (Easy-RSA) + one client .ovpn.
# Run: sudo bash openvpn-autoinstall.sh

set -Eeuo pipefail

#############
# Formatting
#############
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; BLU='\033[0;34m'; NC='\033[0m'
info(){ echo -e "${BLU}[INFO]${NC} $*"; }
ok(){   echo -e "${GRN}[OK]${NC}   $*"; }
warn(){ echo -e "${YLW}[WARN]${NC} $*"; }
die(){  echo -e "${RED}[ERR]${NC}  $*" >&2; exit 1; }

trap 'die "Erreur à la ligne $LINENO (commande: $BASH_COMMAND)"' ERR

need_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Lance ce script en root (sudo)."; }
has_cmd(){ command -v "$1" >/dev/null 2>&1; }

################
# Prompt helpers
################
prompt() {
  local var="$1" msg="$2" def="${3:-}"
  local ans=""
  if [[ -n "$def" ]]; then
    read -r -p "$msg [$def]: " ans
    ans="${ans:-$def}"
  else
    read -r -p "$msg: " ans
  fi
  printf -v "$var" '%s' "$ans"
}

prompt_yn() {
  local var="$1" msg="$2" def="${3:-y}"
  local ans=""
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

is_valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && (( "$1" >= 1 && "$1" <= 65535 )); }

########################
# OS / Network detection
########################
detect_distro() {
  [[ -r /etc/os-release ]] || die "Impossible de détecter l'OS (/etc/os-release manquant)."
  # shellcheck disable=SC1091
  . /etc/os-release
  echo "${ID:-unknown}:${VERSION_ID:-unknown}"
}

get_default_iface() {
  ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}

get_primary_ip() {
  local iface="$1"
  ip -4 addr show "$iface" 2>/dev/null | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1
}

detect_public_ip() {
  # Best-effort; can fail if no outbound or blocked.
  if has_cmd curl; then
    curl -fsS --max-time 3 https://api.ipify.org 2>/dev/null || true
  fi
}

######################
# System configuration
######################
enable_ip_forward() {
  info "Activation du routage IPv4 (ip_forward)…"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  mkdir -p /etc/sysctl.d
  cat > /etc/sysctl.d/99-openvpn-ipforward.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
  sysctl --system >/dev/null || true
  ok "ip_forward activé."
}

install_pkgs_debian() {
  info "Installation des paquets…"
  apt-get update -y >/dev/null

  # Avoid prompts for iptables-persistent
  export DEBIAN_FRONTEND=noninteractive
  echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections || true
  echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections || true

  apt-get install -y \
    openvpn easy-rsa iptables iproute2 ca-certificates curl \
    netfilter-persistent iptables-persistent >/dev/null

  ok "Paquets installés."
}

######################
# Easy-RSA / PKI setup
######################
setup_pki() {
  local client_name="$1"
  local easyrsa_dir="/etc/openvpn/easy-rsa"
  local pki_dir="/etc/openvpn/pki"

  info "Initialisation PKI (Easy-RSA)…"
  rm -rf "$easyrsa_dir" "$pki_dir"
  mkdir -p "$easyrsa_dir"
  cp -r /usr/share/easy-rsa/* "$easyrsa_dir/"
  chmod 700 "$easyrsa_dir"
  cd "$easyrsa_dir"

  # Generic vars (no personal info)
  cat > vars <<'EOF'
set_var EASYRSA_ALGO ec
set_var EASYRSA_CURVE prime256v1
set_var EASYRSA_REQ_COUNTRY    "XX"
set_var EASYRSA_REQ_PROVINCE   "NA"
set_var EASYRSA_REQ_CITY       "NA"
set_var EASYRSA_REQ_ORG        "OpenVPN"
set_var EASYRSA_REQ_EMAIL      "admin@example.local"
set_var EASYRSA_REQ_OU         "IT"
EOF

  ./easyrsa --batch init-pki >/dev/null
  ./easyrsa --batch build-ca nopass >/dev/null
  ./easyrsa --batch gen-dh >/dev/null
  ./easyrsa --batch build-server-full server nopass >/dev/null
  ./easyrsa --batch build-client-full "$client_name" nopass >/dev/null

  # Use tls-crypt (simpler + better than tls-auth for most cases)
  openvpn --genkey --secret tls-crypt.key >/dev/null

  mkdir -p "$pki_dir"
  cp -r pki/* "$pki_dir/"
  cp tls-crypt.key "$pki_dir/tls-crypt.key"
  chmod -R go-rwx "$pki_dir"
  ok "PKI prête."
}

######################
# OpenVPN config files
######################
write_server_conf() {
  local proto="$1" port="$2" vpn_cidr="$3" dns_choice="$4"
  local conf="/etc/openvpn/server/server.conf"
  local pki="/etc/openvpn/pki"

  mkdir -p /etc/openvpn/server

  # Split CIDR into network and netmask for OpenVPN "server" directive
  local vpn_net="${vpn_cidr%/*}"
  local vpn_prefix="${vpn_cidr#*/}"
  local vpn_mask="255.255.255.0"

  # Convert prefix -> netmask for common /8..../30 (simple robust conversion)
  if has_cmd python3; then
    vpn_mask="$(python3 - <<PY
import ipaddress
n = ipaddress.IPv4Network(f"0.0.0.0/{vpn_prefix}")
print(n.netmask)
PY
)"
  else
    # Fallback for /24 only
    [[ "$vpn_prefix" == "24" ]] || die "python3 absent: impossible de convertir /$vpn_prefix en masque. Installe python3 ou utilise /24."
    vpn_mask="255.255.255.0"
  fi

  info "Écriture de la config serveur OpenVPN…"
  cat > "$conf" <<EOF
port $port
proto $proto
dev tun

user nobody
group nogroup
persist-key
persist-tun

topology subnet
server $vpn_net $vpn_mask

# Certificats / clés
ca $pki/ca.crt
cert $pki/issued/server.crt
key $pki/private/server.key
dh $pki/dh.pem

# TLS key (tls-crypt)
tls-crypt $pki/tls-crypt.key

# Forcer tout le trafic via VPN
push "redirect-gateway def1 bypass-dhcp"

# DNS poussés aux clients
EOF

  case "$dns_choice" in
    1) echo 'push "dhcp-option DNS 1.1.1.1"' >> "$conf"
       echo 'push "dhcp-option DNS 1.0.0.1"' >> "$conf" ;;
    2) echo 'push "dhcp-option DNS 8.8.8.8"' >> "$conf"
       echo 'push "dhcp-option DNS 8.8.4.4"' >> "$conf" ;;
    3) echo 'push "dhcp-option DNS 9.9.9.9"' >> "$conf"
       echo 'push "dhcp-option DNS 149.112.112.112"' >> "$conf" ;;
    4) echo 'push "dhcp-option DNS 208.67.222.222"' >> "$conf"
       echo 'push "dhcp-option DNS 208.67.220.220"' >> "$conf" ;;
    5)
       local dns1 dns2
       dns1="$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf || true)"
       dns2="$(awk '/^nameserver/{print $2}' /etc/resolv.conf | sed -n '2p' || true)"
       [[ -n "$dns1" ]] && echo "push \"dhcp-option DNS $dns1\"" >> "$conf"
       [[ -n "$dns2" ]] && echo "push \"dhcp-option DNS $dns2\"" >> "$conf"
       ;;
  esac

  cat >> "$conf" <<'EOF'

# Crypto (solide + compatible)
cipher AES-256-GCM
ncp-ciphers AES-256-GCM:AES-128-GCM
auth SHA256
tls-version-min 1.2

# Keepalive
keepalive 10 120

# Logs
verb 3
status /var/log/openvpn-status.log
EOF

  ok "server.conf écrit."
}

write_client_ovpn() {
  local client_name="$1" remote_host="$2" proto="$3" port="$4"
  local out_dir="/root/openvpn-clients"
  local pki="/etc/openvpn/pki"

  mkdir -p "$out_dir"

  info "Génération du profil client .ovpn…"
  cat > "$out_dir/${client_name}.ovpn" <<EOF
client
dev tun
proto $proto
remote $remote_host $port
resolv-retry infinite
nobind
persist-key
persist-tun

remote-cert-tls server
cipher AES-256-GCM
auth SHA256
verb 3

<ca>
$(cat "$pki/ca.crt")
</ca>

<cert>
$(awk 'BEGIN{p=0} /BEGIN CERTIFICATE/{p=1} {if(p)print} /END CERTIFICATE/{p=0}' "$pki/issued/${client_name}.crt")
</cert>

<key>
$(cat "$pki/private/${client_name}.key")
</key>

<tls-crypt>
$(cat "$pki/tls-crypt.key")
</tls-crypt>
EOF

  chmod 600 "$out_dir/${client_name}.ovpn"
  ok "Client généré : $out_dir/${client_name}.ovpn"
}

######################
# Firewall / NAT
######################
setup_iptables_nat() {
  local iface="$1" vpn_cidr="$2"
  info "Configuration NAT (iptables)…"

  # NAT for VPN subnet
  iptables -t nat -C POSTROUTING -s "$vpn_cidr" -o "$iface" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "$vpn_cidr" -o "$iface" -j MASQUERADE

  # Forward rules
  iptables -C FORWARD -i tun0 -o "$iface" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -i tun0 -o "$iface" -j ACCEPT
  iptables -C FORWARD -i "$iface" -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -i "$iface" -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT

  ok "Règles iptables appliquées (session courante)."

  if has_cmd netfilter-persistent; then
    info "Sauvegarde iptables via netfilter-persistent…"
    netfilter-persistent save >/dev/null || true
    ok "Règles sauvegardées."
  else
    warn "netfilter-persistent absent: les règles iptables ne seront pas persistées après reboot."
  fi
}

open_firewall_ufw() {
  local proto="$1" port="$2"
  if has_cmd ufw; then
    local ufw_state
    ufw_state="$(ufw status | head -n1 || true)"
    info "Ouverture du port $port/$proto via UFW…"
    ufw allow "${port}/${proto}" >/dev/null || true
    if [[ "$ufw_state" =~ inactive ]]; then
      warn "UFW est inactif. Tu peux l'activer plus tard avec: ufw enable"
    fi
    ok "Règle UFW ajoutée."
  else
    warn "UFW non installé. Si tu as un firewall, ouvre $port/$proto."
  fi
}

######################
# Service management
######################
start_openvpn() {
  info "Activation et démarrage du service OpenVPN…"
  systemctl enable --now openvpn-server@server >/dev/null
  systemctl --no-pager --full status openvpn-server@server | sed -n '1,14p' || true
  ok "Service OpenVPN démarré (si pas d'erreur ci-dessus)."
}

############
# Main
############
need_root

[[ -e /dev/net/tun ]] || die "TUN indisponible (/dev/net/tun). Vérifie le support TUN (souvent un souci en VM)."
has_cmd apt-get || die "apt-get introuvable. Ce script vise Debian/Ubuntu."

distro="$(detect_distro)"
case "$distro" in
  debian:*|ubuntu:*) ;;
  *) warn "OS détecté: $distro. Ce script vise Debian/Ubuntu. Ça peut marcher sans garantie." ;;
esac

iface="$(get_default_iface || true)"
[[ -n "$iface" ]] || die "Impossible de détecter l'interface réseau par défaut."
ip_local="$(get_primary_ip "$iface" || true)"
ip_pub="$(detect_public_ip || true)"

info "Interface détectée : $iface (IP locale: ${ip_local:-inconnue})"
[[ -n "$ip_pub" ]] && info "IP publique détectée : $ip_pub"

# Remote host (public IP / DNS) used by clients
default_remote="${ip_pub:-${ip_local:-}}"
prompt REMOTE_HOST "Adresse publique / nom DNS pour se connecter (IP publique ou domaine)" "$default_remote"
while [[ -z "$REMOTE_HOST" ]]; do prompt REMOTE_HOST "Adresse publique / nom DNS" ""; done

# Protocol
while true; do
  echo "Choisis le protocole OpenVPN :"
  echo "  1) UDP (recommandé)"
  echo "  2) TCP"
  read -r -p "Ton choix [1]: " p
  p="${p:-1}"
  case "$p" in
    1) PROTO="udp"; break ;;
    2) PROTO="tcp"; break ;;
    *) echo "Choix invalide." ;;
  esac
done

# Port
while true; do
  prompt PORT "Port OpenVPN" "1194"
  is_valid_port "$PORT" && break
  echo "Port invalide."
done

# VPN subnet (CIDR)
prompt VPN_CIDR "Réseau VPN en CIDR (ex: 10.8.0.0/24)" "10.8.0.0/24"
# Simple validation
if ! [[ "$VPN_CIDR" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; then
  die "CIDR invalide: $VPN_CIDR (ex attendu: 10.8.0.0/24)"
fi

# DNS choice
echo "DNS à pousser aux clients :"
echo "  1) Cloudflare (1.1.1.1)"
echo "  2) Google (8.8.8.8)"
echo "  3) Quad9 (9.9.9.9)"
echo "  4) OpenDNS"
echo "  5) DNS du serveur (resolv.conf)"
while true; do
  read -r -p "Ton choix [1]: " DNS_CHOICE
  DNS_CHOICE="${DNS_CHOICE:-1}"
  [[ "$DNS_CHOICE" =~ ^[1-5]$ ]] && break
  echo "Choix invalide."
done

# Client name
prompt CLIENT_NAME "Nom du premier client (ex: laptop1)" "client1"
CLIENT_NAME="${CLIENT_NAME// /_}"
[[ -n "$CLIENT_NAME" ]] || die "Nom client invalide."

prompt_yn DO_UFW "Ajouter une règle firewall UFW (si UFW est installé) ?" "y"

echo
info "Résumé :"
echo "  - Remote : $REMOTE_HOST"
echo "  - Proto  : $PROTO"
echo "  - Port   : $PORT"
echo "  - VPN    : $VPN_CIDR"
echo "  - DNS    : $DNS_CHOICE"
echo "  - Client : $CLIENT_NAME"
echo "  - IFACE  : $iface"
echo

prompt_yn GO "Lancer l'installation maintenant ?" "y"
[[ "$GO" == "y" ]] || die "Annulé."

install_pkgs_debian
enable_ip_forward

setup_pki "$CLIENT_NAME"
write_server_conf "$PROTO" "$PORT" "$VPN_CIDR" "$DNS_CHOICE"
setup_iptables_nat "$iface" "$VPN_CIDR"

if [[ "$DO_UFW" == "y" ]]; then
  open_firewall_ufw "$PROTO" "$PORT"
fi

start_openvpn
write_client_ovpn "$CLIENT_NAME" "$REMOTE_HOST" "$PROTO" "$PORT"

echo
ok "Terminé."
info "Fichier client : /root/openvpn-clients/${CLIENT_NAME}.ovpn"
info "Logs : journalctl -u openvpn-server@server --no-pager -n 80"