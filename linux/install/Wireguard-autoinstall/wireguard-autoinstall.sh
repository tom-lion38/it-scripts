#!/usr/bin/env bash
# wireguard-autoinstall.sh
# Interactive WireGuard server installer for Debian/Ubuntu.
# - Installs WireGuard
# - Creates wg0 server config
# - Enables IPv4 forwarding
# - Sets up NAT (iptables) + persistence (netfilter-persistent)
# - Generates one or more client configs (.conf) + optional QR display
#
# Run: sudo bash wireguard-autoinstall.sh

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

is_valid_port(){ [[ "$1" =~ ^[0-9]+$ ]] && (( "$1" >= 1 && "$1" <= 65535 )); }
is_valid_name(){ [[ "$1" =~ ^[a-zA-Z0-9._-]+$ ]]; }
is_valid_ipv4(){ [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
is_valid_cidr(){ [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; }

###############
# Networking
###############
get_default_iface() {
  ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}
get_primary_ip() {
  local iface="$1"
  ip -4 addr show "$iface" 2>/dev/null | awk '/inet /{print $2}' | head -n1 | cut -d/ -f1
}
detect_public_ip() {
  has_cmd curl || return 0
  curl -fsS --max-time 3 https://api.ipify.org 2>/dev/null || true
}

###############
# System setup
###############
ensure_debian_like() {
  has_cmd apt-get || die "apt-get introuvable. Ce script vise Debian/Ubuntu."
  has_cmd systemctl || die "systemd requis (systemctl introuvable)."
  has_cmd ip || die "iproute2 requis (commande ip introuvable)."
}

install_pkgs() {
  info "Installation WireGuard + outils…"
  apt-get update -y >/dev/null
  export DEBIAN_FRONTEND=noninteractive
  echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections || true
  echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections || true

  # wireguard package name varies; on Debian/Ubuntu it's usually "wireguard"
  apt-get install -y wireguard iptables iproute2 ca-certificates curl netfilter-persistent iptables-persistent >/dev/null

  # optional QR tool
  apt-get install -y qrencode >/dev/null 2>&1 || true

  ok "Paquets installés."
}

enable_ip_forward() {
  info "Activation du routage IPv4 (ip_forward)…"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  mkdir -p /etc/sysctl.d
  cat > /etc/sysctl.d/99-wireguard-ipforward.conf <<'EOF'
net.ipv4.ip_forward=1
EOF
  sysctl --system >/dev/null || true
  ok "ip_forward activé."
}

###############
# WireGuard keys
###############
gen_keypair() {
  local priv pub
  priv="$(wg genkey)"
  pub="$(printf '%s' "$priv" | wg pubkey)"
  printf '%s|%s' "$priv" "$pub"
}

###############
# Firewall/NAT
###############
apply_nat_rules_now() {
  local iface="$1" wg_cidr="$2"
  info "Application NAT (iptables) sur $iface pour $wg_cidr…"

  iptables -t nat -C POSTROUTING -s "$wg_cidr" -o "$iface" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "$wg_cidr" -o "$iface" -j MASQUERADE

  iptables -C FORWARD -i wg0 -o "$iface" -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -i wg0 -o "$iface" -j ACCEPT

  iptables -C FORWARD -i "$iface" -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null \
    || iptables -A FORWARD -i "$iface" -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT

  ok "Règles iptables appliquées (session courante)."

  if has_cmd netfilter-persistent; then
    netfilter-persistent save >/dev/null || true
    ok "Règles sauvegardées (netfilter-persistent)."
  else
    warn "netfilter-persistent absent: règles iptables non persistées après reboot."
  fi
}

open_firewall_ufw() {
  local port="$1"
  if has_cmd ufw; then
    info "Ouverture du port WireGuard $port/udp via UFW…"
    ufw allow "${port}/udp" >/dev/null || true
    ok "Règle UFW ajoutée."
  else
    warn "UFW non installé. Si firewall actif, ouvre $port/udp."
  fi
}

###############
# Config files
###############
backup_file() {
  local f="$1"
  if [[ -f "$f" ]]; then
    cp -a "$f" "${f}.bak.$(date +%Y%m%d-%H%M%S)"
    ok "Backup: ${f}.bak.*"
  fi
}

write_server_conf() {
  local wg_addr="$1" wg_cidr="$2" listen_port="$3" server_priv="$4" iface="$5"

  mkdir -p /etc/wireguard
  chmod 700 /etc/wireguard
  backup_file /etc/wireguard/wg0.conf

  info "Écriture /etc/wireguard/wg0.conf…"
  cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = $wg_addr
ListenPort = $listen_port
PrivateKey = $server_priv

# NAT + forwarding (au moment where wg0 monte/descend)
PostUp   = iptables -t nat -A POSTROUTING -s $wg_cidr -o $iface -j MASQUERADE; iptables -A FORWARD -i wg0 -o $iface -j ACCEPT; iptables -A FORWARD -i $iface -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s $wg_cidr -o $iface -j MASQUERADE; iptables -D FORWARD -i wg0 -o $iface -j ACCEPT; iptables -D FORWARD -i $iface -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
EOF

  chmod 600 /etc/wireguard/wg0.conf
  ok "wg0.conf écrit."
}

append_peer_to_server() {
  local client_pub="$1" client_ip="$2"
  {
    echo
    echo "[Peer]"
    echo "PublicKey = $client_pub"
    echo "AllowedIPs = $client_ip/32"
  } >> /etc/wireguard/wg0.conf
}

write_client_conf() {
  local name="$1" client_priv="$2" server_pub="$3" endpoint_host="$4" endpoint_port="$5" client_ip="$6" wg_dns="$7" allowed="$8"

  local outdir="/root/wireguard-clients"
  mkdir -p "$outdir"
  chmod 700 "$outdir"

  local f="$outdir/${name}.conf"
  cat > "$f" <<EOF
[Interface]
PrivateKey = $client_priv
Address = $client_ip/32
DNS = $wg_dns

[Peer]
PublicKey = $server_pub
Endpoint = $endpoint_host:$endpoint_port
AllowedIPs = $allowed
PersistentKeepalive = 25
EOF

  chmod 600 "$f"
  ok "Client généré : $f"

  if has_cmd qrencode; then
    echo
    info "QR (si tu importes sur mobile) :"
    qrencode -t ansiutf8 < "$f" || true
    echo
  fi
}

###############
# Client IP allocation
###############
next_client_ip() {
  local base="$1" start="$2" used_list="$3"
  # base like 10.8.0.0 and start like 2
  local i ip
  for i in $(seq "$start" 254); do
    ip="${base%.*}.${i}"
    if ! grep -qx "$ip" <<< "$used_list"; then
      echo "$ip"
      return 0
    fi
  done
  return 1
}

extract_base_from_cidr() {
  local cidr="$1"
  # expects /24-like networks for automatic IP allocation
  echo "${cidr%/*}"
}

###############
# Service
###############
start_wg() {
  info "Activation + démarrage wg-quick@wg0…"
  systemctl enable --now wg-quick@wg0 >/dev/null
  systemctl --no-pager --full status wg-quick@wg0 | sed -n '1,14p' || true
  ok "WireGuard démarré (si pas d'erreur ci-dessus)."
}

reload_wg() {
  # wg-quick is fine to restart
  systemctl restart wg-quick@wg0 >/dev/null
}

###############
# Main
###############
need_root
ensure_debian_like

iface="$(get_default_iface || true)"
[[ -n "$iface" ]] || die "Impossible de détecter l'interface réseau par défaut."
ip_local="$(get_primary_ip "$iface" || true)"
ip_pub="$(detect_public_ip || true)"

echo
info "Interface : $iface (IP locale: ${ip_local:-inconnue})"
[[ -n "$ip_pub" ]] && info "IP publique détectée : $ip_pub"

# Endpoint
default_endpoint="${ip_pub:-${ip_local:-}}"
prompt ENDPOINT_HOST "Endpoint (IP publique ou domaine que les clients utiliseront)" "$default_endpoint"
[[ -n "$ENDPOINT_HOST" ]] || die "Endpoint vide."

# Port
while true; do
  prompt WG_PORT "Port WireGuard (UDP)" "51820"
  is_valid_port "$WG_PORT" && break
  echo "Port invalide."
done

# WG network
prompt WG_CIDR "Réseau WireGuard (CIDR)" "10.8.0.0/24"
is_valid_cidr "$WG_CIDR" || die "CIDR invalide (ex: 10.8.0.0/24)."

# Only /24 is supported for automatic IP allocation in this script.
WG_PREFIX="${WG_CIDR#*/}"
[[ "$WG_PREFIX" == "24" ]] || die "Ce script gère l’allocation IP automatique en /24 uniquement. Utilise /24 ou adapte le script."

WG_BASE="$(extract_base_from_cidr "$WG_CIDR")"
WG_SERVER_IP="${WG_BASE%.*}.1"
WG_SERVER_ADDR="${WG_SERVER_IP}/24"

# DNS pushed to clients
echo
echo "DNS à pousser aux clients :"
echo "  1) Cloudflare (1.1.1.1)"
echo "  2) Google (8.8.8.8)"
echo "  3) Quad9 (9.9.9.9)"
echo "  4) DNS du serveur (resolv.conf)"
while true; do
  read -r -p "Ton choix [1]: " DNS_CHOICE
  DNS_CHOICE="${DNS_CHOICE:-1}"
  [[ "$DNS_CHOICE" =~ ^[1-4]$ ]] && break
  echo "Choix invalide."
done

WG_DNS="1.1.1.1"
case "$DNS_CHOICE" in
  1) WG_DNS="1.1.1.1" ;;
  2) WG_DNS="8.8.8.8" ;;
  3) WG_DNS="9.9.9.9" ;;
  4)
    WG_DNS="$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf || true)"
    [[ -n "$WG_DNS" ]] || WG_DNS="1.1.1.1"
    ;;
esac

# Full tunnel or split tunnel
echo
echo "Mode de routage client :"
echo "  1) Full-tunnel (tout le trafic passe dans le VPN)  -> AllowedIPs = 0.0.0.0/0"
echo "  2) Split-tunnel (seulement accès au réseau VPN)   -> AllowedIPs = ${WG_CIDR}"
read -r -p "Ton choix [1]: " ROUTE_MODE
ROUTE_MODE="${ROUTE_MODE:-1}"
[[ "$ROUTE_MODE" =~ ^[1-2]$ ]] || die "Choix invalide."
CLIENT_ALLOWED="0.0.0.0/0"
[[ "$ROUTE_MODE" == "2" ]] && CLIENT_ALLOWED="$WG_CIDR"

prompt_yn DO_UFW "Ajouter une règle UFW pour $WG_PORT/udp (si UFW est installé) ?" "y"

echo
info "Résumé :"
echo "  - Endpoint : $ENDPOINT_HOST:$WG_PORT/udp"
echo "  - IFACE    : $iface"
echo "  - WG Net   : $WG_CIDR (serveur: $WG_SERVER_IP)"
echo "  - DNS      : $WG_DNS"
echo "  - Clients  : ${CLIENT_ALLOWED}"
echo

prompt_yn GO "Lancer l'installation maintenant ?" "y"
[[ "$GO" == "y" ]] || die "Annulé."

install_pkgs
enable_ip_forward

# Generate server keys
info "Génération des clés serveur…"
server_keys="$(gen_keypair)"
SERVER_PRIV="${server_keys%%|*}"
SERVER_PUB="${server_keys##*|}"
ok "Clés serveur OK."

write_server_conf "$WG_SERVER_ADDR" "$WG_CIDR" "$WG_PORT" "$SERVER_PRIV" "$iface"

# Apply NAT now + persist
apply_nat_rules_now "$iface" "$WG_CIDR"

# Create clients
echo
info "Création des clients (au moins 1)."
USED_IPS="$WG_SERVER_IP"
CLIENT_START_OCTET="2"

while true; do
  prompt CLIENT_NAME "Nom du client (ex: phone1) ou vide pour finir" "client1"
  # If user pressed enter on default for first loop, it becomes client1; allow empty only if already created one
  if [[ -z "$CLIENT_NAME" ]]; then
    break
  fi
  is_valid_name "$CLIENT_NAME" || { echo "Nom invalide (lettres/chiffres/._-)."; continue; }

  # Suggest next free IP
  NEXT_IP="$(next_client_ip "$WG_BASE" "$CLIENT_START_OCTET" "$USED_IPS" || true)"
  [[ -n "$NEXT_IP" ]] || die "Plus d'IP disponibles dans /24."
  prompt CLIENT_IP "IP du client (dans $WG_CIDR)" "$NEXT_IP"
  is_valid_ipv4 "$CLIENT_IP" || { echo "IP invalide."; continue; }

  # simple check IP inside same /24 base
  [[ "${CLIENT_IP%.*}" == "${WG_BASE%.*}" ]] || { echo "IP hors du /24 (base attendue: ${WG_BASE%.*}.x)"; continue; }
  if grep -qx "$CLIENT_IP" <<< "$USED_IPS"; then
    echo "IP déjà utilisée. Choisis-en une autre."
    continue
  fi

  # Generate client keys
  client_keys="$(gen_keypair)"
  CLIENT_PRIV="${client_keys%%|*}"
  CLIENT_PUB="${client_keys##*|}"

  # Append peer to server conf
  append_peer_to_server "$CLIENT_PUB" "$CLIENT_IP"
  USED_IPS="$USED_IPS"$'\n'"$CLIENT_IP"

  # Write client config
  write_client_conf "$CLIENT_NAME" "$CLIENT_PRIV" "$SERVER_PUB" "$ENDPOINT_HOST" "$WG_PORT" "$CLIENT_IP" "$WG_DNS" "$CLIENT_ALLOWED"

  prompt_yn MORE "Ajouter un autre client ?" "y"
  [[ "$MORE" == "y" ]] || break
done

# Start/reload WG
start_wg

# Ensure server picks up new peers (wg-quick restart reads config)
reload_wg

if [[ "$DO_UFW" == "y" ]]; then
  open_firewall_ufw "$WG_PORT"
fi

echo
ok "Terminé."
info "Configs clients : /root/wireguard-clients/*.conf"
info "Voir état : wg show"
info "Logs service : journalctl -u wg-quick@wg0 --no-pager -n 120"
