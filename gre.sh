#!/bin/bash
set -euo pipefail

CONF_FILE="/etc/gre-tunnel.conf"
INSTALL_BIN="/usr/local/bin/gre.sh"
SERVICE_UNIT="/etc/systemd/system/gre-tunnel.service"
DEFAULT_TUNNEL_DEV="gre1"
DEFAULT_MTU="1390"

ensure_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "[-] This script must be run as root." >&2
    exit 1
  fi
}

validate_ipv4() {
  local ip=$1
  local ip_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
  if [[ ! $ip =~ $ip_regex ]]; then
    return 1
  fi
  IFS='.' read -r -a octets <<< "$ip"
  for octet in "${octets[@]}"; do
    if ((octet < 0 || octet > 255)); then
      return 1
    fi
  done
  return 0
}

validate_cidr_ipv4() {
  local cidr=$1
  local ip="${cidr%/*}"
  local prefix="${cidr#*/}"

  if [[ "$ip" == "$cidr" || -z "$prefix" || ! "$prefix" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  if ((prefix < 8 || prefix > 32)); then
    return 1
  fi
  validate_ipv4 "$ip"
}

detect_local_public_ip() {
  local detected
  detected=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}' || true)
  if [ -z "$detected" ]; then
    detected=$(curl -s4 --max-time 3 https://api.ipify.org || true)
  fi
  echo "$detected"
}

save_config() {
  cat > "$CONF_FILE" <<EOF
ROLE="$ROLE"
SERVER_ROLE="$SERVER_ROLE"
TUNNEL_DEV="$TUNNEL_DEV"
LOCAL_PUBLIC_IP="$LOCAL_PUBLIC_IP"
REMOTE_PUBLIC_IP="$REMOTE_PUBLIC_IP"
LOCAL_GRE_IP="$LOCAL_GRE_IP"
REMOTE_GRE_IP="$REMOTE_GRE_IP"
MTU_VAL="$MTU_VAL"
EOF
  chmod 600 "$CONF_FILE"
  echo "[✓] Configuration saved to $CONF_FILE"
}

load_config() {
  if [ -f "$CONF_FILE" ]; then
    # shellcheck disable=SC1090
    source "$CONF_FILE"
    TUNNEL_DEV="${TUNNEL_DEV:-$DEFAULT_TUNNEL_DEV}"
    MTU_VAL="${MTU_VAL:-$DEFAULT_MTU}"
    return 0
  fi
  return 1
}

apply_firewall_and_sysctl() {
  local dev="$1"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
  if [ -f /etc/sysctl.conf ]; then
    if grep -q '^net.ipv4.ip_forward' /etc/sysctl.conf; then
      sed -i 's/^net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf
    else
      echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
  fi

  if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p gre -j ACCEPT 2>/dev/null || iptables -A INPUT -p gre -j ACCEPT
    iptables -C OUTPUT -p gre -j ACCEPT 2>/dev/null || iptables -A OUTPUT -p gre -j ACCEPT

    # MSS Clamping جهت جلوگیری از افت پکت و کندی وب
    iptables -t mangle -C FORWARD -o "$dev" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
      iptables -t mangle -A FORWARD -o "$dev" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
  fi
}

remove_firewall_rules() {
  local dev="$1"
  if command -v iptables >/dev/null 2>&1; then
    iptables -t mangle -D FORWARD -o "$dev" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
  fi
}

create_tunnel() {
  local interactive=${1:-0}
  if [ "$interactive" -eq 1 ]; then
    clear
  fi

  LOCAL_PUBLIC_IP="${LOCAL_PUBLIC_IP:-$(detect_local_public_ip)}"
  TUNNEL_DEV="${TUNNEL_DEV:-$DEFAULT_TUNNEL_DEV}"
  MTU_VAL="${MTU_VAL:-$DEFAULT_MTU}"

  if [ -z "$LOCAL_PUBLIC_IP" ] || ! validate_ipv4 "$LOCAL_PUBLIC_IP"; then
    echo "[-] Invalid local public IPv4: '$LOCAL_PUBLIC_IP'" >&2
    return 1
  fi

  if [ -z "$REMOTE_PUBLIC_IP" ] || ! validate_ipv4 "$REMOTE_PUBLIC_IP"; then
    echo "[-] Invalid remote public IPv4: '$REMOTE_PUBLIC_IP'" >&2
    return 1
  fi

  echo "=========================================="
  echo "[*] Role:             ${SERVER_ROLE:-Custom}"
  echo "[*] Tunnel Interface: $TUNNEL_DEV"
  echo "[*] Local Public IP:  $LOCAL_PUBLIC_IP"
  echo "[*] Remote Public IP: $REMOTE_PUBLIC_IP"
  echo "[*] Tunnel IP (Self): $LOCAL_GRE_IP"
  echo "[*] Tunnel IP (Peer): $REMOTE_GRE_IP"
  echo "[*] MTU:              $MTU_VAL"
  echo "=========================================="

  modprobe ip_gre 2>/dev/null || true

  # ریست اینترفیس قبلی
  ip link set "$TUNNEL_DEV" down 2>/dev/null || true
  ip tunnel del "$TUNNEL_DEV" 2>/dev/null || true

  # ساخت تانل
  ip tunnel add "$TUNNEL_DEV" mode gre local "$LOCAL_PUBLIC_IP" remote "$REMOTE_PUBLIC_IP" ttl 255
  ip addr add "$LOCAL_GRE_IP" dev "$TUNNEL_DEV"
  ip link set "$TUNNEL_DEV" mtu "$MTU_VAL"
  ip link set "$TUNNEL_DEV" up

  if ! ip link show "$TUNNEL_DEV" >/dev/null 2>&1; then
    echo "[-] GRE interface creation failed." >&2
    return 1
  fi

  apply_firewall_and_sysctl "$TUNNEL_DEV"

  echo
  echo "[✓] GRE tunnel interface ($TUNNEL_DEV) is successfully UP!"

  if [ "$interactive" -eq 1 ]; then
    echo
    read -rp "Save this configuration to $CONF_FILE? [Y/n]: " yn
    yn="${yn:-y}"
    case "$yn" in
      [Yy]*)
        save_config
        echo
        read -rp "Install & enable systemd service on boot? [Y/n]: " sn
        sn="${sn:-y}"
        case "$sn" in
          [Yy]*) install_service || echo "[-] Failed to setup systemd unit." ;;
          *) echo "[i] Service not installed." ;;
        esac
        ;;
      *) echo "[i] Configuration discarded." ;;
    esac
  fi

  return 0
}

menu_config_tunnel() {
  clear
  echo "======================================"
  echo "       Configure GRE Tunnel           "
  echo "======================================"
  echo "1) Iran Server"
  echo "2) Kharej Server"
  echo
  read -rp "Select server role [1-2]: " ROLE
  if [[ "$ROLE" != "1" && "$ROLE" != "2" ]]; then
    echo "[-] Invalid selection."
    return
  fi

  if [ "$ROLE" == "1" ]; then
    SERVER_ROLE="IRAN"
  else
    SERVER_ROLE="KHAREJ"
  fi

  TUNNEL_DEV="$DEFAULT_TUNNEL_DEV"
  read -rp "Interface name [Default: $DEFAULT_TUNNEL_DEV]: " input_dev
  TUNNEL_DEV="${input_dev:-$DEFAULT_TUNNEL_DEV}"

  detected_ip=$(detect_local_public_ip)
  read -rp "Local Public IP [Detected: ${detected_ip:-None}]: " input_local_ip
  LOCAL_PUBLIC_IP="${input_local_ip:-$detected_ip}"
  if ! validate_ipv4 "$LOCAL_PUBLIC_IP"; then
    echo "[-] Invalid Local Public IPv4."
    return
  fi

  read -rp "Remote Server Public IPv4: " REMOTE_PUBLIC_IP
  if ! validate_ipv4 "$REMOTE_PUBLIC_IP"; then
    echo "[-] Invalid Remote Public IPv4."
    return
  fi

  echo
  echo "--- Private / Tunnel IP Setup ---"
  echo "Enter subnet base (e.g. 10.10.30 or 172.16.1)."
  echo "The script will automatically assign:"
  echo "  - Iran Server:   <base>.1/30 (Local)  | <base>.2 (Remote)"
  echo "  - Kharej Server: <base>.2/30 (Local)  | <base>.1 (Remote)"
  echo
  read -rp "Tunnel Subnet [Default: 10.10.10]: " input_prefix
  input_prefix="${input_prefix:-10.10.10}"

  # استخراج دقیق ۳ بخش اول IP بدون باگ sed
  if [[ "$input_prefix" =~ ^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) ]]; then
    BASE_NET="${BASH_REMATCH[1]}"
  else
    echo "[-] Invalid subnet format! Using default: 10.10.10"
    BASE_NET="10.10.10"
  fi

  # انتساب دقیق و خودکار بر اساس نقش سرور
  if [ "$ROLE" == "1" ]; then
    LOCAL_GRE_IP="${BASE_NET}.1/30"
    REMOTE_GRE_IP="${BASE_NET}.2"
  else
    LOCAL_GRE_IP="${BASE_NET}.2/30"
    REMOTE_GRE_IP="${BASE_NET}.1"
  fi

  echo
  echo "[✓] Configured IPs for $SERVER_ROLE:"
  echo "    Local GRE IP:  $LOCAL_GRE_IP"
  echo "    Remote GRE IP: $REMOTE_GRE_IP"
  echo

  read -rp "Do you want to change these private IPs manually? [y/N]: " custom_yn
  if [[ "$custom_yn" =~ ^[Yy]$ ]]; then
    read -rp "Enter Local GRE IP with CIDR (e.g. ${BASE_NET}.1/30): " LOCAL_GRE_IP
    read -rp "Enter Remote GRE IP (e.g. ${BASE_NET}.2): " REMOTE_GRE_IP
  fi

  read -rp "Tunnel MTU [Default: $DEFAULT_MTU]: " input_mtu
  MTU_VAL="${input_mtu:-$DEFAULT_MTU}"

  create_tunnel 1 || echo "[-] Tunnel setup failed."
}

status_check() {
  clear
  echo "======================================"
  echo "          GRE Tunnel Status           "
  echo "======================================"

  local dev="$DEFAULT_TUNNEL_DEV"
  if load_config; then
    dev="$TUNNEL_DEV"
  fi

  if ! ip link show "$dev" >/dev/null 2>&1; then
    echo "[-] Interface '$dev' does not exist."
    return
  fi

  local link_state
  link_state=$(ip -brief link show "$dev" | awk '{print $2}')
  local local_addr
  local_addr=$(ip -brief addr show "$dev" | awk '{print $3}')

  echo "[i] Interface:      $dev"
  echo "[i] Link State:     $link_state"
  echo "[i] Tunnel Local:   ${local_addr:-Not set}"

  local tun_info
  tun_info=$(ip tunnel show "$dev" 2>/dev/null || true)
  local remote_pub
  remote_pub=$(echo "$tun_info" | awk -F'remote ' '{print $2}' | awk '{print $1}')
  echo "[i] Remote Pub IP:  ${remote_pub:-N/A}"

  echo "--------------------------------------"
  if [ -n "$remote_pub" ]; then
    echo "[*] Pinging Remote Public IP ($remote_pub)..."
    if ping -c 2 -W 1 "$remote_pub" >/dev/null 2>&1; then
      echo "    -> Remote Public IP is REACHABLE [✓]"
    else
      echo "    -> Remote Public IP is UNREACHABLE [✗]"
    fi
  fi

  local target_inner="${REMOTE_GRE_IP:-}"
  if [ -z "$target_inner" ] && load_config; then
    target_inner="$REMOTE_GRE_IP"
  fi

  if [ -n "$target_inner" ]; then
    echo "[*] Pinging Tunnel Remote IP ($target_inner)..."
    local ping_result
    ping_result=$(ping -c 3 -W 2 "$target_inner" 2>&1 || true)
    if echo "$ping_result" | grep -qE '([1-9]) (packets )?received'; then
      local rtt
      rtt=$(echo "$ping_result" | awk -F'/' 'END{print $5}')
      echo "    -> Tunnel Link is ACTIVE [✓] (Latency: ~${rtt:-?} ms)"
    else
      echo "    -> Tunnel Link is DOWN / NOT RESPONDING [✗]"
    fi
  else
    echo "[i] Remote inner IP not loaded. Save configuration to test tunnel ping."
  fi

  echo "--------------------------------------"
  echo "[*] Interface Traffic Stats:"
  ip -s link show "$dev" | grep -E 'RX:|TX:|[0-9]+ +[0-9]+ +[0-9]+'
}

stop_tunnel() {
  local dev="${1:-$DEFAULT_TUNNEL_DEV}"
  remove_firewall_rules "$dev"
  ip link set dev "$dev" down 2>/dev/null || true
  ip tunnel del "$dev" 2>/dev/null || true
  ip link delete "$dev" 2>/dev/null || true
}

remove_tun() {
  clear
  echo "======================================"
  echo "       Remove Tunnel Interfaces       "
  echo "======================================"

  mapfile -t tunifs < <(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep -E '^(gre|gretap|erspan)' || true)

  if [ ${#tunifs[@]} -eq 0 ]; then
    echo "[i] No GRE/GRETAP interfaces found."
  else
    for ifc in "${tunifs[@]}"; do
      echo "[*] Removing $ifc..."
      stop_tunnel "$ifc"
      echo "[✓] $ifc removed."
    done
  fi

  echo
  read -rp "Remove saved configuration ($CONF_FILE)? [y/N]: " yn
  case "$yn" in
    [Yy]*) rm -f "$CONF_FILE"; echo "[✓] Config removed." ;;
    *) echo "[i] Config retained." ;;
  esac

  if [ -f "$SERVICE_UNIT" ] || systemctl list-unit-files 2>/dev/null | grep -q '^gre-tunnel.service'; then
    read -rp "Uninstall systemd boot service? [y/N]: " sy
    case "$sy" in
      [Yy]*) uninstall_service ;;
      *) echo "[i] Service kept." ;;
    esac
  fi
}

install_service() {
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "[-] systemctl not available." >&2
    return 1
  fi

  local script_source="${BASH_SOURCE[0]:-$0}"
  if [ ! -f "$script_source" ]; then
    script_source="$(command -v "$0" || true)"
  fi

  if [ ! -f "$script_source" ]; then
    echo "[-] Cannot detect script file path directly." >&2
    echo "[-] Please save the script to a file (e.g. /root/gre.sh) and run with: bash /root/gre.sh" >&2
    return 1
  fi

  mkdir -p "$(dirname "$INSTALL_BIN")"
  cp -f -- "$script_source" "$INSTALL_BIN"
  chmod 755 "$INSTALL_BIN"

  cat > "$SERVICE_UNIT" <<EOF
[Unit]
Description=GRE Tunnel Service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash $INSTALL_BIN --service start
ExecStop=/bin/bash $INSTALL_BIN --service stop
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now gre-tunnel.service

  if systemctl is-active --quiet gre-tunnel.service; then
    echo "[✓] Service installed and started successfully: gre-tunnel.service"
  else
    echo "[-] Service installed but failed to start. Run: journalctl -xeu gre-tunnel.service"
    return 1
  fi
}

uninstall_service() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now gre-tunnel.service 2>/dev/null || true
    rm -f "$SERVICE_UNIT"
    systemctl daemon-reload
  fi
  rm -f "$INSTALL_BIN"
  echo "[✓] Service uninstalled and binary removed."
}

service_start() {
  if load_config; then
    create_tunnel 0
  else
    echo "[-] No configuration found at $CONF_FILE" >&2
    return 1
  fi
}

service_stop() {
  if load_config; then
    stop_tunnel "$TUNNEL_DEV"
  else
    stop_tunnel "$DEFAULT_TUNNEL_DEV"
  fi
}

show_menu() {
  clear
  echo "======================================"
  echo "      GRE Tunnel Management Tool      "
  echo "======================================"
  echo "1) Configure / Start Tunnel"
  echo "2) Check Tunnel Status"
  echo "3) Remove Tunnel & Clean"
  echo "0) Exit"
  echo
  read -rp "Select an option [0-3]: " CHOICE
  case "$CHOICE" in
    1) menu_config_tunnel ; read -rp "Press Enter to continue..." _ ;;
    2) status_check ; read -rp "Press Enter to continue..." _ ;;
    3) remove_tun ; read -rp "Press Enter to continue..." _ ;;
    0) echo "Exiting..."; exit 0 ;;
    *) echo "[-] Invalid option."; sleep 1 ;;
  esac
}

# Entrypoint
if [[ "${1:-}" == "--service" ]]; then
  ensure_root
  case "${2:-}" in
    start) service_start; exit $? ;;
    stop)  service_stop; exit $? ;;
    *) echo "Usage: $0 --service {start|stop}" >&2; exit 1 ;;
  esac
fi

ensure_root
while true; do
  show_menu
done
