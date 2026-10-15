#!/bin/bash
# با -e کار نمی‌کنیم تا هر خطای جزئی باعث خروج از اسکریپت نشود؛
# هر عملیات خطاپذیر خودش خطا را مدیریت می‌کند.
set -o pipefail

VERSION="2.0.0"

CONF_FILE="/etc/gre-tunnel.conf"
CONF_DIR="/etc/gre-tunnel.d"
INSTALL_BIN="/usr/local/bin/gre.sh"
SERVICE_UNIT="/etc/systemd/system/gre-tunnel.service"
MOTD_FILE="/etc/update-motd.d/99-gre-tunnel"
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

# آی‌پی سرور یک‌بار تشخیص داده و کش می‌شود تا منو سریع باز شود
CACHED_SERVER_IPV4=""
get_server_ipv4_cached() {
  if [ -z "$CACHED_SERVER_IPV4" ]; then
    CACHED_SERVER_IPV4=$(detect_local_public_ip)
  fi
  printf '%s' "$CACHED_SERVER_IPV4"
}

# پیدا کردن اولین اینترفیس gre آزاد (gre1, gre2, ...)
next_tunnel_dev() {
  local i=1
  while ip link show "gre$i" >/dev/null 2>&1; do
    i=$((i + 1))
  done
  echo "gre$i"
}

write_config_block() {
  local file=$1
  cat > "$file" <<EOF
ROLE="$ROLE"
SERVER_ROLE="$SERVER_ROLE"
TUNNEL_DEV="$TUNNEL_DEV"
LOCAL_PUBLIC_IP="$LOCAL_PUBLIC_IP"
REMOTE_PUBLIC_IP="$REMOTE_PUBLIC_IP"
LOCAL_GRE_IP="$LOCAL_GRE_IP"
REMOTE_GRE_IP="$REMOTE_GRE_IP"
MTU_VAL="$MTU_VAL"
EOF
  chmod 600 "$file"
}

# ثبت تانل در پوشه‌ی مدیریت تا در منوی Management قابل مشاهده/حذف باشد
save_tunnel_record() {
  local quiet=${1:-0}
  mkdir -p "$CONF_DIR"
  local target="$CONF_DIR/${TUNNEL_DEV}.conf"
  write_config_block "$target"
  if [ "$quiet" -ne 1 ]; then
    echo "[✓] Tunnel '$TUNNEL_DEV' registered for management: $target"
  fi
}

save_config() {
  save_tunnel_record 1
  write_config_block "$CONF_FILE"
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

# خواندن فیلدهای یک فایل کانفیگ به صورت رشته‌ی جدا شده با |
# خروجی: dev|role|local_pub|remote_pub|local_gre|remote_gre|mtu
config_fields() {
  local cfg=$1
  (
    set +u
    # shellcheck disable=SC1090
    source "$cfg" 2>/dev/null || true
    printf '%s|%s|%s|%s|%s|%s|%s' \
      "${TUNNEL_DEV:-}" "${SERVER_ROLE:-}" "${LOCAL_PUBLIC_IP:-}" \
      "${REMOTE_PUBLIC_IP:-}" "${LOCAL_GRE_IP:-}" "${REMOTE_GRE_IP:-}" "${MTU_VAL:-}"
  )
}

# فهرست فایل‌های کانفیگ تانل‌های ثبت‌شده (هر خط یک مسیر)
list_tunnel_records() {
  local cfg
  for cfg in "$CONF_DIR"/*.conf; do
    [ -e "$cfg" ] || continue
    printf '%s\n' "$cfg"
  done
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

  # ثبت خودکار تانل ساخته‌شده برای منوی Management
  save_tunnel_record 1

  if [ "$interactive" -eq 1 ]; then
    echo
    # ذخیرهٔ خودکار کانفیگ + فعال‌سازی ماندگاری پس از ریبوت
    save_config
    echo
    install_service || echo "[-] Boot persistence could not be enabled (service setup failed)."
    install_motd || true
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
  read -rp "Select server role [1-2]: " role_in
  case "$role_in" in
    1) ROLE="1"; SERVER_ROLE="IRAN" ;;
    2) ROLE="2"; SERVER_ROLE="KHAREJ" ;;
    *) echo "[-] Invalid selection."; return ;;
  esac

  # کمترین ورودی الزامی: آی‌پی عمومی سمت مقابل
  read -rp "Remote (peer) Public IPv4: " REMOTE_PUBLIC_IP
  if ! validate_ipv4 "$REMOTE_PUBLIC_IP"; then
    echo "[-] Invalid Remote Public IPv4."
    return
  fi

  # آی‌پی عمومی این سرور به صورت خودکار تشخیص داده می‌شود
  local detected_ip
  detected_ip=$(detect_local_public_ip)
  read -rp "This server's Public IPv4 [Detected: ${detected_ip:-None}]: " input_local_ip
  LOCAL_PUBLIC_IP="${input_local_ip:-$detected_ip}"
  if ! validate_ipv4 "$LOCAL_PUBLIC_IP"; then
    echo "[-] Invalid Local Public IPv4."
    return
  fi

  # مقادیر پیش‌فرض (در حالت عادی نیازی به تغییر ندارند)
  TUNNEL_DEV="$(next_tunnel_dev)"
  BASE_NET="10.10.10"
  MTU_VAL="$DEFAULT_MTU"

  echo
  read -rp "Use advanced settings (interface / subnet / MTU)? [y/N]: " adv_yn
  if [[ "$adv_yn" =~ ^[Yy]$ ]]; then
    local input_dev input_prefix input_mtu
    read -rp "Interface name [Default: $TUNNEL_DEV]: " input_dev
    TUNNEL_DEV="${input_dev:-$TUNNEL_DEV}"

    echo "Subnet base sets the two inner tunnel IPs automatically:"
    echo "  - Iran Server:   <base>.1/30 (Local) | <base>.2 (Remote)"
    echo "  - Kharej Server: <base>.2/30 (Local) | <base>.1 (Remote)"
    read -rp "Tunnel Subnet base (e.g. 10.10.30) [Default: $BASE_NET]: " input_prefix
    input_prefix="${input_prefix:-$BASE_NET}"
    if [[ "$input_prefix" =~ ^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) ]]; then
      BASE_NET="${BASH_REMATCH[1]}"
    else
      echo "[-] Invalid subnet format! Using default: $BASE_NET"
    fi

    read -rp "Tunnel MTU [Default: $DEFAULT_MTU]: " input_mtu
    MTU_VAL="${input_mtu:-$DEFAULT_MTU}"
  fi

  # انتساب خودکار آی‌پی‌های داخلی تانل بر اساس نقش سرور
  if [ "$ROLE" == "1" ]; then
    LOCAL_GRE_IP="${BASE_NET}.1/30"
    REMOTE_GRE_IP="${BASE_NET}.2"
  else
    LOCAL_GRE_IP="${BASE_NET}.2/30"
    REMOTE_GRE_IP="${BASE_NET}.1"
  fi

  echo
  echo "[✓] Summary for $SERVER_ROLE:"
  echo "    Interface:        $TUNNEL_DEV"
  echo "    Local Public IP:  $LOCAL_PUBLIC_IP"
  echo "    Remote Public IP: $REMOTE_PUBLIC_IP"
  echo "    Local GRE IP:     $LOCAL_GRE_IP"
  echo "    Remote GRE IP:    $REMOTE_GRE_IP"
  echo "    MTU:              $MTU_VAL"
  echo

  # امکان شخصی‌سازی دستی آی‌پی‌های داخلی (اختیاری)
  read -rp "Customize inner GRE IPs manually? [y/N]: " custom_yn
  if [[ "$custom_yn" =~ ^[Yy]$ ]]; then
    read -rp "Enter Local GRE IP with CIDR (e.g. ${BASE_NET}.1/30): " LOCAL_GRE_IP
    read -rp "Enter Remote GRE IP (e.g. ${BASE_NET}.2): " REMOTE_GRE_IP
  fi

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
    [Yy]*)
      rm -f "$CONF_FILE"
      rm -f "$CONF_DIR"/*.conf 2>/dev/null || true
      rmdir "$CONF_DIR" 2>/dev/null || true
      echo "[✓] Config removed."
      ;;
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

# ------------------------------------------------------------------
#  منوی Management: مدیریت تمام تانل‌های ثبت‌شده توسط این اسکریپت
# ------------------------------------------------------------------

# نمایش وضعیت یک تانل به همراه ۴ درخواست پینگ بین آی‌پی‌های تانل
show_tunnel_status_from_config() {
  local cfg=$1
  local dev role lpub rpub lgre rgre mtu
  IFS='|' read -r dev role lpub rpub lgre rgre mtu < <(config_fields "$cfg")
  dev="${dev:-$DEFAULT_TUNNEL_DEV}"

  echo "--------------------------------------"
  echo "[*] Tunnel Interface: ${dev}"
  echo "    Role:              ${role:-Custom}"
  echo "    Config:            $cfg"
  echo "    Local Public IP:   ${lpub:-N/A}"
  echo "    Remote Public IP:  ${rpub:-N/A}"
  echo "    Local GRE IP:      ${lgre:-N/A}"
  echo "    Remote GRE IP:     ${rgre:-N/A}"

  if ip link show "$dev" >/dev/null 2>&1; then
    local link_state local_addr
    link_state=$(ip -brief link show "$dev" | awk '{print $2}')
    local_addr=$(ip -brief addr show "$dev" | awk '{print $3}')
    echo "    Link State:        ${link_state:-UNKNOWN}"
    echo "    Assigned Address:  ${local_addr:-Not set}"
  else
    echo "    Link State:        DOWN (interface missing) [✗]"
  fi

  # پینگ به آی‌پی داخلی تانل سمت مقابل - ۴ درخواست
  local target="${rgre%/}"
  if [ -z "$target" ]; then
    echo "    Ping Test:         skipped (remote GRE IP unknown)"
    return
  fi

  echo "    Ping Test -> $target (4 requests):"
  local result
  result=$(ping -c 4 -W 2 "$target" 2>&1 || true)
  if echo "$result" | grep -qE '[1-9][0-9]* (packets )?received'; then
    local rtt
    rtt=$(echo "$result" | awk -F'/' '/rtt|round-trip/ {print $5}')
    echo "      -> Tunnel Link is ACTIVE [✓] (avg latency: ~${rtt:-?} ms)"
  else
    echo "      -> Tunnel Link is DOWN / NOT RESPONDING [✗]"
  fi
}

# ساخت آرایه‌ای از مسیر کانفیگ تانل‌های ثبت‌شده
collect_tunnel_records() {
  local line
  TUNNEL_RECORDS=()
  while IFS= read -r line; do
    if [ -n "$line" ]; then
      TUNNEL_RECORDS+=("$line")
    fi
  done < <(list_tunnel_records)

  # سازگاری با کانفیگ قدیمی (تک‌تانلی) که در پوشه‌ی مدیریت ثبت نشده است
  if [ ${#TUNNEL_RECORDS[@]} -eq 0 ] && [ -f "$CONF_FILE" ]; then
    TUNNEL_RECORDS+=("$CONF_FILE")
  fi
}

manage_view_status() {
  clear
  echo "======================================"
  echo "        All Tunnels Status            "
  echo "======================================"

  collect_tunnel_records
  if [ ${#TUNNEL_RECORDS[@]} -eq 0 ]; then
    echo "[i] No tunnels are registered by this script."
    return
  fi

  local cfg
  for cfg in "${TUNNEL_RECORDS[@]}"; do
    show_tunnel_status_from_config "$cfg"
    echo
  done
}

# حذف یک تانل (اینترفیس + رکورد کانفیگ)
delete_tunnel_record() {
  local cfg=$1
  local dev
  IFS='|' read -r dev _ < <(config_fields "$cfg")
  dev="${dev:-$DEFAULT_TUNNEL_DEV}"

  echo "[*] Stopping and removing tunnel '$dev'..."
  stop_tunnel "$dev"
  rm -f "$cfg"

  # اگر کانفیگ اصلی (legacy) مربوط به همین تانل بود، آن را هم پاک کن
  if [ -f "$CONF_FILE" ]; then
    local legacy_dev
    IFS='|' read -r legacy_dev _ < <(config_fields "$CONF_FILE")
    if [ "$legacy_dev" = "$dev" ]; then
      rm -f "$CONF_FILE"
      echo "[i] Legacy config removed: $CONF_FILE"
    fi
  fi

  echo "[✓] Tunnel '$dev' removed."
}

manage_delete_tunnel() {
  clear
  echo "======================================"
  echo "          Delete a Tunnel             "
  echo "======================================"

  collect_tunnel_records
  if [ ${#TUNNEL_RECORDS[@]} -eq 0 ]; then
    echo "[i] No tunnels are registered by this script."
    return
  fi

  local i=1 cfg dev
  for cfg in "${TUNNEL_RECORDS[@]}"; do
    IFS='|' read -r dev _ < <(config_fields "$cfg")
    printf '%s) %-12s (%s)\n' "$i" "${dev:-?}" "$cfg"
    i=$((i + 1))
  done
  echo "0) Back"
  echo

  local sel
  read -rp "Select tunnel number to delete: " sel
  case "$sel" in
    0 | "") return ;;
  esac

  if ! [[ "$sel" =~ ^[0-9]+$ ]] || ((sel < 1 || sel > ${#TUNNEL_RECORDS[@]})); then
    echo "[-] Invalid selection."
    return
  fi

  local target="${TUNNEL_RECORDS[$((sel - 1))]}"
  IFS='|' read -r dev _ < <(config_fields "$target")

  local confirm
  read -rp "Delete tunnel '$dev' and its config? [y/N]: " confirm
  case "$confirm" in
    [Yy]*) delete_tunnel_record "$target" ;;
    *) echo "[i] Cancelled." ;;
  esac
}

menu_management() {
  while true; do
    clear
    echo "======================================"
    echo "          Tunnel Management           "
    echo "======================================"
    echo "1) View status of all tunnels (4x ping each)"
    echo "2) Delete a specific tunnel"
    echo "0) Back"
    echo
    read -rp "Select an option [0-2]: " mchoice
    case "$mchoice" in
      1) manage_view_status ;;
      2) manage_delete_tunnel ;;
      0 | "") return ;;
      *) echo "[-] Invalid option."; sleep 1; continue ;;
    esac
    echo
    read -rp "Press Enter to continue..." _
  done
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
    echo "[✓] Service installed & enabled — tunnels will survive reboot."
  else
    echo "[-] Service installed but failed to start. Run: journalctl -xeu gre-tunnel.service"
    return 1
  fi
}

# نصب اسکریپت وضعیت تانل در بنر ورود SSH (MOTD) اوبونتو
install_motd() {
  local dir
  dir="$(dirname "$MOTD_FILE")"
  if [ ! -d "$dir" ]; then
    echo "[i] $dir not found; skipping login banner setup."
    return 0
  fi

  cat > "$MOTD_FILE" <<'EOF'
#!/bin/bash
# Auto-generated by gre.sh — shows GRE tunnel status at SSH login
CONF_DIR="/etc/gre-tunnel.d"
shown=0
if [ -d "$CONF_DIR" ]; then
  for cfg in "$CONF_DIR"/*.conf; do
    [ -e "$cfg" ] || continue
    unset TUNNEL_DEV SERVER_ROLE LOCAL_GRE_IP REMOTE_GRE_IP
    # shellcheck disable=SC1090
    . "$cfg" 2>/dev/null || continue
    dev="${TUNNEL_DEV:-gre1}"
    state=$(ip -brief link show "$dev" 2>/dev/null | awk '{print $2}')
    [ -n "$state" ] || continue
    if [ "$shown" -eq 0 ]; then
      echo ""
      echo "  GRE Tunnels:"
      shown=1
    fi
    printf "   - %-6s [%-4s]  local %-18s remote %s\n" \
      "$dev" "$state" "${LOCAL_GRE_IP:-?}" "${REMOTE_GRE_IP:-?}"
  done
  if [ "$shown" -eq 1 ]; then
    echo ""
  fi
fi
EOF

  chmod +x "$MOTD_FILE" 2>/dev/null || true
  echo "[✓] Login banner installed: $MOTD_FILE"
}

uninstall_service() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now gre-tunnel.service 2>/dev/null || true
    rm -f "$SERVICE_UNIT"
    systemctl daemon-reload
  fi
  rm -f "$INSTALL_BIN"
  rm -f "$MOTD_FILE"
  echo "[✓] Service uninstalled, binary and login banner removed."
}

# شروع یک تانل ثبت‌شده در ساب‌شل (برای سرویس و منوی مدیریت)
start_tunnel_from_config() {
  local cfg=$1
  (
    set +u
    # shellcheck disable=SC1090
    source "$cfg" 2>/dev/null || true
    TUNNEL_DEV="${TUNNEL_DEV:-$DEFAULT_TUNNEL_DEV}"
    MTU_VAL="${MTU_VAL:-$DEFAULT_MTU}"
    create_tunnel 0
  )
}

service_start() {
  local started=0 cfg

  while IFS= read -r cfg; do
    [ -n "$cfg" ] || continue
    started=1
    start_tunnel_from_config "$cfg" || true
  done < <(list_tunnel_records)

  # سازگاری با کانفیگ قدیمی تک‌تانلی
  if [ "$started" -eq 0 ] && [ -f "$CONF_FILE" ]; then
    load_config && create_tunnel 0
    started=1
  fi

  if [ "$started" -eq 0 ]; then
    echo "[-] No configuration found at $CONF_DIR or $CONF_FILE" >&2
    return 1
  fi
}

service_stop() {
  local cfg dev

  while IFS= read -r cfg; do
    [ -n "$cfg" ] || continue
    IFS='|' read -r dev _ < <(config_fields "$cfg")
    [ -n "$dev" ] && stop_tunnel "$dev"
  done < <(list_tunnel_records)

  if [ -f "$CONF_FILE" ]; then
    load_config && stop_tunnel "$TUNNEL_DEV"
  fi

  return 0
}

show_menu() {
  clear
  local server_ip
  server_ip=$(get_server_ipv4_cached)
  echo "======================================"
  echo "      GRE Tunnel Management Tool      "
  echo "======================================"
  echo "   Version:     v$VERSION"
  echo "   Server IPv4: ${server_ip:-Unknown}"
  echo "--------------------------------------"
  echo "1) Configure / Start Tunnel"
  echo "2) Check Tunnel Status"
  echo "3) Management (all tunnels)"
  echo "4) Remove Tunnel & Clean"
  echo "0) Exit"
  echo
  read -rp "Select an option [0-4]: " CHOICE
  case "$CHOICE" in
    1) menu_config_tunnel ;;
    2) status_check ;;
    3) menu_management ;;
    4) remove_tun ;;
    0) echo "Exiting..."; exit 0 ;;
    *) echo "[-] Invalid option."; sleep 1; return ;;
  esac
  echo
  read -rp "Press Enter to continue..." _
}

# Entrypoint
case "${1:-}" in
  --service)
    ensure_root
    case "${2:-}" in
      start) service_start; exit $? ;;
      stop)  service_stop; exit $? ;;
      *) echo "Usage: $0 --service {start|stop}" >&2; exit 1 ;;
    esac
    ;;
  --version | -v)
    echo "gre.sh v$VERSION"
    exit 0
    ;;
esac

ensure_root
while true; do
  show_menu || true
done
