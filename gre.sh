#!/bin/bash
# با -e کار نمی‌کنیم تا هر خطای جزئی باعث خروج از اسکریپت نشود؛
# هر عملیات خطاپذیر خودش خطا را مدیریت می‌کند.
set -o pipefail

VERSION="2.2.0"

CONF_FILE="/etc/gre-tunnel.conf"
CONF_DIR="/etc/gre-tunnel.d"
INSTALL_BIN="/usr/local/bin/gre.sh"
SERVICE_UNIT="/etc/systemd/system/gre-tunnel.service"
# بنر ورود SSH: خطوط آی‌پی تانل داخل بلوک «System information» (landscape) تزریق می‌شوند
MOTD_FILE="/etc/update-motd.d/50-landscape-sysinfo"
MOTD_ORIG="/etc/update-motd.d/50-landscape-sysinfo.gre-orig"
MOTD_HELPER="/usr/local/bin/gre-motd-ip-lines"
MOTD_LEGACY="/etc/update-motd.d/99-gre-tunnel"
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

  echo
  read -rp "Remote (peer) Public IPv4: " REMOTE_PUBLIC_IP
  if ! validate_ipv4 "$REMOTE_PUBLIC_IP"; then
    echo "[-] Invalid Remote Public IPv4."
    return
  fi

  local detected_ip
  detected_ip=$(detect_local_public_ip)
  read -rp "This server's Public IPv4 [Detected: ${detected_ip:-None}]: " input_local_ip
  LOCAL_PUBLIC_IP="${input_local_ip:-$detected_ip}"
  if ! validate_ipv4 "$LOCAL_PUBLIC_IP"; then
    echo "[-] Invalid Local Public IPv4."
    return
  fi

  echo
  local default_dev
  default_dev="$(next_tunnel_dev)"
  read -rp "Interface name [Default: $default_dev]: " input_dev
  TUNNEL_DEV="${input_dev:-$default_dev}"

  # آی‌پی‌های داخلی تانل: کاربر کامل با CIDR وارد می‌کند
  local default_local default_remote
  if [ "$ROLE" == "1" ]; then
    default_local="10.10.10.1/24"
    default_remote="10.10.10.2/24"
  else
    default_local="10.10.10.2/24"
    default_remote="10.10.10.1/24"
  fi

  echo
  read -rp "Local Tunnel IP (this server) [Default: $default_local]: " input_local_gre
  LOCAL_GRE_IP="${input_local_gre:-$default_local}"
  if ! validate_cidr_ipv4 "$LOCAL_GRE_IP"; then
    echo "[-] Invalid Local Tunnel IP. Use IP/CIDR format, e.g. $default_local"
    return
  fi

  read -rp "Remote Tunnel IP (peer) [Default: $default_remote]: " input_remote_gre
  REMOTE_GRE_IP="${input_remote_gre:-$default_remote}"
  if ! validate_cidr_ipv4 "$REMOTE_GRE_IP"; then
    echo "[-] Invalid Remote Tunnel IP. Use IP/CIDR format, e.g. $default_remote"
    return
  fi

  read -rp "Tunnel MTU [Default: $DEFAULT_MTU]: " input_mtu
  MTU_VAL="${input_mtu:-$DEFAULT_MTU}"

  echo
  echo "[✓] Summary for $SERVER_ROLE:"
  echo "    Interface:        $TUNNEL_DEV"
  echo "    Local Public IP:  $LOCAL_PUBLIC_IP"
  echo "    Remote Public IP: $REMOTE_PUBLIC_IP"
  echo "    Local Tunnel IP:  $LOCAL_GRE_IP"
  echo "    Remote Tunnel IP: $REMOTE_GRE_IP"
  echo "    MTU:              $MTU_VAL"
  echo

  create_tunnel 1 || echo "[-] Tunnel setup failed."
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

# نمایش وضعیت/محتویات یک تانل (بدون تست پینگ)
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
  echo "    Local Tunnel IP:   ${lgre:-N/A}"
  echo "    Remote Tunnel IP:  ${rgre:-N/A}"

  if ip link show "$dev" >/dev/null 2>&1; then
    local link_state local_addr
    link_state=$(ip -brief link show "$dev" | awk '{print $2}')
    local_addr=$(ip -brief addr show "$dev" | awk '{print $3}')
    echo "    Link State:        ${link_state:-UNKNOWN}"
    echo "    Assigned Address:  ${local_addr:-Not set}"
  else
    echo "    Link State:        DOWN (interface missing) [✗]"
  fi
  echo "--------------------------------------"
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

# منوی یک تانل خاص: عملیات Status / Restart / Delete
tunnel_actions_menu() {
  local cfg=$1
  local dev
  IFS='|' read -r dev _ < <(config_fields "$cfg")
  dev="${dev:-?}"

  while true; do
    clear
    echo "======================================"
    echo "             Tunnel: $dev"
    echo "======================================"
    echo "1) Status / details"
    echo "2) Restart this tunnel"
    echo "3) Delete this tunnel"
    echo "0) Back"
    echo
    read -rp "Select an option [0-3]: " tchoice
    case "$tchoice" in
      1)
        echo
        show_tunnel_status_from_config "$cfg"
        ;;
      2)
        echo
        echo "[*] Restarting tunnel '$dev'..."
        start_tunnel_from_config "$cfg"
        ;;
      3)
        local confirm
        read -rp "Delete tunnel '$dev' and its config? [y/N]: " confirm
        case "$confirm" in
          [Yy]*) delete_tunnel_record "$cfg"; return ;;
          *) echo "[i] Cancelled." ;;
        esac
        ;;
      0 | "") return ;;
      *) echo "[-] Invalid option."; sleep 1; continue ;;
    esac
    echo
    read -rp "Press Enter to continue..." _
  done
}

# منوی انتخاب اینترفیس (تانل‌ها با نام اینترفیس منو می‌شوند)
select_tunnel_menu() {
  while true; do
    clear
    echo "======================================"
    echo "                Tunnels               "
    echo "======================================"

    collect_tunnel_records
    if [ ${#TUNNEL_RECORDS[@]} -eq 0 ]; then
      echo "[i] No tunnels are registered by this script."
      return
    fi

    local i=1 cfg dev
    for cfg in "${TUNNEL_RECORDS[@]}"; do
      IFS='|' read -r dev _ < <(config_fields "$cfg")
      printf '%s) %s\n' "$i" "${dev:-?}"
      i=$((i + 1))
    done
    echo "0) Back"
    echo

    local sel
    read -rp "Select a tunnel [0-$((i - 1))]: " sel
    case "$sel" in
      0 | "") return ;;
    esac
    if ! [[ "$sel" =~ ^[0-9]+$ ]] || ((sel < 1 || sel > ${#TUNNEL_RECORDS[@]})); then
      echo "[-] Invalid selection."
      sleep 1
      continue
    fi

    tunnel_actions_menu "${TUNNEL_RECORDS[$((sel - 1))]}"
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

  # اطمینان از نصب/به‌روزرسانی بنر ورود
  install_motd || true

  if systemctl is-active --quiet gre-tunnel.service; then
    echo "[✓] Service installed & enabled — tunnels will survive reboot."
  else
    echo "[-] Service installed but failed to start. Run: journalctl -xeu gre-tunnel.service"
    return 1
  fi
}

# نصب بنر ورود SSH: خطوط آی‌پی تانل داخل بلوک «System information» تزریق می‌شوند
install_motd() {
  local dir
  dir="$(dirname "$MOTD_FILE")"
  if [ ! -d "$dir" ]; then
    echo "[i] $dir not found; skipping login banner setup."
    return 0
  fi

  # پاک‌سازی بنر نسخه‌های قدیمی
  rm -f "$MOTD_LEGACY" 2>/dev/null || true

  # helper قدیمی (نسخه قبل) دیگر لازم نیست
  rm -f "$MOTD_HELPER" 2>/dev/null || true

  # پشتیبان‌گیری از اسکریپت اصلی landscape (فقط اگر مربوط به خودمان نباشد)
  if [ -e "$MOTD_FILE" ] && ! grep -q 'gre.sh landscape sysinfo' "$MOTD_FILE" 2>/dev/null; then
    if [ ! -e "$MOTD_ORIG" ]; then
      mv -f "$MOTD_FILE" "$MOTD_ORIG" 2>/dev/null || true
    else
      rm -f "$MOTD_FILE" 2>/dev/null || true
    fi
  fi

  # بنر: بلوک «System information» را با همان فرمت‌بند landscape می‌سازیم و
  # آی‌پی تانل‌ها را به‌عنوان هدر اضافه می‌کنیم تا در ستون IPv4 تراز شوند.
  cat > "$MOTD_FILE" <<'PYMOTD'
#!/usr/bin/python3
# gre.sh landscape sysinfo — renders the "System information" block and adds
# GRE tunnel addresses so they appear aligned inside the IPv4 column.
import os
import subprocess
import sys
import time

CONF_DIR = "/etc/gre-tunnel.d"
CACHE = "/var/lib/landscape/landscape-sysinfo.cache"
ORIG = "/etc/update-motd.d/50-landscape-sysinfo.gre-orig"
CACHE_MAX_AGE = 60


def _ip_binary():
    for candidate in ("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"):
        if os.path.exists(candidate):
            return candidate
    return "ip"


IP_BIN = _ip_binary()


def read_conf(path):
    data = {}
    try:
        with open(path, "r", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                data[key.strip()] = val.strip().strip('"').strip("'")
    except OSError:
        return {}
    return data


def gre_addresses():
    result = []
    if not os.path.isdir(CONF_DIR):
        return result
    for name in sorted(os.listdir(CONF_DIR)):
        if not name.endswith(".conf"):
            continue
        conf = read_conf(os.path.join(CONF_DIR, name))
        dev = conf.get("TUNNEL_DEV", "")
        if not dev:
            continue
        try:
            raw = subprocess.check_output(
                [IP_BIN, "-4", "-brief", "addr", "show", dev],
                stderr=subprocess.DEVNULL,
            ).decode("utf-8", "replace")
        except Exception:
            continue
        line = raw.splitlines()[0].strip() if raw.strip() else ""
        parts = line.split()
        if len(parts) >= 3 and "/" in parts[2]:
            result.append((dev, parts[2].split("/")[0]))
    return result


def build_block():
    from landscape.sysinfo.sysinfo import SysInfoPluginRegistry, format_sysinfo
    from landscape.sysinfo.deployment import SysInfoConfiguration

    registry = SysInfoPluginRegistry()
    config = SysInfoConfiguration()
    try:
        config.load([], accept_nonexistent_default_config=True)
    except TypeError:
        config.load([])
    for plugin in config.get_plugins():
        registry.add(plugin)
    registry.run()
    for dev, ip in gre_addresses():
        registry.add_header("IPv4 address for " + dev, ip)
    width = getattr(config, "width", 80) or 80
    return format_sysinfo(
        registry.get_headers(),
        registry.get_notes(),
        registry.get_footnotes(),
        width=width,
        indent="  ",
    )


def original_output():
    if os.path.exists(ORIG):
        try:
            return subprocess.check_output(["/bin/sh", ORIG]).decode("utf-8", "replace")
        except Exception:
            return ""
    return ""


def main():
    try:
        if os.path.isfile(CACHE) and (time.time() - os.path.getmtime(CACHE)) < CACHE_MAX_AGE:
            with open(CACHE, "r", errors="replace") as fh:
                sys.stdout.write(fh.read())
            return
    except OSError:
        pass

    try:
        body = build_block()
    except Exception:
        fallback = original_output()
        if fallback.strip():
            sys.stdout.write(fallback)
        else:
            gre = "\n".join(
                "  IPv4 address for %s: %s" % (d, i) for d, i in gre_addresses()
            )
            if gre:
                sys.stdout.write("\n" + gre + "\n")
        return

    try:
        date_str = subprocess.check_output(["/bin/date"]).decode().strip()
    except Exception:
        date_str = time.strftime("%a %b %d %H:%M:%S %Z %Y")

    text = "\n System information as of %s\n\n%s\n" % (date_str, body)
    try:
        with open(CACHE, "w") as fh:
            fh.write(text)
        os.chmod(CACHE, 0o644)
    except OSError:
        pass
    sys.stdout.write(text)


if __name__ == "__main__":
    main()
PYMOTD
  chmod +x "$MOTD_FILE" 2>/dev/null || true

  echo "[✓] Tunnel IP will appear aligned inside the login 'System information' block."
}

uninstall_service() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now gre-tunnel.service 2>/dev/null || true
    rm -f "$SERVICE_UNIT"
    systemctl daemon-reload
  fi
  rm -f "$INSTALL_BIN"
  rm -f "$MOTD_HELPER" 2>/dev/null || true
  rm -f "$MOTD_LEGACY" 2>/dev/null || true

  # بازگرداندن اسکریپت اصلی landscape
  if grep -q 'gre.sh landscape sysinfo' "$MOTD_FILE" 2>/dev/null; then
    rm -f "$MOTD_FILE"
  fi
  if [ -e "$MOTD_ORIG" ]; then
    mv -f "$MOTD_ORIG" "$MOTD_FILE" 2>/dev/null || true
  fi

  echo "[✓] Service uninstalled, binary and login banner restored."
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
  echo "1) Create new tunnel"
  echo "2) Tunnels (select & manage)"
  echo "3) Remove ALL tunnels & clean"
  echo "0) Exit"
  echo
  read -rp "Select an option [0-3]: " CHOICE
  case "$CHOICE" in
    1) menu_config_tunnel ;;
    2) select_tunnel_menu ;;
    3) remove_tun ;;
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
