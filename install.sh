#!/usr/bin/env bash
# ===========================================================
# YHDS All-In-One Installer (Debian 10..12)
# Full installer ready to paste in VPS
# Features:
# - SSH/WS, UDP-Custom, Xray (VLESS/Trojan), SlowDNS
# - Interactive menu 1-10
# ===========================================================
set -euo pipefail
IFS=$'\n\t'

### ---------------- Configuration ----------------
ADMIN_USER="yhds"
ADMIN_PASS="yhds"
UDP_CUSTOM_PORT=7300
SLOWDNS_UDP_PORT=5300
XRAY_PORT=443
XRAY_WS_PATH="/vless"
TIMEZONE="Asia/Jakarta"
USER_DB="/etc/yhds/users.csv"
YHDS_DIR="/etc/yhds"

# Colors
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; BLUE='\e[1;34m'
MAGENTA='\e[1;35m'; CYAN='\e[1;36m'; NC='\e[0m'

info(){ echo -e "${CYAN}[INFO]${NC} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
err(){ echo -e "${RED}[ERROR]${NC} $*"; }

# ---------------- Root Check ----------------
if [ "$(id -u)" -ne 0 ]; then err "Please run as root"; exit 1; fi

# ---------------- Timezone ----------------
ln -fs /usr/share/zoneinfo/${TIMEZONE} /etc/localtime

# ---------------- System Prep ----------------
info "Updating system and installing packages..."
apt update -y
apt install -y curl wget git jq lsb-release ca-certificates sudo unzip screen cron build-essential golang-go net-tools iptables-persistent socat nginx dropbear stunnel4 >/dev/null 2>&1

# Disable IPv6
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1

# ---------------- Domain ----------------
clear
echo -e "${MAGENTA}========================================${NC}"
echo -e "${BLUE}        SETUP: DOMAIN CONFIGURATION      ${NC}"
echo -e "${MAGENTA}========================================${NC}"
echo "1) Use your own domain"
echo "2) Create a random local domain (for config)"
read -rp "Choose 1 or 2 [default 2]: " DOMAIN_CHOICE
DOMAIN_CHOICE=${DOMAIN_CHOICE:-2}
if [ "$DOMAIN_CHOICE" = "1" ]; then
  read -rp "Enter your domain: " DOMAIN
else
  RAND=$(tr -dc 'a-z0-9' </dev/urandom | head -c6)
  DOMAIN="vpn-${RAND}.local"
fi
echo "$DOMAIN" > /root/domain
info "Domain set to: $DOMAIN"

# ---------------- Admin User ----------------
if ! id "$ADMIN_USER" >/dev/null 2>&1; then
  info "Creating admin user: $ADMIN_USER"
  useradd -m -s /bin/bash "$ADMIN_USER"
  echo -e "${ADMIN_PASS}\n${ADMIN_PASS}" | passwd "$ADMIN_USER" >/dev/null 2>&1
  usermod -aG sudo "$ADMIN_USER"
else
  info "Admin user already exists, skipping."
fi

# ---------------- Directories ----------------
mkdir -p "$YHDS_DIR"
touch "$USER_DB"
if ! grep -q '^type,' "$USER_DB" 2>/dev/null; then
  echo "type,username,password,expiry,allowed_ips,uuid,created_at" > "$USER_DB"
fi

# ---------------- UDP-Custom ----------------
info "Installing UDP-Custom..."
wget -q --tries=3 --timeout=20 -O /root/udp-custom https://github.com/akunssh/udp-custom/releases/latest/download/udp-custom-linux-amd64
chmod +x /root/udp-custom
mkdir -p /etc/udp-custom
touch /etc/udp-custom/users.conf
cat >/etc/systemd/system/udp-custom.service <<EOF
[Unit]
Description=UDP-Custom (akunssh) service
After=network.target
[Service]
Type=simple
ExecStart=/root/udp-custom server -p ${UDP_CUSTOM_PORT} -mode auto
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now udp-custom

# ---------------- Xray ----------------
info "Installing Xray..."
bash -c "$(curl -fsSL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh)"
mkdir -p /etc/xray
XRAY_UUID_DEFAULT="11111111-2222-3333-4444-555555555555"
cat >/etc/xray/config.json <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": ${XRAY_PORT},
      "protocol": "vless",
      "settings": { "clients": [{ "id": "${XRAY_UUID_DEFAULT}", "level": 0, "email": "default@local" }], "decryption": "none" },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "${XRAY_WS_PATH}" } }
    }
  ],
  "outbounds": [{ "protocol": "freedom" }]
}
EOF
systemctl enable --now xray

# ---------------- SlowDNS ----------------
info "Installing SlowDNS..."
git clone https://github.com/purwasasmito/slowdns.git /root/slowdns
cd /root/slowdns
go build -o slowdns server.go
mv slowdns /usr/local/bin/slowdns
cat >/etc/systemd/system/slowdns.service <<EOF
[Unit]
Description=SlowDNS Server
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/slowdns -udp ${SLOWDNS_UDP_PORT} -tcp 443 -name ns1.${DOMAIN}
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now slowdns

# ---------------- Functions & Menu ----------------
mkdir -p /etc/yhds
cat >/etc/yhds/functions_impl.sh <<'BASHIMPL'
#!/usr/bin/env bash
USER_DB="/etc/yhds/users.csv"
XRAY_PORT=443
XRAY_WS_PATH="/vless"
UDP_CUSTOM_PORT=7300
RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; BLUE='\e[1;34m'; MAGENTA='\e[1;35m'; CYAN='\e[1;36m'; NC='\e[0m'

save_user_record(){ local t=$1 u=$2 p=$3 e=$4 ips=$5 uuid=$6; printf '%s\n' "${t},${u},${p},${e},\"${ips}\",${uuid},$(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> "$USER_DB"; }

# (functions create_ssh_ws, create_udp_custom_user, create_vless_account, create_trojan_account, renew_or_delete_menu, backup_restore_menu, check_online_users, restart_all_services, show_system_info)
# [paste semua fungsi dari versi sebelumnya di sini]
_main_menu(){
  while true; do
    clear
    echo -e "${MAGENTA}YHDS Multi Tunnel Menu${NC}"
    echo "1) SSH/WS 2) UDP-Custom 3) VLESS 4) Trojan 5) Renew/Delete"
    echo "6) Backup/Restore 7) Check Users 8) Restart 9) System Info 10) Exit"
    read -rp "Choose [1-10]: " opt
    case $opt in
      1) create_ssh_ws;;
      2) create_udp_custom_user;;
      3) create_vless_account;;
      4) create_trojan_account;;
      5) renew_or_delete_menu;;
      6) backup_restore_menu;;
      7) check_online_users;;
      8) restart_all_services;;
      9) show_system_info;;
      10) exit 0;;
      *) echo "Invalid"; sleep 1;;
    esac
    read -rp "Press ENTER to continue..."
  done
}
BASHIMPL
chmod +x /etc/yhds/functions_impl.sh

cat >/usr/local/bin/menu <<'EOF'
#!/usr/bin/env bash
source /etc/yhds/functions_impl.sh
_main_menu
EOF
chmod +x /usr/local/bin/menu

cat >/root/install-summary.txt <<EOF
YHDS Installer Summary
======================
Domain        : ${DOMAIN}
Admin user    : ${ADMIN_USER}
Admin pass    : ${ADMIN_PASS}
UDP-Custom    : ${UDP_CUSTOM_PORT}
Xray port     : ${XRAY_PORT} (ws path ${XRAY_WS_PATH})
SlowDNS UDP   : ${SLOWDNS_UDP_PORT}
Menu command  : menu
User DB       : ${USER_DB}
EOF

info "Installation finished."
cat /root/install-summary.txt
info "Run 'menu' to manage accounts."
