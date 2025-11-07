#!/usr/bin/env bash
# ===========================================================
# YHDS All-In-One Installer (Debian 10..12)
# - SSH/WS, UDP-Custom (akunssh), Xray (VLESS/Trojan), SlowDNS
# - Telegram Bot (menu 11)
# - Colorful interactive menu (command: menu) with options 1-12
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
# ------------------------------------------------

RED='\e[1;31m'; GREEN='\e[1;32m'; YELLOW='\e[1;33m'; BLUE='\e[1;34m'
MAGENTA='\e[1;35m'; CYAN='\e[1;36m'; NC='\e[0m'

info(){ echo -e "${CYAN}[INFO]${NC} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
err(){ echo -e "${RED}[ERROR]${NC} $*"; }

# Root check
if [ "$(id -u)" -ne 0 ]; then
  err "Please run as root."
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
ln -fs /usr/share/zoneinfo/${TIMEZONE} /etc/localtime || true

# ---------------- Prepare system ----------------
info "Updating apt and installing base packages..."
apt update -y >/dev/null 2>&1 || warn "apt update failed"
apt install -y curl wget git jq lsb-release ca-certificates sudo unzip screen cron build-essential golang-go net-tools iptables-persistent socat python3 python3-pip >/dev/null 2>&1 || warn "Some packages failed to install"
pip3 install python-telegram-bot >/dev/null 2>&1 || warn "Failed to install telegram bot library"

mkdir -p "$YHDS_DIR"
touch "$USER_DB"
if ! grep -q '^type,' "$USER_DB" 2>/dev/null; then
  printf '%s\n' "type,username,password,expiry,allowed_ips,uuid,created_at" > "$USER_DB"
fi

sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true

# ---------------- Domain selection ----------------
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

# ---------------- Admin user ----------------
if ! id "$ADMIN_USER" >/dev/null 2>&1; then
  info "Creating admin user: $ADMIN_USER"
  useradd -m -s /bin/bash "$ADMIN_USER"
  echo -e "${ADMIN_PASS}\n${ADMIN_PASS}" | passwd "$ADMIN_USER" >/dev/null 2>&1
  usermod -aG sudo "$ADMIN_USER"
else
  info "Admin user already exists, skipping."
fi

# ---------------- Base services ----------------
apt install -y nginx dropbear stunnel4 >/dev/null 2>&1 || warn "Base services failed"

sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear 2>/dev/null || true
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=109/g' /etc/default/dropbear 2>/dev/null || true
if ! grep -q "DROPBEAR_EXTRA_ARGS" /etc/default/dropbear 2>/dev/null; then
  echo "DROPBEAR_EXTRA_ARGS='-p 143'" >> /etc/default/dropbear
fi
systemctl enable --now dropbear nginx stunnel4 || warn "Service start failed"

# ---------------- UDP-Custom ----------------
info "Installing UDP-Custom..."
UDP_BIN_URL="https://github.com/akunssh/udp-custom/releases/latest/download/udp-custom-linux-amd64"
wget -q --tries=3 --timeout=20 -O /root/udp-custom "$UDP_BIN_URL" && chmod +x /root/udp-custom
mkdir -p /etc/udp-custom
touch /etc/udp-custom/users.conf
cat >/etc/systemd/system/udp-custom.service <<EOF
[Unit]
Description=UDP-Custom Service
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
systemctl enable --now udp-custom || warn "udp-custom failed"

# ---------------- Xray ----------------
info "Installing Xray..."
curl -fsSL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh -o /tmp/xray-install.sh
bash /tmp/xray-install.sh >/dev/null 2>&1 || warn "Xray install failed"

mkdir -p /etc/xray
XRAY_UUID_DEFAULT="11111111-2222-3333-4444-555555555555"
if [ ! -f /etc/xray/config.json ]; then
cat >/etc/xray/config.json <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "port": ${XRAY_PORT},
    "protocol": "vless",
    "settings": {
      "clients": [{ "id": "${XRAY_UUID_DEFAULT}", "level": 0, "email": "default@local" }],
      "decryption": "none"
    },
    "streamSettings": { "network": "ws", "wsSettings": { "path": "${XRAY_WS_PATH}" } }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
EOF
fi
systemctl enable --now xray || warn "Xray start failed"

# ---------------- SlowDNS ----------------
info "Installing SlowDNS..."
cd /root
if [ ! -d slowdns ]; then
  git clone https://github.com/purwasasmito/slowdns.git slowdns >/dev/null 2>&1
  cd slowdns
  go build -o slowdns server.go >/dev/null 2>&1
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
  systemctl enable --now slowdns || warn "SlowDNS failed"
fi

# ---------------- Helper functions ----------------
save_user_record(){ local type="$1" user="$2" pass="$3" exp="$4" ips="$5" uuid="$6"; now=$(date -u +"%Y-%m-%dT%H:%M:%SZ"); printf '%s\n' "${type},${user},${pass},${exp},\"${ips}\",${uuid},${now}" >> "$USER_DB"; }

add_ssh_ip_limit(){
  local user="$1" ips="$2"
  [ -z "$ips" ] && return
  IFS=',' read -ra IPARR <<< "$ips"
  local chain="YHDS_${user}_SSH"
  iptables -N "$chain" 2>/dev/null || true
  iptables -F "$chain" 2>/dev/null || true
  for ip in "${IPARR[@]}"; do
    ip=$(echo "$ip" | xargs)
    [ -n "$ip" ] && iptables -A "$chain" -p tcp -s "$ip" --dport 22 -j ACCEPT
    [ -n "$ip" ] && iptables -A "$chain" -p tcp -s "$ip" --dport 109 -j ACCEPT
    [ -n "$ip" ] && iptables -A "$chain" -p tcp -s "$ip" --dport 143 -j ACCEPT
  done
  iptables -A "$chain" -p tcp --dport 22 -j DROP
  iptables -A "$chain" -p tcp --dport 109 -j DROP
  iptables -A "$chain" -p tcp --dport 143 -j DROP
  iptables -I INPUT -j "$chain" 2>/dev/null || true
}

remove_ssh_ip_limit(){
  local user="$1"; local chain="YHDS_${user}_SSH"
  iptables -D INPUT -j "$chain" 2>/dev/null || true
  iptables -F "$chain" 2>/dev/null || true
  iptables -X "$chain" 2>/dev/null || true
}

# ---------------- Account functions ----------------
create_ssh_ws(){
  echo -e "${BLUE}== Create SSH / WS Account ==${NC}"
  read -rp "Username: " u
  [ -z "$u" ] && echo "Canceled" && return
  [ $(id -u "$u" 2>/dev/null || echo 0) -ne 0 ] && warn "User exists" && return
  read -rp "Password: " -s p; echo
  read -rp "Expire in days [7]: " days; days=${days:-7}
  read -rp "Limit IPs (comma) [none]: " ips
  useradd -m -s /bin/bash "$u"
  echo -e "${p}\n${p}" | passwd "$u" >/dev/null 2>&1
  chage -E $(date -d "+$days days" +"%Y-%m-%d") "$u"
  save_user_record "ssh-ws" "$u" "$p" "$days" "$ips" ""
  [ -n "$ips" ] && add_ssh_ip_limit "$u" "$ips"
  echo -e "${GREEN}SSH/WS user created: $u${NC}"
}

create_udp_custom_user(){
  echo -e "${BLUE}== Create UDP-Custom Account ==${NC}"
  read -rp "Username: " u
  [ -z "$u" ] && echo "Canceled" && return
  [ -f /etc/udp-custom/users.conf ] && grep -q "^$u:" /etc/udp-custom/users.conf && warn "User exists" && return
  read -rp "Expire in days [7]: " days; days=${days:-7}
  read -rp "Limit IPs (comma) [none]: " ips
  exp=$(date -d "+$days days" +"%Y-%m-%d")
  echo "${u}:${exp}:${ips}" >> /etc/udp-custom/users.conf
  save_user_record "udp" "$u" "" "$exp" "$ips" ""
  systemctl restart udp-custom
  echo -e "${GREEN}UDP user added: $u${NC}"
}

create_vless_account(){
  echo -e "${BLUE}== Create VLESS Account ==${NC}"
  read -rp "Account note: " name
  [ -z "$name" ] && echo "Canceled" && return
  read -rp "Expire in days [7]: " days; days=${days:-7}
  read -rp "Limit IPs [none]: " ips
  uuid=$(cat /proc/sys/kernel/random/uuid)
  tmp=$(mktemp)
  jq --arg id "$uuid" --arg em "$name" '.inbounds[0].settings.clients += [{"id": $id,"level":0,"email":$em}]' /etc/xray/config.json > "$tmp" && mv "$tmp" /etc/xray/config.json
  systemctl restart xray
  save_user_record "vless" "$name" "" "$(date -d "+$days days" +"%Y-%m-%d")" "$ips" "$uuid"
  echo -e "${GREEN}VLESS created: $name${NC} UUID=$uuid"
}

create_trojan_account(){
  echo -e "${BLUE}== Create Trojan Account ==${NC}"
  read -rp "Account note: " name
  [ -z "$name" ] && echo "Canceled" && return
  read -rp "Expire in days [7]: " days; days=${days:-7}
  read -rp "Limit IPs [none]: " ips
  passwd_t=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c14)
  save_user_record "trojan" "$name" "$passwd_t" "$(date -d "+$days days" +"%Y-%m-%d")" "$ips" ""
  echo -e "${GREEN}Trojan created: $name${NC} Password=$passwd_t"
}

renew_or_delete_menu(){
  echo -e "${BLUE}== Renew/Delete User ==${NC}"
  read -rp "1) Renew 2) Delete: " r
  if [ "$r" = "1" ]; then
    read -rp "Username: " u
    read -rp "Extra days: " days
    [ ! "$(id -u "$u" 2>/dev/null)" ] && echo "User not found" && return
    chage -E $(date -d "+$days days" +"%Y-%m-%d") "$u"
    echo "Renewed $u"
  else
    read -rp "Username: " u
    id "$u" >/dev/null 2>&1 && userdel -r "$u" || echo "User not found"
    remove_ssh_ip_limit "$u"
    sed -i "/^$u:/d" /etc/udp-custom/users.conf 2>/dev/null || true
  fi
}

backup_restore_menu(){
  echo -e "${BLUE}== Backup & Restore ==${NC}"
  read -rp "1) Backup 2) Restore: " br
  if [ "$br" = "1" ]; then
    tar czf /root/yhds-backup.tar.gz /etc/yhds "$USER_DB" /etc/udp-custom /etc/slowdns /etc/xray
    echo "Backup done"
  else
    tar xzf /root/yhds-backup.tar.gz -C /
    echo "Restore done"
  fi
}

check_online_users(){
  echo -e "${MAGENTA}--- Recent logins ---${NC}"; lastlog | grep -v "Never"
  echo -e "${MAGENTA}--- Current ---${NC}"; who
}

restart_all_services(){
  for s in nginx dropbear stunnel4 xray slowdns udp-custom yhds-bot; do
    systemctl restart "$s" 2>/dev/null && echo "$s restarted"
  done
}

show_system_info(){
  echo "Domain: $(cat /root/domain)"
  echo "IP: $(curl -sS ipv4.icanhazip.com)"
  echo "Ports: SSH/WS 22,109,143; Xray $XRAY_PORT; UDP $UDP_CUSTOM_PORT; SlowDNS $SLOWDNS_UDP_PORT"
  echo "Time: $(date)"
}

install_telegram_bot(){
  echo -e "${BLUE}== Install Telegram Bot ==${NC}"
  read -rp "Telegram Bot Token: " BOT_TOKEN
  read -rp "Chat ID: " CHAT_ID
  mkdir -p /etc/yhds/bot
  cat >/etc/yhds/bot/bot.py <<EOF
#!/usr/bin/env python3
import telegram,time
bot=telegram.Bot(token="$BOT_TOKEN")
while True:
    try: bot.send_message(chat_id="$CHAT_ID",text="Server running ✅")
    except: pass
    time.sleep(3600)
EOF
  cat >/etc/systemd/system/yhds-bot.service <<EOF
[Unit]
Description=YHDS Telegram Bot
After=network.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 /etc/yhds/bot/bot.py
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now yhds-bot
  echo "Telegram Bot installed and running."
}

# ---------------- Menu ----------------
_main_menu(){
  while true; do
    clear
    echo "1) SSH/WS 2) UDP-Custom 3) VLESS 4) Trojan 5) Renew/Delete"
    echo "6) Backup/Restore 7) Check Online 8) Restart Services 9) System Info"
    echo "11) Install Telegram Bot 12) Exit"
    read -rp "Choose [1-12]: " opt
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
      11) install_telegram_bot;;
      12) exit 0;;
      *) echo "Invalid"; sleep 1;;
    esac
    read -rp "Press ENTER to continue..."
  done
}

# ---------------- Install menu command ----------------
cat >/usr/local/bin/menu <<'EOF'
#!/usr/bin/env bash
source /etc/yhds/functions_impl.sh
_main_menu
EOF
chmod +x /usr/local/bin/menu

info "Installation
