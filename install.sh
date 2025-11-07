#!/usr/bin/env bash
# ===========================================================
# YHDS All-In-One Installer (Debian 10..12)
# - SSH/WS, UDP-Custom, Xray (VLESS/Trojan), SlowDNS
# - Interactive menu 1-10
# - Manual account creation
# ===========================================================
set -euo pipefail
IFS=$'\n\t'

# ---------------- Configuration ----------------
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

# Colors
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

# Timezone
ln -fs /usr/share/zoneinfo/${TIMEZONE} /etc/localtime || true
export DEBIAN_FRONTEND=noninteractive

# Update & install base packages
apt update -y >/dev/null 2>&1 || warn "apt update failed"
apt install -y curl wget git jq lsb-release ca-certificates sudo unzip screen cron build-essential golang-go net-tools iptables-persistent socat nginx dropbear stunnel4 >/dev/null 2>&1 || warn "Some packages failed"

# Create YHDS dirs & user DB
mkdir -p "$YHDS_DIR"
touch "$USER_DB"
[[ ! $(head -n1 "$USER_DB") =~ type ]] && echo "type,username,password,expiry,allowed_ips,uuid,created_at" > "$USER_DB"

# Disable IPv6
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true

# ---------------- Domain setup ----------------
echo "1) Use your domain"
echo "2) Random local domain"
read -rp "Choose 1 or 2 [2]: " DOMAIN_CHOICE
DOMAIN_CHOICE=${DOMAIN_CHOICE:-2}
if [[ "$DOMAIN_CHOICE" == "1" ]]; then
  read -rp "Enter domain: " DOMAIN
else
  RAND=$(tr -dc 'a-z0-9' </dev/urandom | head -c6)
  DOMAIN="vpn-${RAND}.local"
fi
echo "$DOMAIN" > /root/domain
info "Domain: $DOMAIN"

# ---------------- Admin user ----------------
if ! id "$ADMIN_USER" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$ADMIN_USER"
  echo -e "${ADMIN_PASS}\n${ADMIN_PASS}" | passwd "$ADMIN_USER" >/dev/null 2>&1
  usermod -aG sudo "$ADMIN_USER"
fi

# ---------------- Dropbear config ----------------
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=109/g' /etc/default/dropbear
grep -q "DROPBEAR_EXTRA_ARGS" /etc/default/dropbear || echo "DROPBEAR_EXTRA_ARGS='-p 143'" >> /etc/default/dropbear
systemctl enable --now dropbear
systemctl enable --now stunnel4
systemctl enable --now nginx

# ---------------- UDP-Custom ----------------
cd /root
UDP_BIN_URL="https://github.com/akunssh/udp-custom/releases/latest/download/udp-custom-linux-amd64"
wget -q --tries=3 --timeout=20 -O /root/udp-custom "$UDP_BIN_URL" && chmod +x /root/udp-custom
mkdir -p /etc/udp-custom && touch /etc/udp-custom/users.conf
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
curl -fsSL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh -o /tmp/xray-install.sh
bash /tmp/xray-install.sh >/dev/null 2>&1
mkdir -p /etc/xray
[[ ! -f /etc/xray/config.json ]] && cat >/etc/xray/config.json <<EOF
{
  "log":{"loglevel":"warning"},
  "inbounds":[{"port":${XRAY_PORT},"protocol":"vless","settings":{"clients":[{"id":"11111111-2222-3333-4444-555555555555","level":0,"email":"default@local"}],"decryption":"none"},"streamSettings":{"network":"ws","wsSettings":{"path":"${XRAY_WS_PATH}"}}}],
  "outbounds":[{"protocol":"freedom"}]
}
EOF
systemctl enable --now xray

# ---------------- SlowDNS ----------------
cd /root
if [ ! -d /root/slowdns ]; then
  git clone https://github.com/purwasasmito/slowdns.git /root/slowdns
  cd /root/slowdns && go build -o slowdns server.go && mv slowdns /usr/local/bin/slowdns
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
fi

# ---------------- Functions ----------------
cat >/etc/yhds/functions.sh <<'EOS'
#!/usr/bin/env bash
USER_DB="/etc/yhds/users.csv"
XRAY_PORT=443
XRAY_WS_PATH="/vless"
DOMAIN=$(cat /root/domain 2>/dev/null || echo "-")
UDP_CUSTOM_PORT=7300
SLOWDNS_UDP_PORT=5300

save_user_record(){ local type="$1" user="$2" pass="$3" exp="$4" ips="$5" uuid="$6"; now=$(date -u +"%Y-%m-%dT%H:%M:%SZ"); echo "${type},${user},${pass},${exp},\"${ips}\",${uuid},${now}" >> "$USER_DB"; }

create_ssh_ws(){
  read -rp "Username: " u
  read -rp "Password: " -s p; echo
  read -rp "Expire in days [7]: " days; days=${days:-7}
  read -rp "Limit IPs comma (optional): " ips
  useradd -m -s /bin/bash "$u"; echo -e "${p}\n${p}" | passwd "$u"
  exp=$(date -d "+${days} days" +"%Y-%m-%d")
  chage -E "$exp" "$u"
  save_user_record "ssh-ws" "$u" "$p" "$exp" "$ips" ""
  echo "SSH/WS $u created. Exp: $exp, IPs: ${ips:-none}"
}

create_udp_custom_user(){
  read -rp "Username: " u
  read -rp "Expire in days [7]: " days; days=${days:-7}
  read -rp "Limit IPs comma (optional): " ips
  exp=$(date -d "+${days} days" +"%Y-%m-%d")
  echo "${u}:${exp}:${ips}" >> /etc/udp-custom/users.conf
  save_user_record "udp" "$u" "" "$exp" "$ips" ""
  systemctl restart udp-custom
  echo "UDP $u added. Exp: $exp, IPs: ${ips:-none}"
}

create_vless_account(){
  read -rp "Note / Account name: " name
  read -rp "Expire in days [7]: " days; days=${days:-7}
  read -rp "Limit IPs comma (optional): " ips
  uuid=$(cat /proc/sys/kernel/random/uuid)
  tmp=$(mktemp)
  jq --arg id "$uuid" --arg em "$name" '.inbounds[0].settings.clients += [{"id": $id,"level":0,"email":$em}]' /etc/xray/config.json > "$tmp" && mv "$tmp" /etc/xray/config.json
  systemctl restart xray
  exp=$(date -d "+${days} days" +"%Y-%m-%d")
  save_user_record "vless" "$name" "" "$exp" "$ips" "$uuid"
  echo "VLESS $name created. UUID: $uuid, Exp: $exp"
}

create_trojan_account(){
  read -rp "Note / Account name: " name
  read -rp "Expire in days [7]: " days; days=${days:-7}
  read -rp "Limit IPs comma (optional): " ips
  passwd_t=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c14)
  tmp=$(mktemp)
  jq --arg pw "$passwd_t" --arg em "$name" '.inbounds |= map(if .protocol=="trojan" then (.settings.clients += [{"password":$pw,"email":$em}]) else . end)' /etc/xray/config.json > "$tmp" && mv "$tmp" /etc/xray/config.json
  systemctl restart xray
  exp=$(date -d "+${days} days" +"%Y-%m-%d")
  save_user_record "trojan" "$name" "$passwd_t" "$exp" "$ips" ""
  echo "Trojan $name created. Pass: $passwd_t, Exp: $exp"
}
EOS

chmod +x /etc/yhds/functions.sh

# ---------------- Menu ----------------
cat >/usr/local/bin/menu <<'EOS'
#!/usr/bin/env bash
source /etc/yhds/functions.sh
while true; do
  clear
  echo "🌐 YHDS MULTI TUNNEL PANEL"
  echo "1) Create SSH/WS"
  echo "2) Create UDP"
  echo "3) Create VLESS"
  echo "4) Create Trojan"
  echo "5) Renew/Delete"
  echo "6) Backup/Restore"
  echo "7) Check Online"
  echo "8) Restart Services"
  echo "9) System Info"
  echo "10) Exit"
  read -rp "Choose: " opt
  case $opt in
    1) create_ssh_ws;;
    2) create_udp_custom_user;;
    3) create_vless_account;;
    4) create_trojan_account;;
    5)
      read -rp "1) Renew 2) Delete: " r
      if [[ "$r"=="1" ]]; then
        read -rp "Username: " u
        read -rp "Extra days: " d
        cur=$(chage -l "$u" | grep "Account expires" | cut -d: -f2- | xargs)
        [[ -z "$cur" || "$cur"=="never" ]] && cur=$(date +"%Y-%m-%d")
        new=$(date -d "$cur + $d days" +"%Y-%m-%d")
        chage -E "$new" "$u"
        echo "User $u renewed to $new"
      else
        read -rp "Username: " u
        userdel -r "$u"
        sed -i "/,${u},/d" "$USER_DB"
        sed -i "/^${u}:/d" /etc/udp-custom/users.conf 2>/dev/null || true
        echo "User $u deleted"
      fi
    ;;
    6)
      echo "1) Backup 2) Restore"
      read -rp "Choose: " br
      [[ "$br"=="1" ]] && tar czf /root/yhds-backup.tar.gz /etc/yhds "$USER_DB" /etc/udp-custom /etc/slowdns /etc/xray && echo "Backup saved"
      [[ "$br"=="2" ]] && tar xzf /root/yhds-backup.tar.gz -C / && echo "Restore done"
    ;;
    7)
      lastlog | grep -v "Never"
      who
    ;;
    8)
      for s in nginx dropbear stunnel4 xray slowdns udp-custom; do systemctl restart "$s"; done
      echo "Services restarted"
    ;;
    9)
      echo "Domain: $DOMAIN"
      echo "IP: $(curl -s ipv4.icanhazip.com)"
      echo "OS: $(lsb_release -d | cut -f2-)"
      echo "Time: $(date)"
      echo "Ports: SSH(22) Dropbear(109,143) Stunnel(443) Xray(${XRAY_PORT}) UDP(${UDP_CUSTOM_PORT}) SlowDNS(${SLOWDNS_UDP_PORT})"
    ;;
    10) exit 0;;
  esac
  read -rp "Press ENTER to continue..."
done
EOS
chmod +x /usr/local/bin/menu

info "Installation complete. Run 'menu' to manage VPS."
