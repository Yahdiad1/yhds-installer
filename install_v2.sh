#!/usr/bin/env bash
# ===========================================================
# YHDS Installer v2 - All-in-One (Debian 10..12 / Ubuntu 20+)
# - Installs: nginx, dropbear, stunnel4, xray (VLESS/Trojan), slowdns (best-effort)
# - Installs udp-custom from your repo (raw URL) and configures it
# - Creates interactive menu (/usr/local/bin/menu) with options 1..12
# - Manual account creation for SSH/WS, UDP, VLESS, Trojan
# - Account output uses "Format 1" (simple copy-able block)
# ===========================================================
set -euo pipefail
IFS=$'\n\t'

### ---------------- CONFIG ----------------
ADMIN_USER="yhds"
ADMIN_PASS="yhds"
TIMEZONE="Asia/Jakarta"
YHDS_DIR="/etc/yhds"
USER_DB="${YHDS_DIR}/users.csv"
UDP_PORT=7300
XRAY_PORT=443
XRAY_WS_PATH="/vless"
DEFAULT_DOMAIN="vyntra.cloud"
# raw URL to udp-custom binary in your repo (edit if you host under different name)
UDP_REMOTE_RAW="https://raw.githubusercontent.com/Yahdiad1/yhds-installer/main/udp-custom-linux-amd64"
# ------------------------------------------------

GREEN='\e[1;32m'; YELLOW='\e[1;33m'; RED='\e[1;31m'; CYAN='\e[1;36m'; NC='\e[0m'
info(){ printf "${CYAN}[INFO]${NC} %s\n" "$*"; }
warn(){ printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }
err(){ printf "${RED}[ERROR]${NC} %s\n" "$*"; }

# require root
if [ "$(id -u)" -ne 0 ]; then err "Please run as root"; exit 1; fi

export DEBIAN_FRONTEND=noninteractive
ln -fs /usr/share/zoneinfo/"${TIMEZONE}" /etc/localtime || true

# ---------------- system packages ----------------
info "Updating APT and installing base packages (this may take a while)..."
apt update -y >/dev/null 2>&1 || warn "apt update failed"
apt install -y curl wget git jq lsb-release ca-certificates sudo unzip screen cron build-essential golang-go net-tools iptables-persistent socat python3 python3-pip nginx dropbear stunnel4 >/dev/null 2>&1 || warn "Some packages may have failed to install"

# pip dependency for optional bot
pip3 install requests python-telegram-bot --no-warn-script-location >/dev/null 2>&1 || true

# create dirs & user DB
mkdir -p "${YHDS_DIR}" /etc/udp-custom /etc/xray /etc/yhds/bot
if [ ! -f "${USER_DB}" ]; then
  printf '%s\n' "type,username,password,expiry,allowed_ips,uuid,created_at" > "${USER_DB}"
fi

# ---------------- domain ----------------
read -rp "Use default domain '${DEFAULT_DOMAIN}'? (Y/n): " ddom
ddom=${ddom:-Y}
if [[ "$ddom" =~ ^[Nn] ]]; then
  read -rp "Enter your domain (e.g. vpn.example.com): " DOMAIN
  DOMAIN=${DOMAIN:-$DEFAULT_DOMAIN}
else
  DOMAIN="${DEFAULT_DOMAIN}"
fi
echo "$DOMAIN" > /root/domain
info "Domain set: $DOMAIN"

# ---------------- admin user ----------------
if ! id "${ADMIN_USER}" >/dev/null 2>&1; then
  info "Creating admin user: ${ADMIN_USER}"
  useradd -m -s /bin/bash "${ADMIN_USER}" || true
  echo -e "${ADMIN_PASS}\n${ADMIN_PASS}" | passwd "${ADMIN_USER}" >/dev/null 2>&1 || true
  usermod -aG sudo "${ADMIN_USER}" >/dev/null 2>&1 || true
fi

# ---------------- dropbear basic config ----------------
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear 2>/dev/null || true
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=109/g' /etc/default/dropbear 2>/dev/null || true
if ! grep -q "DROPBEAR_EXTRA_ARGS" /etc/default/dropbear 2>/dev/null; then
  echo "DROPBEAR_EXTRA_ARGS='-p 143'" >> /etc/default/dropbear
fi
systemctl enable --now dropbear || true
systemctl enable --now stunnel4 || true
systemctl enable --now nginx || true

# ---------------- install Xray (official) ----------------
info "Installing Xray (official installer) - best-effort..."
if curl -fsSL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh -o /tmp/xray-install.sh; then
  bash /tmp/xray-install.sh >/dev/null 2>&1 || warn "Xray installer finished with warnings"
fi

# create minimal Xray config if absent
if [ ! -f /etc/xray/config.json ]; then
  cat >/etc/xray/config.json <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": ${XRAY_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "11111111-2222-3333-4444-555555555555", "level": 0, "email": "default@local" }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": { "path": "${XRAY_WS_PATH}" }
      }
    }
  ],
  "outbounds": [{ "protocol": "freedom" }]
}
EOF
fi
systemctl enable --now xray >/dev/null 2>&1 || true

# ---------------- SlowDNS (optional) ----------------
if [ ! -x /usr/local/bin/slowdns ]; then
  if git clone https://github.com/purwasasmito/slowdns.git /root/slowdns >/dev/null 2>&1; then
    cd /root/slowdns || true
    if go build -o slowdns server.go >/dev/null 2>&1; then
      mv slowdns /usr/local/bin/slowdns || true
      cat >/etc/systemd/system/slowdns.service <<SRV
[Unit]
Description=SlowDNS Server
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/slowdns -udp 5300 -tcp 443 -name ns1.${DOMAIN}
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
SRV
      systemctl daemon-reload
      systemctl enable --now slowdns >/dev/null 2>&1 || true
    fi
  fi
fi

# ---------------- UDP-Custom ----------------
UDP_BIN="/usr/local/bin/udp-custom"
info "Downloading udp-custom from your repo: ${UDP_REMOTE_RAW}"
rm -f "${UDP_BIN}" >/dev/null 2>&1 || true
if wget -q -O "${UDP_BIN}" "${UDP_REMOTE_RAW}"; then
  chmod +x "${UDP_BIN}" || true
else
  warn "Failed to download udp-custom from ${UDP_REMOTE_RAW}"
fi

# if binary valid, create config + systemd
if [ -f "${UDP_BIN}" ] && [ -s "${UDP_BIN}" ]; then
  if file "${UDP_BIN}" | grep -q "ELF"; then
    info "udp-custom binary OK (ELF). Creating config + systemd unit..."
    mkdir -p /etc/udp-custom
    cat >/etc/udp-custom/server.json <<JSON
{
  "listen": "0.0.0.0:${UDP_PORT}",
  "mode": "auto",
  "nodelay": true,
  "mtu": 1350,
  "key": "",
  "sniffer": true
}
JSON
    cat >/etc/systemd/system/udp-custom.service <<UNIT
[Unit]
Description=UDP-Custom Service (akunssh)
After=network.target
[Service]
Type=simple
ExecStart=${UDP_BIN} server --config /etc/udp-custom/server.json
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
UNIT

    systemctl daemon-reload
    systemctl enable --now udp-custom || warn "udp-custom service enable/start failed"
    # add iptables NAT redirect 1-65535 -> UDP_PORT (best-effort)
    if ! iptables -t nat -C PREROUTING -p udp --dport 1:65535 -j REDIRECT --to-ports ${UDP_PORT} >/dev/null 2>&1; then
      iptables -t nat -A PREROUTING -p udp --dport 1:65535 -j REDIRECT --to-ports ${UDP_PORT} || warn "iptables redirect failed"
    fi
    iptables-save >/etc/iptables.rules || true
    # persist iptables
    if command -v netfilter-persistent >/dev/null 2>&1; then
      netfilter-persistent save >/dev/null 2>&1 || true
    else
      cat >/etc/network/if-pre-up.d/iptables <<'IPT'
#!/bin/sh
/sbin/iptables-restore < /etc/iptables.rules
exit 0
IPT
      chmod +x /etc/network/if-pre-up.d/iptables
    fi
  else
    warn "Downloaded udp-custom is not ELF; skipping service creation."
    rm -f "${UDP_BIN}" || true
  fi
else
  warn "udp-custom not present or empty; skipping UDP setup."
fi

# ---------------- helper functions ----------------
save_user_record(){
  # type username password expiry allowed_ips uuid
  local t="$1" u="$2" p="$3" e="$4" ips="$5" uuid="$6"
  local now; now=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  printf '%s\n' "${t},${u},${p},${e},\"${ips}\",${uuid},${now}" >> "${USER_DB}"
}

add_ssh_ip_limit(){
  local user="$1" ips="$2"
  [ -z "$ips" ] && return
  IFS=',' read -ra IPARR <<< "$ips"
  local chain="YHDS_${user}_SSH"
  iptables -N "$chain" 2>/dev/null || true
  iptables -F "$chain" 2>/dev/null || true
  for ip in "${IPARR[@]}"; do
    ip=$(echo "$ip" | xargs)
    if [ -n "$ip" ]; then
      iptables -A "$chain" -p tcp -s "$ip" --dport 22 -j ACCEPT
      iptables -A "$chain" -p tcp -s "$ip" --dport 109 -j ACCEPT
      iptables -A "$chain" -p tcp -s "$ip" --dport 143 -j ACCEPT
    fi
  done
  iptables -A "$chain" -p tcp --dport 22 -j DROP
  iptables -A "$chain" -p tcp --dport 109 -j DROP
  iptables -A "$chain" -p tcp --dport 143 -j DROP
  if ! iptables -C INPUT -j "$chain" >/dev/null 2>&1; then
    iptables -I INPUT -j "$chain"
  fi
  warn "iptables chain $chain added. Remove with iptables -D INPUT -j $chain; iptables -F $chain; iptables -X $chain"
}

remove_ssh_ip_limit(){
  local user="$1"; local chain="YHDS_${user}_SSH"
  if iptables -L "$chain" >/dev/null 2>&1; then
    iptables -D INPUT -j "$chain" 2>/dev/null || true
    iptables -F "$chain" 2>/dev/null || true
    iptables -X "$chain" 2>/dev/null || true
  fi
}

# ---------------- create menu backend ----------------
info "Writing menu backend to /etc/yhds/functions_impl.sh ..."
cat >/etc/yhds/functions_impl.sh <<'BACK'
#!/usr/bin/env bash
USER_DB="/etc/yhds/users.csv"
UDP_USERS="/etc/udp-custom/users.conf"
XRAY_CFG="/etc/xray/config.json"
XRAY_PORT=443
XRAY_WS_PATH="/vless"

save_user_record(){ local t="$1" u="$2" p="$3" e="$4" ips="$5" uuid="$6"; now=$(date -u +"%Y-%m-%dT%H:%M:%SZ"); printf '%s\n' "${t},${u},${p},${e},\"${ips}\",${uuid},${now}" >> "${USER_DB}"; }

create_ssh_ws(){
  echo -e "\033[1;36m== Create SSH / WebSocket Account ==\033[0m"
  read -rp "Username: " u
  [ -z "$u" ] && echo "Canceled" && return
  if id "$u" >/dev/null 2>&1; then echo "User exists"; return; fi
  read -rsp "Password: " p; echo
  read -rp "Expire in days [7]: " days; days=${days:-7}
  read -rp "Limit IPs (comma sep, optional): " ips
  useradd -m -s /bin/bash "$u"
  echo "${u}:${p}" | chpasswd || true
  exp=$(date -d "+${days} days" +"%Y-%m-%d")
  chage -E "$exp" "$u" >/dev/null 2>&1 || true
  save_user_record "ssh-ws" "$u" "$p" "$exp" "$ips" ""
  [ -n "$ips" ] && add_ssh_ip_limit "$u" "$ips"
  echo "=== Akun SSH Created ==="
  echo "Username : $u"
  echo "Password : $p"
  echo "Expired  : ${days} hari ($exp)"
  echo "Host     : $(cat /root/domain 2>/dev/null || hostname -I | awk '{print $1}')"
  echo "Port SSH : 22"
}

create_udp_custom_user(){
  echo -e "\033[1;36m== Create UDP-Custom Account ==\033[0m"
  read -rp "Username: " u
  [ -z "$u" ] && echo "Canceled" && return
  if grep -q "^${u}:" "$UDP_USERS" 2>/dev/null; then echo "UDP user exists"; return; fi
  read -rsp "Password (shared secret): " p; echo
  read -rp "Expire in days [7]: " days; days=${days:-7}
  read -rp "Limit IPs (comma sep, optional): " ips
  exp=$(date -d "+${days} days" +"%Y-%m-%d")
  mkdir -p /etc/udp-custom
  echo "${u}:${p}:${exp}" >> "$UDP_USERS"
  systemctl restart udp-custom >/dev/null 2>&1 || true
  save_user_record "udp" "$u" "$p" "$exp" "$ips" ""
  echo "=== Akun UDP-Custom Created ==="
  echo "Username : $u"
  echo "Password : $p"
  echo "Expired  : ${days} hari ($exp)"
  echo "Host     : $(cat /root/domain 2>/dev/null || hostname -I | awk '{print $1}')"
  echo "Port UDP : 1-65535 (redirected to ${UDP_PORT:-7300})"
  echo "Copy     : udp://${u}:${p}@$(cat /root/domain 2>/dev/null || hostname -I | awk '{print $1}')"
}

create_vless_account(){
  echo -e "\033[1;36m== Create VLESS Account ==\033[0m"
  read -rp "Note (email/name): " note
  [ -z "$note" ] && echo "Canceled" && return
  read -rp "Expire in days [7]: " days; days=${days:-7}
  read -rp "Limit IPs (comma sep, optional): " ips
  uuid=$(cat /proc/sys/kernel/random/uuid)
  if [ -f "${XRAY_CFG}" ]; then
    if command -v jq >/dev/null 2>&1; then
      tmp=$(mktemp)
      jq --arg id "$uuid" --arg em "$note" '.inbounds[0].settings.clients += [{"id":$id,"level":0,"email":$em}]' "${XRAY_CFG}" > "$tmp" && mv "$tmp" "${XRAY_CFG}"
    else
      sed -i "/\"clients\": \[/,/\]/ { /]/ i \ \ \ \ { \"id\": \"${uuid}\", \"level\":0, \"email\": \"${note}\" }," "${XRAY_CFG}" 2>/dev/null || true
    fi
    systemctl restart xray >/dev/null 2>&1 || true
    exp=$(date -d "+${days} days" +"%Y-%m-%d")
    save_user_record "vless" "$note" "" "$exp" "$ips" "$uuid"
    echo "=== Akun VLESS Created ==="
    echo "Note     : $note"
    echo "UUID     : $uuid"
    echo "Expired  : ${days} hari ($exp)"
    echo "Host     : $(cat /root/domain 2>/dev/null || hostname -I | awk '{print $1}')"
    echo "Port     : ${XRAY_PORT}"
    echo "WS Path  : ${XRAY_WS_PATH}"
    echo "Config   : vless://${uuid}@$(cat /root/domain 2>/dev/null || hostname -I | awk '{print $1}'):${XRAY_PORT}?path=${XRAY_WS_PATH}"
  else
    echo "Xray config not found."
  fi
}

create_trojan_account(){
  echo -e "\033[1;36m== Create Trojan Account ==\033[0m"
  read -rp "Note (email/name): " note
  [ -z "$note" ] && echo "Canceled" && return
  read -rp "Expire in days [7]: " days; days=${days:-7}
  read -rp "Limit IPs (comma sep, optional): " ips
  passwd_t=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c14)
  if [ -f "${XRAY_CFG}" ]; then
    if grep -q '"protocol": "trojan"' "${XRAY_CFG}" 2>/dev/null; then
      if command -v jq >/dev/null 2>&1; then
        tmp=$(mktemp)
        jq --arg pw "$passwd_t" --arg em "$note" '.inbounds |= map(if .protocol=="trojan" then (.settings.clients += [{"password": $pw, "email": $em}]) else . end)' "${XRAY_CFG}" > "$tmp" && mv "$tmp" "${XRAY_CFG}"
      else
        sed -i "/\"protocol\": \"trojan\"/,/]/ { /]/ i \ \ \ \ { \"password\": \"${passwd_t}\", \"email\": \"${note}\" }," "${XRAY_CFG}" 2>/dev/null || true
      fi
    else
      cat >/etc/xray/trojan-inbound.json <<JSON
{
  "port": 1443,
  "protocol": "trojan",
  "settings": { "clients": [{ "password": "${passwd_t}", "email": "${note}" }] },
  "streamSettings": { "network": "tcp" }
}
JSON
      if command -v jq >/dev/null 2>&1; then
        tmp=$(mktemp)
        jq '.inbounds += ['$(cat /etc/xray/trojan-inbound.json)']' "${XRAY_CFG}" > "$tmp" && mv "$tmp" "${XRAY_CFG}"
        rm -f /etc/xray/trojan-inbound.json
      else
        cat /etc/xray/trojan-inbound.json >> "${XRAY_CFG}" 2>/dev/null || true
      fi
    fi
    systemctl restart xray >/dev/null 2>&1 || true
    exp=$(date -d "+${days} days" +"%Y-%m-%d")
    save_user_record "trojan" "$note" "$passwd_t" "$exp" "$ips" ""
    echo "=== Akun Trojan Created ==="
    echo "Note     : $note"
    echo "Password : $passwd_t"
    echo "Expired  : ${days} hari ($exp)"
    echo "Port     : 1443"
  else
    echo "Xray config not found."
  fi
}

renew_or_delete_menu(){
  echo "1) Renew user expiry"
  echo "2) Delete user"
  read -rp "Choose [1/2]: " r
  if [ "$r" = "1" ]; then
    read -rp "Username to renew: " u
    read -rp "Extra days to add: " days
    if ! id "$u" >/dev/null 2>&1; then echo "User not found"; return; fi
    cur=$(chage -l "$u" | awk -F: '/Account expires/ {print $2}' | xargs)
    [ -z "$cur" ] && cur=$(date +%Y-%m-%d)
    new=$(date -d "$cur + $days days" +%Y-%m-%d)
    chage -E "$new" "$u" >/dev/null 2>&1 || true
    echo "User $u expiry set to $new"
  else
    read -rp "Username to delete: " u
    if id "$u" >/dev/null 2>&1; then
      userdel -r "$u" >/dev/null 2>&1 || true
      remove_ssh_ip_limit "$u" || true
      sed -i "/,${u},/d" "$USER_DB" 2>/dev/null || true
      sed -i "/^${u}:/d" /etc/udp-custom/users.conf 2>/dev/null || true
      sed -i "/^${u}:/d" /etc/slowdns/users.txt 2>/dev/null || true
      echo "User $u deleted"
    else
      echo "User not found."
    fi
  fi
}

backup_restore_menu(){
  echo "1) Backup"
  echo "2) Restore"
  read -rp "Choose [1/2]: " br
  if [ "$br" = "1" ]; then
    tar czf /root/yhds-backup.tar.gz /etc/yhds "$USER_DB" /etc/udp-custom /etc/slowdns /etc/xray 2>/dev/null || true
    echo "Backup saved to /root/yhds-backup.tar.gz"
  else
    if [ -f /root/yhds-backup.tar.gz ]; then
      tar xzf /root/yhds-backup.tar.gz -C / 2>/dev/null || true
      echo "Restore finished."
    else
      echo "No backup file found."
    fi
  fi
}

check_online_users(){ lastlog | grep -v "Never" || true; echo; who || true; }
restart_all_services(){ for s in nginx dropbear stunnel4 xray slowdns udp-custom yhds-bot; do systemctl restart $s >/dev/null 2>&1 || true; done; echo "Services restarted"; }
show_system_info(){ echo "Domain : $(cat /root/domain 2>/dev/null || echo '-')"; echo "IP     : $(curl -sS ipv4.icanhazip.com || echo '-')"; echo "Time   : $(date '+%Y-%m-%d %H:%M:%S')"; echo "Uptime : $(uptime -p)"; echo "Ports  : SSH(22), Dropbear(109,143), Stunnel(443), Xray(${XRAY_PORT}), UDP(${UDP_PORT}), SlowDNS(5300)"; }

install_telegram_bot(){
  read -rp "Bot Token: " BOT_TOKEN
  read -rp "Chat ID: " CHAT_ID
  mkdir -p /etc/yhds/bot
  cat >/etc/yhds/bot/bot.py <<'PY'
#!/usr/bin/env python3
import os,time,requests
TOKEN=os.environ.get("YHDS_BOT_TOKEN","")
CHAT=os.environ.get("YHDS_BOT_CHAT","")
def send(msg):
    if TOKEN and CHAT:
        try:
            requests.post(f"https://api.telegram.org/bot{TOKEN}/sendMessage", data={"chat_id":CHAT,"text":msg}, timeout=10)
        except:
            pass
if __name__ == "__main__":
    send("YHDS Bot installed and running ✅")
    while True:
        time.sleep(3600)
PY
  chmod +x /etc/yhds/bot/bot.py
  cat >/etc/systemd/system/yhds-bot.service <<'SRV'
[Unit]
Description=YHDS Telegram Bot
After=network.target
[Service]
Environment=YHDS_BOT_TOKEN=__TOKEN__
Environment=YHDS_BOT_CHAT=__CHAT__
ExecStart=/usr/bin/python3 /etc/yhds/bot/bot.py
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
SRV
  sed -i "s/__TOKEN__/${BOT_TOKEN}/" /etc/systemd/system/yhds-bot.service
  sed -i "s/__CHAT__/${CHAT_ID}/" /etc/systemd/system/yhds-bot.service
  systemctl daemon-reload
  systemctl enable --now yhds-bot >/dev/null 2>&1 || true
  echo "Bot installed (service started if dependencies ok)."
}

BACK
chmod +x /etc/yhds/functions_impl.sh

# ---------------- create menu launcher ----------------
cat >/usr/local/bin/menu <<'MENU'
#!/usr/bin/env bash
if [ -f /etc/yhds/functions_impl.sh ]; then
  source /etc/yhds/functions_impl.sh
  while true; do
    clear
    echo "===================================="
    echo "      YHDS MULTI TUNNEL PANEL"
    echo "===================================="
    echo "1) Install / Restart UDP-Custom Service"
    echo "2) Create SSH / WebSocket Account"
    echo "3) Create UDP-Custom Account (manual)"
    echo "4) Create VLESS Account (UUID)"
    echo "5) Create Trojan Account"
    echo "6) Renew / Delete Account"
    echo "7) Backup & Restore"
    echo "8) Check Online Users"
    echo "9) Restart All Services"
    echo "10) System Information"
    echo "11) Install Telegram Bot"
    echo "12) Exit"
    read -rp "Select [1-12]: " opt
    case "$opt" in
      1) systemctl restart udp-custom >/dev/null 2>&1 || true; echo "udp-custom restarted"; read -rp "Press Enter...";;
      2) create_ssh_ws; read -rp "Press Enter...";;
      3) create_udp_custom_user; read -rp "Press Enter...";;
      4) create_vless_account; read -rp "Press Enter...";;
      5) create_trojan_account; read -rp "Press Enter...";;
      6) renew_or_delete_menu; read -rp "Press Enter...";;
      7) backup_restore_menu; read -rp "Press Enter...";;
      8) check_online_users; read -rp "Press Enter...";;
      9) restart_all_services; read -rp "Press Enter...";;
      10) show_system_info; read -rp "Press Enter...";;
      11) install_telegram_bot; read -rp "Press Enter...";;
      12) exit 0;;
      *) echo "Invalid"; sleep 1;;
    esac
  done
else
  echo "Menu backend missing: /etc/yhds/functions_impl.sh"
fi
MENU
chmod +x /usr/local/bin/menu

# enable on boot
for s in nginx dropbear stunnel4 xray slowdns udp-custom yhds-bot; do
  systemctl enable "$s" >/dev/null 2>&1 || true
done

# write summary
cat >/root/install-summary.txt <<EOF
YHDS Installer Summary
======================
Domain        : ${DOMAIN}
IP            : $(curl -sS ipv4.icanhazip.com || echo "-")
Admin user    : ${ADMIN_USER}
Admin pass    : ${ADMIN_PASS}
UDP main port : ${UDP_PORT}
Xray port     : ${XRAY_PORT} (ws path ${XRAY_WS_PATH})
Menu command  : menu
User DB       : ${USER_DB}
EOF

info "Installation finished. Summary written to /root/install-summary.txt"
cat /root/install-summary.txt

read -rp "Reboot now to finalize (y/N)? " do_reboot
if [[ "${do_reboot:-N}" =~ ^[Yy]$ ]]; then
  sync
  reboot
fi

# End install_v2.sh
