sudo tee /usr/local/bin/menu_full_yhds_v5.sh > /dev/null <<'SCRIPT'
#!/bin/bash
# menu_full_yhds_v5.sh - YHDS VPS FULL MENU v5 (fixed, ready-to-use)
# Includes: Dropbear (2222), OpenSSH(22), Xray (443/8443), UDP-Custom (40000-50000),
# Wildcard toggle, Telegram bot, payload builder, auto-expire, fixer, menu 1-15.
# Place at /usr/local/bin/menu_full_yhds_v5.sh and chmod +x
# Run as root.

set -euo pipefail
IFS=$'\n\t'

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[1;36m'; MAGENTA='\033[1;35m'; BLUE='\033[0;34m'; NC='\033[0m'

# Paths
YHDS_DIR="/etc/yhds"
USERS_CSV="${YHDS_DIR}/users.csv"
META_JSON="${YHDS_DIR}/meta.json"
TG_CONF="${YHDS_DIR}/telegram-bot/config.json"
TG_BOT_PY="${YHDS_DIR}/telegram-bot/bot.py"

XRAY_CONF1="/usr/local/etc/xray/config.json"
XRAY_CONF2="/etc/xray/config.json"
XRAY_BIN="/usr/local/bin/xray"

CERT_DIR="/etc/ssl/yhds"
CERT_PEM="${CERT_DIR}/yhds-ip.crt"
KEY_PEM="${CERT_DIR}/yhds-ip.key"

UDP_BIN="/usr/local/bin/udp-custom"
UDP_CONF="/etc/udp-custom/server.json"
UDP_SERVICE="/etc/systemd/system/udp-custom.service"

DROPBEAR_SERVICE="/etc/systemd/system/dropbear.service"
MENU_PATH="/usr/local/bin/menu_full_yhds_v5.sh"
SCREEN_NAME="yhds-menu"

# Defaults
WILDCARD_MODE="off"
WILDCARD_DOMAIN=""

# Helpers
log(){ echo -e "${GREEN}[INFO]${NC} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
err(){ echo -e "${RED}[ERROR]${NC} $*"; }

if [[ $EUID -ne 0 ]]; then
  err "Jalankan sebagai root!"
  exit 1
fi

server_ip(){ curl -s ipv4.icanhazip.com || hostname -I | awk '{print $1}'; }

load_meta(){
  if [[ -f "${META_JSON}" ]]; then
    WILDCARD_MODE=$(jq -r '.wildcard_mode // "off"' "${META_JSON}" 2>/dev/null || echo "off")
    WILDCARD_DOMAIN=$(jq -r '.wildcard_domain // ""' "${META_JSON}" 2>/dev/null || echo "")
  fi
}
save_meta(){
  mkdir -p "$(dirname "${META_JSON}")"
  jq -n --arg w "${WILDCARD_MODE}" --arg d "${WILDCARD_DOMAIN}" '{wildcard_mode:$w, wildcard_domain:$d}' > "${META_JSON}"
}

# Ensure deps & dirs
ensure_deps_and_dirs(){
  log "Memastikan dependensi dan direktori..."
  apt update -y >/dev/null 2>&1 || true
  apt install -y wget curl jq unzip bzip2 screen git lsof netcat-openbsd openssl util-linux grep sed awk iproute2 iptables ufw ca-certificates python3 python3-pip qrencode figlet lolcat uuid-runtime || true
  python3 -m pip install --upgrade pip >/dev/null 2>&1 || true
  python3 -m pip install pyTelegramBotAPI requests >/dev/null 2>&1 || true

  mkdir -p "${YHDS_DIR}" "${CERT_DIR}" "$(dirname "${XRAY_CONF1}")" "$(dirname "${XRAY_CONF2}")" /var/log/xray /etc/udp-custom
  touch "${USERS_CSV}" || true
  chmod 600 "${USERS_CSV}" || true
  load_meta
}

# Create self-signed cert for IP (and optional domain)
ensure_cert_for_ip_and_domain(){
  IP="$1"; DOMAIN="${2:-}"
  if [[ -f "${CERT_PEM}" && -f "${KEY_PEM}" ]]; then
    # quick check if existing cert contains IP or domain
    if openssl x509 -in "${CERT_PEM}" -noout -text 2>/dev/null | grep -q "${IP}"; then
      if [[ -z "${DOMAIN}" ]] || openssl x509 -in "${CERT_PEM}" -noout -text 2>/dev/null | grep -q "${DOMAIN}"; then
        log "Certificate exists and contains required SAN(s)."
        return 0
      fi
    fi
  fi

  log "Membuat self-signed cert untuk ${IP} ${DOMAIN:+(domain ${DOMAIN})}..."
  CN="${DOMAIN:-${IP}}"
  cat > "${CERT_DIR}/openssl-ip.cnf" <<EOF
[req]
prompt = no
distinguished_name = dn
req_extensions = v3_req
[dn]
CN = ${CN}
[v3_req]
subjectAltName = @alt_names
[alt_names]
IP.1 = ${IP}
EOF
  if [[ -n "${DOMAIN}" ]]; then
    echo "DNS.1 = ${DOMAIN}" >> "${CERT_DIR}/openssl-ip.cnf"
  fi
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout "${KEY_PEM}" -out "${CERT_PEM}" -config "${CERT_DIR}/openssl-ip.cnf" >/dev/null 2>&1 || true
  chmod 600 "${KEY_PEM}" || true
}

# Install Xray (if missing)
install_xray(){
  if command -v xray >/dev/null 2>&1; then
    XRAY_BIN="$(command -v xray)"
    log "Xray binary found at ${XRAY_BIN}"
    return 0
  fi
  log "Menginstall Xray..."
  TMP=$(mktemp -d); cd "${TMP}" || return 1
  URL=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.assets[]?.browser_download_url' 2>/dev/null | grep -E 'linux-64|xray-linux-64' | head -n1 || true)
  [[ -z "$URL" ]] && URL="https://github.com/XTLS/Xray-core/releases/latest/download/xray-linux-64.zip"
  wget -q --show-progress "$URL" -O xray.zip || { warn "Download xray gagal"; cd -; rm -rf "${TMP}"; return 1; }
  unzip -o xray.zip >/dev/null 2>&1 || true
  if [[ -f xray ]]; then
    mv -f xray /usr/local/bin/xray
    chmod +x /usr/local/bin/xray
    XRAY_BIN="/usr/local/bin/xray"
  else
    warn "Binary xray tidak ditemukan di zip."
  fi
  # systemd unit
  cat > /etc/systemd/system/xray.service <<'SVC'
[Unit]
Description=Xray Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
LimitNOFILE=65536
User=root
Group=root

[Install]
WantedBy=multi-user.target
SVC
  systemctl daemon-reload || true
  systemctl enable --now xray >/dev/null 2>&1 || true
  cd - >/dev/null 2>&1
  rm -rf "${TMP}" || true
}

# Build clients JSON from users.csv
clients_json_from_csv(){
  if [[ -f "${USERS_CSV}" ]]; then
    awk -F, 'NF>=2{gsub(/"/,"\\\"",$2); printf "{\"password\":\""$2"\",\"email\":\""$1"\"}\n"}' "${USERS_CSV}" | jq -s '.' 2>/dev/null || echo "[]"
  else
    echo "[]"
  fi
}

# Write Xray config (Trojan WS/gRPC)
write_xray_config(){
  IP="$1"
  load_meta
  CLIENTS_JSON="$(clients_json_from_csv)"
  if [[ -z "${CLIENTS_JSON}" ]]; then CLIENTS_JSON="[]"; fi

  if [[ "${WILDCARD_MODE}" == "on" ]]; then
    WS_PATH="/" 
    HOST_HEADER="${WILDCARD_DOMAIN:-${IP}}"
  else
    WS_PATH="/trojan-ws"
    HOST_HEADER="${IP}"
  fi

  mkdir -p "$(dirname "${XRAY_CONF1}")" "$(dirname "${XRAY_CONF2}")"
  cat > "${XRAY_CONF1}" <<JSON
{
  "log": { "access": "/var/log/xray/access.log", "error": "/var/log/xray/error.log", "loglevel": "warning" },
  "inbounds": [
    {
      "port": 443,
      "protocol": "trojan",
      "settings": { "clients": ${CLIENTS_JSON} },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            { "certificateFile": "${CERT_PEM}", "keyFile": "${KEY_PEM}" }
          ]
        },
        "wsSettings": { "path": "${WS_PATH}", "headers": { "Host": "${HOST_HEADER}" } }
      }
    },
    {
      "port": 8443,
      "protocol": "trojan",
      "settings": { "clients": ${CLIENTS_JSON} },
      "streamSettings": {
        "network": "grpc",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            { "certificateFile": "${CERT_PEM}", "keyFile": "${KEY_PEM}" }
          ]
        },
        "grpcSettings": { "serviceName": "trojan-grpc" }
      }
    }
  ],
  "outbounds": [ { "protocol": "freedom", "settings": {} } ]
}
JSON

  cp -f "${XRAY_CONF1}" "${XRAY_CONF2}" 2>/dev/null || true
  chmod 644 "${XRAY_CONF1}" "${XRAY_CONF2}" 2>/dev/null || true
  log "Xray config written. Wildcard:${WILDCARD_MODE} ${WILDCARD_DOMAIN:+domain:${WILDCARD_DOMAIN}}"
}

# Ensure xray log & drop-in
ensure_xray_runable(){
  mkdir -p /var/log/xray
  touch /var/log/xray/access.log /var/log/xray/error.log
  chown -R root:root /var/log/xray 2>/dev/null || true
  chmod 644 /var/log/xray/*.log 2>/dev/null || true

  mkdir -p /etc/systemd/system/xray.service.d
  cat > /etc/systemd/system/xray.service.d/10-run-as-root.conf <<'SVC'
[Service]
User=root
Group=root
SVC

  systemctl daemon-reload || true
  systemctl enable xray >/dev/null 2>&1 || true
}

# Install UDP-Custom
install_udp_custom(){
  if [[ -f "${UDP_BIN}" ]]; then
    log "udp-custom binary exists."
    return 0
  fi
  log "Menginstall UDP-Custom binary..."
  wget -q -O "${UDP_BIN}" "https://raw.githubusercontent.com/noobconner21/UDP-Custom-Script/main/udp-custom-linux-amd64" || true
  if [[ -f "${UDP_BIN}" ]]; then
    chmod +x "${UDP_BIN}" || true
    cat > "${UDP_CONF}" <<EOF
{
  "port_start": 40000,
  "port_end": 50000,
  "mode": "auto"
}
EOF
    cat > "${UDP_SERVICE}" <<EOF
[Unit]
Description=UDP-Custom Service (YHDS)
After=network.target

[Service]
Type=simple
ExecStart=${UDP_BIN} server --config ${UDP_CONF}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload || true
    systemctl enable --now udp-custom >/dev/null 2>&1 || true
    log "udp-custom installed and started (if binary valid)."
  else
    warn "Gagal download udp-custom. Taruh binary manual di ${UDP_BIN} (chmod +x)."
  fi
}

# Create Dropbear systemd unit (use safe fixed port 2222)
install_dropbear_unit(){
  # create valid systemd unit without shell variables
  cat > "${DROPBEAR_SERVICE}" <<'SVC'
[Unit]
Description=Dropbear SSH
After=network.target

[Service]
ExecStart=/usr/sbin/dropbear -E -F -p 2222
Restart=on-failure
LimitNOFILE=65536
User=root
Group=root

[Install]
WantedBy=multi-user.target
SVC
  systemctl daemon-reload || true
  systemctl enable --now dropbear >/dev/null 2>&1 || true
  systemctl restart dropbear >/dev/null 2>&1 || true
  log "Dropbear unit installed/updated (port 2222)."
}

# Open firewall
open_firewall(){
  log "Opening firewall ports..."
  if command -v ufw >/dev/null 2>&1; then
    ufw allow 22/tcp || true
    ufw allow 2222/tcp || true
    ufw allow 443/tcp || true
    ufw allow 8443/tcp || true
    ufw allow 40000:50000/udp || true
    ufw reload || true
  fi
  # iptables fallback
  iptables -C INPUT -p tcp --dport 2222 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 2222 -j ACCEPT
  iptables -C INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 443 -j ACCEPT
  iptables -C INPUT -p tcp --dport 8443 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 8443 -j ACCEPT
  iptables -C INPUT -p udp --dport 40000:50000 -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport 40000:50000 -j ACCEPT
}

# Payload builder & save (respects wildcard)
build_payloads_and_save(){
  USER="$1"; PASS="$2"; IP="$3"; EXPI="$4"
  WS_PORT=443; GRPC_PORT=8443
  load_meta
  if [[ "${WILDCARD_MODE}" == "on" ]]; then
    PATH_WS="/"
    HOST_FOR_PAYLOAD="${WILDCARD_DOMAIN:-${IP}}"
    SNI_PARAM="${WILDCARD_DOMAIN:-}"
  else
    PATH_WS="/trojan-ws"
    HOST_FOR_PAYLOAD="${IP}"
    SNI_PARAM=""
  fi

  if command -v uuidgen >/dev/null 2>&1; then VMESS_UUID=$(uuidgen); else VMESS_UUID=$(cat /proc/sys/kernel/random/uuid); fi
  VMESS_JSON=$(cat <<J
{
  "v":"2",
  "ps":"YHDS-${USER}",
  "add":"${HOST_FOR_PAYLOAD}",
  "port":"${WS_PORT}",
  "id":"${VMESS_UUID}",
  "aid":"0",
  "net":"ws",
  "type":"none",
  "host":"${HOST_FOR_PAYLOAD}",
  "path":"${PATH_WS}",
  "tls":"tls"
}
J
)
  VMESS_BASE=$(echo -n "${VMESS_JSON}" | base64 | tr -d '\n')
  VMESS_LINK="vmess://${VMESS_BASE}"
  VLESS_LINK="vless://${VMESS_UUID}@${HOST_FOR_PAYLOAD}:${WS_PORT}?type=ws&security=tls&path=${PATH_WS}#YHDS-${USER}"

  if [[ -n "${SNI_PARAM}" ]]; then
    TROJAN_WS="trojan://${PASS}@${HOST_FOR_PAYLOAD}:${WS_PORT}?path=%2F${PATH_WS#"/"}&security=tls&host=${HOST_FOR_PAYLOAD}&sni=${SNI_PARAM}#${USER}"
    TROJAN_GRPC="trojan://${PASS}@${HOST_FOR_PAYLOAD}:${GRPC_PORT}?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc&sni=${SNI_PARAM}#${USER}"
  else
    TROJAN_WS="trojan://${PASS}@${HOST_FOR_PAYLOAD}:${WS_PORT}?path=%2F${PATH_WS#"/"}&security=tls#${USER}"
    TROJAN_GRPC="trojan://${PASS}@${HOST_FOR_PAYLOAD}:${GRPC_PORT}?mode=gun&security=tls&type=grpc&serviceName=trojan-grpc#${USER}"
  fi

  HTTP80="${HOST_FOR_PAYLOAD}:80@${USER}:${PASS}"
  HTTP443="${HOST_FOR_PAYLOAD}:443@${USER}:${PASS}"
  UDP_RANGE="${HOST_FOR_PAYLOAD}:40000-50000@${USER}:${PASS}"

  OUTF="/tmp/last_yhds_payload_${USER}.txt"
  cat > "${OUTF}" <<PAY
===============================
✅ Akun dibuat: ${USER}
Password/UUID: ${PASS}
Expired: ${EXPI}
Host/HostForPayload: ${HOST_FOR_PAYLOAD}
Wildcard mode: ${WILDCARD_MODE} ${WILDCARD_DOMAIN:+(domain:${WILDCARD_DOMAIN})}
===============================

--- SSH / OPENSSH ---
Host: ${IP}
Port: 22
User: ${USER}
Pass: ${PASS}

--- DROPBEAR ---
Host: ${IP}
Port: 2222
User: ${USER}
Pass: ${PASS}

--- HTTP Custom ---
80 : ${HTTP80}
443: ${HTTP443}
UDP : ${UDP_RANGE}

--- WebSocket TLS (WSS) ---
Port: ${WS_PORT}
Payload:
GET / HTTP/1.1[crlf]Host: ${HOST_FOR_PAYLOAD}[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf]User-Agent: [ua][crlf][crlf]

--- VMESS ---
${VMESS_LINK}

--- VLESS ---
${VLESS_LINK}

--- TROJAN WS ---
${TROJAN_WS}

--- TROJAN gRPC ---
${TROJAN_GRPC}

===============================
(Payload disimpan: ${OUTF})
PAY

  chmod 644 "${OUTF}"
  if command -v qrencode >/dev/null 2>&1; then
    echo -n "${VMESS_LINK}" | qrencode -o "/root/vmess-${USER}.png" -s 8 -m 2 >/dev/null 2>&1 || true
    echo -n "${TROJAN_WS}" | qrencode -o "/root/trojan-ws-${USER}.png" -s 8 -m 2 >/dev/null 2>&1 || true
  fi

  # Telegram push if configured
  if [[ -f "${TG_CONF}" ]]; then
    BOT_TOKEN=$(jq -r .token "${TG_CONF}" 2>/dev/null || echo "")
    CHAT_ID=$(jq -r .chat_id "${TG_CONF}" 2>/dev/null || echo "")
    if [[ -n "${BOT_TOKEN}" && -n "${CHAT_ID}" ]]; then
      MSG_HTML="<b>✅ TRIAL TROJAN PREMIUM</b>%0A<pre>Username: ${USER}%0APassword: ${PASS}%0AExpired: ${EXPI}%0AHost: ${HOST_FOR_PAYLOAD}</pre>%0A%0A<pre>${TROJAN_WS}</pre>%0A%0A<pre>${TROJAN_GRPC}</pre>"
      curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" -d chat_id="${CHAT_ID}" -d parse_mode="HTML" --data-urlencode "text=${MSG_HTML}" >/dev/null 2>&1 || true
      [[ -f "/root/trojan-ws-${USER}.png" ]] && curl -s -F chat_id="${CHAT_ID}" -F photo="@/root/trojan-ws-${USER}.png" "https://api.telegram.org/bot${BOT_TOKEN}/sendPhoto" >/dev/null 2>&1 || true
    fi
  fi

  echo "${OUTF}"
}

# Create user interactive
create_user_interactive(){
  read -p "Masukkan username: " USER
  [[ -z "${USER}" ]] && { echo "Batal: username kosong"; return 1; }
  read -p "Masukkan password/UUID (enter utk auto): " PASS
  if [[ -z "${PASS}" ]]; then
    if command -v uuidgen >/dev/null 2>&1; then PASS=$(uuidgen); else PASS=$(cat /proc/sys/kernel/random/uuid); fi
  fi
  read -p "Expired (contoh: 60m atau 7) [default 60m]: " DURATION
  DURATION="${DURATION:-60m}"
  if [[ "${DURATION}" == *m ]]; then
    MIN=$(echo "${DURATION}" | sed 's/m$//'); EXPI=$(date -d "+${MIN} minutes" --iso-8601=seconds); SLEEP=$((MIN*60))
  else
    DAYS="${DURATION}"; EXPI=$(date -d "+${DAYS} days" --iso-8601=seconds); SLEEP=$((DAYS*24*3600))
  fi
  mkdir -p "${YHDS_DIR}"
  echo "${USER},${PASS},${EXPI}" >> "${USERS_CSV}"
  chmod 600 "${USERS_CSV}" || true
  IP=$(server_ip)
  write_xray_config "${IP}"
  systemctl restart xray >/dev/null 2>&1 || true
  OUTF=$(build_payloads_and_save "${USER}" "${PASS}" "${IP}" "${EXPI}")
  echo -e "${GREEN}Akun dibuat. Payload: ${OUTF}${NC}"
  ( sleep "${SLEEP}"; sed -i "/^${USER},/d" "${USERS_CSV}" 2>/dev/null || true; write_xray_config "${IP}"; systemctl restart xray >/dev/null 2>&1 || true; echo "$(date -Iseconds) - Expired ${USER}" >> /var/log/yhds-expire.log ) & disown
}

# Noninteractive create (bot)
create_noninteractive(){
  USER="$1"; PASS="$2"; DURATION="${3:-60m}"
  if [[ -z "${USER}" || -z "${PASS}" ]]; then echo "Missing args"; return 1; fi
  if [[ "${DURATION}" == *m ]]; then MIN=$(echo "${DURATION}" | sed 's/m$//'); EXPI=$(date -d "+${MIN} minutes" --iso-8601=seconds); SLEEP=$((MIN*60)); else DAYS="${DURATION}"; EXPI=$(date -d "+${DAYS} days" --iso-8601=seconds); SLEEP=$((DAYS*24*3600)); fi
  mkdir -p "${YHDS_DIR}"
  echo "${USER},${PASS},${EXPI}" >> "${USERS_CSV}"
  IP=$(server_ip); write_xray_config "${IP}"; systemctl restart xray >/dev/null 2>&1 || true
  build_payloads_and_save "${USER}" "${PASS}" "${IP}" "${EXPI}"
  ( sleep "${SLEEP}"; sed -i "/^${USER},/d" "${USERS_CSV}" 2>/dev/null || true; write_xray_config "${IP}"; systemctl restart xray >/dev/null 2>&1 || true ) & disown
  echo "Created ${USER}"
}

# Telegram bot install
install_telegram_bot(){
  read -p "Masukkan BOT_TOKEN: " BOT
  read -p "Masukkan ADMIN_CHAT_ID: " CID
  mkdir -p "$(dirname "${TG_CONF}")"
  jq -n --arg token "${BOT}" --arg chat_id "${CID}" '{token:$token,chat_id:$chat_id}' > "${TG_CONF}"
  mkdir -p "$(dirname "${TG_BOT_PY}")"
  cat > "${TG_BOT_PY}" <<'PY'
#!/usr/bin/env python3
import telebot, subprocess, json, shlex
conf="/etc/yhds/telegram-bot/config.json"
with open(conf) as f: cfg=json.load(f)
BOT=cfg.get("token"); ADMIN=cfg.get("chat_id")
bot=telebot.TeleBot(BOT)
@bot.message_handler(commands=['start','help'])
def h(m): bot.reply_to(m, "YHDS Bot: /status /menu /create <user> <pass> <days>")
@bot.message_handler(commands=['status'])
def status(m):
    out=subprocess.getoutput("ss -tulpen | head -n 120")
    bot.reply_to(m, "<pre>"+out+"</pre>")
@bot.message_handler(commands=['menu'])
def menu_cmd(m):
    bot.reply_to(m, "Use /create <user> <pass> <days>")
@bot.message_handler(commands=['create'])
def create(m):
    parts=m.text.split()
    if len(parts)<4:
        bot.reply_to(m, "Usage: /create <user> <pass> <days>")
        return
    user, pwd, days = parts[1], parts[2], parts[3]
    out=subprocess.getoutput(f"/usr/local/bin/menu_full_yhds_v5.sh --create-noninteractive {user} {pwd} {days}")
    bot.reply_to(m, "<pre>"+out+"</pre>")
bot.infinity_polling()
PY
  chmod +x "${TG_BOT_PY}" || true
  cat >/etc/systemd/system/yhds-telegram-bot.service <<'SVC'
[Unit]
Description=YHDS Telegram Bot
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /etc/yhds/telegram-bot/bot.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SVC
  systemctl daemon-reload || true
  systemctl enable --now yhds-telegram-bot >/dev/null 2>&1 || true
  log "Telegram bot installed and started (if token valid)."
}

# Banner & dashboard
print_banner(){
  if command -v figlet >/dev/null 2>&1 && command -v lolcat >/dev/null 2>&1; then
    figlet -f slant "YHDS VPS" | lolcat -a
  else
    echo -e "${MAGENTA}"
    echo "╔════════════════════════════════════════════════╗"
    echo "║               YHDS VPS PREMIUM                 ║"
    echo "╚════════════════════════════════════════════════╝"
    echo -e "${NC}"
  fi
}

system_dashboard(){
  clear
  print_banner
  HOSTNAME=$(hostname)
  OS=$(lsb_release -d 2>/dev/null | cut -f2 || echo "$(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '\"')")
  KERNEL=$(uname -r)
  IP=$(server_ip)
  ISP=$(curl -s ipinfo.io/org 2>/dev/null | sed 's/^[0-9]* //' || echo "N/A")
  CITY=$(curl -s ipapi.co/city 2>/dev/null || echo "N/A")
  UPTIME=$(uptime -p)
  LOAD=$(uptime | awk -F'load average:' '{print $2}')
  RAM=$(free -h | awk '/Mem:/ {print $3 "/" $2}')
  DISK=$(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')
  load_meta
  echo -e "${CYAN}╔════════════════════════════════════════════════╗${NC}"
  echo -e "${MAGENTA}║               MENU YHDS VPS PREMIUM            ║${NC}"
  echo -e "${CYAN}╠════════════════════════════════════════════════╣${NC}"
  echo -e "${YELLOW} Hostname :${NC} $HOSTNAME"
  echo -e "${YELLOW} OS       :${NC} $OS"
  echo -e "${YELLOW} Kernel   :${NC} $KERNEL"
  echo -e "${YELLOW} IP       :${NC} $IP"
  echo -e "${YELLOW} ISP      :${NC} $ISP"
  echo -e "${YELLOW} Lokasi   :${NC} $CITY"
  echo -e "${YELLOW} Uptime   :${NC} $UPTIME"
  echo -e "${YELLOW} Load Avg :${NC} $LOAD"
  echo -e "${YELLOW} RAM      :${NC} $RAM"
  echo -e "${YELLOW} Disk     :${NC} $DISK"
  echo -e "${YELLOW} Wildcard :${NC} ${WILDCARD_MODE} ${WILDCARD_DOMAIN:+(domain:${WILDCARD_DOMAIN})}"
  echo -e "${CYAN}╚════════════════════════════════════════════════╝${NC}"
  echo ""
}

# Wildcard toggle
toggle_wildcard_mode(){
  load_meta
  if [[ "${WILDCARD_MODE}" == "on" ]]; then
    WILDCARD_MODE="off"; WILDCARD_DOMAIN=""; save_meta; echo "Wildcard mode dimatikan."
  else
    read -p "Masukkan wildcard domain (contoh: *.example.com) : " D
    WILDCARD_DOMAIN="${D:-}"; WILDCARD_MODE="on"; save_meta
    IP=$(server_ip)
    ensure_cert_for_ip_and_domain "${IP}" "${WILDCARD_DOMAIN}"
    write_xray_config "${IP}"
    systemctl restart xray >/dev/null 2>&1 || true
    echo "Wildcard mode diaktifkan. Domain:${WILDCARD_DOMAIN:-(none)}"
  fi
}

recreate_cert_and_reload(){
  read -p "Masukkan wildcard domain (kosong to keep current): " D
  if [[ -n "${D}" ]]; then WILDCARD_DOMAIN="${D}"; fi
  save_meta
  IP=$(server_ip)
  ensure_cert_for_ip_and_domain "${IP}" "${WILDCARD_DOMAIN}"
  write_xray_config "${IP}"
  systemctl restart xray >/dev/null 2>&1 || true
  echo "Cert dibuat/diupdate dan xray direstart."
}

# Fixer (regen cert, ensure services)
fixer_all(){
  echo -e "${YELLOW}Menjalankan fixer: regen cert, install/enable dropbear, xray, udp-custom, open firewall...${NC}"
  ensure_deps_and_dirs
  IP=$(server_ip)
  ensure_cert_for_ip_and_domain "${IP}" "${WILDCARD_DOMAIN}"
  install_xray || true
  ensure_xray_runable
  write_xray_config "${IP}"
  install_udp_custom || true
  install_dropbear_unit || true
  open_firewall
  systemctl restart xray >/dev/null 2>&1 || true
  systemctl restart udp-custom >/dev/null 2>&1 || true
  systemctl restart dropbear >/dev/null 2>&1 || true
  echo -e "${GREEN}Fixer selesai — cek: systemctl status xray dropbear udp-custom${NC}"
}

# Main menu loop
main_menu(){
  ensure_deps_and_dirs
  IP=$(server_ip)
  ensure_cert_for_ip_and_domain "${IP}" "${WILDCARD_DOMAIN}"
  install_xray || true
  ensure_xray_runable
  write_xray_config "${IP}"
  install_udp_custom || true
  install_dropbear_unit || true
  open_firewall
  systemctl restart xray >/dev/null 2>&1 || true
  systemctl restart udp-custom >/dev/null 2>&1 || true
  systemctl restart dropbear >/dev/null 2>&1 || true

  (crontab -l 2>/dev/null | grep -v -F "${MENU_PATH}" || true; echo "@reboot screen -dmS ${SCREEN_NAME} ${MENU_PATH}") | crontab -

  while true; do
    system_dashboard
    echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN} 1) Create SSH Account"
    echo -e " 2) Create UDP-Custom Account"
    echo -e " 3) Create WS Account"
    echo -e " 4) Create Trojan Account"
    echo -e " 5) Create V2Ray Account (placeholder)"
    echo -e " 6) List Users"
    echo -e " 7) Remove User"
    echo -e " 8) Restart UDP-Custom Service"
    echo -e " 9) Check UDP-Custom Status"
    echo -e "10) Check Logs (xray & udp-custom)"
    echo -e "11) Auto Update Script"
    echo -e "12) Install / Restart Telegram Bot"
    echo -e "13) Toggle Wildcard Mode (on/off)"
    echo -e "14) Set / Recreate Wildcard Cert & Reload"
    echo -e "15) Run Fixer (regen cert, restart services)"
    echo -e "16) Exit"
    echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"
    read -p "Pilih menu [1-16]: " MENU
    case "${MENU}" in
      1) create_user_interactive ;;
      2) create_user_interactive ;;
      3) create_user_interactive ;;
      4) create_user_interactive ;;
      5) create_v2ray_account 2>/dev/null || echo "(placeholder: belum diimplementasi)" ;;
      6) if [[ -f "${USERS_CSV}" ]]; then column -t -s, "${USERS_CSV}" || cat "${USERS_CSV}"; else echo "(belum ada user)"; fi ;;
      7) read -p "Masukkan username: " R; userdel -f "$R" 2>/dev/null || true; sed -i "/^$R,/d" "${USERS_CSV}"; write_xray_config "$(server_ip)"; systemctl restart xray >/dev/null 2>&1 || true; echo "User $R dihapus." ;;
      8) systemctl restart udp-custom && echo "UDP-Custom direstart." || echo "Gagal restart udp-custom." ;;
      9) systemctl status udp-custom --no-pager || echo "(udp-custom service tidak ada)" ;;
      10) journalctl -u xray -n 200 --no-pager || true; journalctl -u udp-custom -n 200 --no-pager || true ;;
      11) read -p "Masukkan raw URL menu (atau enter skip): " REM; if [[ -n "${REM}" ]]; then wget -q -O "${MENU_PATH}" "${REM}" && chmod +x "${MENU_PATH}" && echo "Menu updated."; else echo "Skipped."; fi ;;
      12) install_telegram_bot ;;
      13) toggle_wildcard_mode ;;
      14) recreate_cert_and_reload ;;
      15) fixer_all ;;
      16) echo "Keluar..."; exit 0 ;;
      *) echo -e "${RED}Pilihan salah!${NC}" ;;
    esac
    echo -e "\nTekan Enter untuk kembali..."
    read -r
  done
}

# CLI flags
if [[ "${1:-}" == "--create-noninteractive" ]]; then
  create_noninteractive "${2:-}" "${3:-}" "${4:-}"
  exit 0
fi
if [[ "${1:-}" == "--fix-now" ]]; then
  fixer_all
  exit 0
fi

# start
load_meta
main_menu
SCRIPT
sudo chmod +x /usr/local/bin/menu_full_yhds_v5.sh && echo "Script tersimpan di /usr/local/bin/menu_full_yhds_v5.sh (executable)."
