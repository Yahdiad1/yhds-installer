#!/bin/bash
# /usr/local/bin/menu
# MENU YHDS VPS v4 — Full Payload Generator + Telegram Send
# Paste file ini ke /usr/local/bin/menu dan chmod +x

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[1;36m'; MAGENTA='\033[1;35m'; BLUE='\033[0;34m'; NC='\033[0m'

# Load Telegram config jika ada
BOT_TOKEN="$(jq -r .token /etc/yhds/telegram-bot/config.json 2>/dev/null || echo '')"
CHAT_ID="$(jq -r .chat_id /etc/yhds/telegram-bot/config.json 2>/dev/null || echo '')"

if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}Run as root${NC}"
  exit 1
fi

print_banner(){
  if command -v figlet >/dev/null 2>&1 && command -v lolcat >/dev/null 2>&1; then
    figlet -f slant "YHDS VPS" | lolcat -a
  else
    echo -e "${MAGENTA}"
    echo "██╗   ██╗██╗  ██╗██████╗ ███████╗"
    echo "██║   ██║██║  ██║██╔══██╗██╔════╝"
    echo "██║   ██║███████║██████╔╝█████╗  "
    echo "██║   ██║██╔══██║██╔═══╝ ██╔══╝  "
    echo "╚██████╔╝██║  ██║██║     ███████╗"
    echo " ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝"
    echo -e "${NC}"
  fi
}

show_info(){
  HOSTNAME=$(hostname)
  OS=$(lsb_release -d 2>/dev/null | cut -f2 || echo "$(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '\"')")
  KERNEL=$(uname -r)
  IP=$(curl -s ipv4.icanhazip.com || hostname -I | awk '{print $1}')
  ISP=$(curl -s ipinfo.io/org | sed 's/^[0-9]* //' 2>/dev/null || echo "N/A")
  CITY=$(curl -s ipapi.co/city 2>/dev/null || echo "N/A")
  UPTIME=$(uptime -p)
  LOAD=$(uptime | awk -F'load average:' '{print $2}')
  RAM=$(free -h | awk '/Mem:/ {print $3 "/" $2}')
  SWAP=$(free -h | awk '/Swap:/ {print $3 "/" $2}')
  DISK=$(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 ")"}')
  echo -e "${CYAN}╔════════════════════════════════════════════════╗${NC}"
  echo -e "${MAGENTA}║                MENU YHDS VPS PREMIUM           ║${NC}"
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
  echo -e "${YELLOW} SWAP     :${NC} $SWAP"
  echo -e "${YELLOW} Disk     :${NC} $DISK"
  echo -e "${CYAN}╚════════════════════════════════════════════════╝${NC}"
  echo ""
}

send_telegram(){
  local text="$1"
  if [ -n "$BOT_TOKEN" ] && [ -n "$CHAT_ID" ]; then
    curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
      -d chat_id="${CHAT_ID}" -d parse_mode="HTML" --data-urlencode "text=${text}" >/dev/null 2>&1 || true
  fi
}

create_interactive(){
  read -p "Masukkan username: " U
  [ -z "$U" ] && { echo "Username kosong. Batal."; return; }
  read -p "Masukkan password: " P
  [ -z "$P" ] && { echo "Password kosong. Batal."; return; }
  read -p "Expired (hari): " D
  if ! [[ "$D" =~ ^[0-9]+$ ]]; then D=1; fi
  read -p "Host/domain (enter=IP): " H
  [ -z "$H" ] && H=$(curl -s ipv4.icanhazip.com || hostname -I | awk '{print $1}')

  EXP_DATE=$(date -d "+${D} days" +%Y-%m-%d)
  useradd -M -s /bin/false -e "$EXP_DATE" "$U" 2>/dev/null || true
  echo -e "${P}\n${P}" | passwd "$U" 2>/dev/null || true
  mkdir -p /etc/yhds
  echo "$U,$P,$EXP_DATE" >> /etc/yhds/users.csv

  SSH_PORT=22
  WS_PORT=80
  WSS_PORT=443
  TROJAN_PORT=443
  VMESS_PATH="/"

  UUID=$(command -v uuidgen >/dev/null 2>&1 && uuidgen || python3 -c "import uuid; print(uuid.uuid4())")

  SSH_LINE="${H}:${SSH_PORT}@${U}:${P}"
  HTTP80_LINE="${H}:80@${U}:${P}"
  HTTP443_LINE="${H}:443@${U}:${P}"
  UDP_RANGE="${H}:1-65535@${U}:${P}"
  WS_PAY="GET / HTTP/1.1[crlf]Host: ${H}[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf]User-Agent: [ua][crlf][crlf]"
  WSS_PAY="$WS_PAY"

  VMESS_JSON=$(cat <<J | sed 's/^  //g'
  {
    "v": "2",
    "ps": "YHDS-${U}",
    "add": "${H}",
    "port": "${WSS_PORT}",
    "id": "${UUID}",
    "aid": "0",
    "net": "ws",
    "type": "none",
    "host": "${H}",
    "path": "${VMESS_PATH}",
    "tls": "tls"
  }
J
)

  VMESS_BASE=$(echo -n "${VMESS_JSON}" | base64 | tr -d '\n')
  VMESS_LINK="vmess://${VMESS_BASE}"
  VLESS_LINK="vless://${UUID}@${H}:${WSS_PORT}?type=ws&security=tls&path=${VMESS_PATH}#YHDS-${U}"
  TROJAN_LINK="trojan://${P}@${H}:${TROJAN_PORT}#YHDS-${U}"

  OUTPUT="===============================\n"
  OUTPUT+="✅ Akun dibuat: ${U}\nPassword: ${P}\nExpired : ${EXP_DATE}\nHost    : ${H}\n"
  OUTPUT+="===============================\n\n"
  OUTPUT+="--- SSH ---\nHost: ${H}\nPort: ${SSH_PORT}\nUser: ${U}\nPass: ${P}\n\n"
  OUTPUT+="--- HTTP ---\nPort 80  : ${HTTP80_LINE}\nPort 443 : ${HTTP443_LINE}\nUDP range: ${UDP_RANGE}\n\n"
  OUTPUT+="--- WS ---\nPort: ${WS_PORT}\nPayload:\n${WS_PAY}\n\n"
  OUTPUT+="--- WSS ---\nPort: ${WSS_PORT}\nPayload:\n${WSS_PAY}\n\n"
  OUTPUT+="--- VMESS ---\n${VMESS_LINK}\n\n"
  OUTPUT+="--- VLESS ---\n${VLESS_LINK}\n\n"
  OUTPUT+="--- TROJAN ---\n${TROJAN_LINK}\n\n"
  OUTPUT+="===============================\n(Payload disimpan: /tmp/last_yhds_payload.txt)\n===============================\n"

  echo -e "${OUTPUT}" | tee /tmp/last_yhds_payload.txt

  if [ -n "$BOT_TOKEN" ] && [ -n "$CHAT_ID" ]; then
    MSG_HTML="<b>✅ TRIAL SSH PREMIUM</b>\n<pre>Username: ${U}\nPassword: ${P}\nExpired : ${EXP_DATE}\nHost    : ${H}\n</pre>\n"
    MSG_HTML+="<b>SSH</b>\n<pre>${H}:${SSH_PORT}@${U}:${P}</pre>\n"
    MSG_HTML+="<b>WS Payload</b>\n<pre>${WS_PAY}</pre>\n"
    MSG_HTML+="<b>VMESS</b>\n<pre>${VMESS_LINK}</pre>\n"
    MSG_HTML+="<b>VLESS</b>\n<pre>${VLESS_LINK}</pre>\n"
    MSG_HTML+="<b>TROJAN</b>\n<pre>${TROJAN_LINK}</pre>\n"
    curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
      -d chat_id="${CHAT_ID}" -d parse_mode="HTML" --data-urlencode "text=${MSG_HTML}" >/dev/null 2>&1
    echo "Payload dikirim ke Telegram."
  fi
}

update_menu(){
  echo "Mencoba update script menu..."
  wget -q -O /usr/local/bin/menu 'https://raw.githubusercontent.com/Yahdiad1/yhds-installer/main/menu' || echo "Update gagal"
  chmod +x /usr/local/bin/menu
}

while true; do
  clear
  print_banner
  show_info
  echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN} 1) Create SSH Account"
  echo -e " 2) Create UDP-Custom Account"
  echo -e " 3) Create WS Account"
  echo -e " 4) Create Trojan Account"
  echo -e " 5) Create V2Ray Account"
  echo -e " 6) List Users"
  echo -e " 7) Remove User"
  echo -e " 8) Restart UDP-Custom Service"
  echo -e " 9) Check UDP-Custom Status"
  echo -e "10) Check Logs"
  echo -e "11) Auto Update Script"
  echo -e "12) Install / Restart Telegram Bot"
  echo -e "13) Exit"
  echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"
  read -p "Pilih menu [1-13]: " CH
  case "$CH" in
    1|2|3|4|5) create_interactive ;;
    6) cat /etc/yhds/users.csv || echo "(belum ada user)" ;;
    7) read -p "Masukkan username: " R; userdel -f "$R" 2>/dev/null || true; sed -i "/^$R,/d" /etc/yhds/users.csv; echo "User $R dihapus." ;;
    8) systemctl restart udp-custom && echo "UDP-Custom direstart." ;;
    9) systemctl status udp-custom --no-pager || true ;;
    10) journalctl -u udp-custom -n 200 --no-pager || true ;;
    11) update_menu ;;
    12) systemctl enable yhds-telegram-bot >/dev/null 2>&1 || true; systemctl restart yhds-telegram-bot >/dev/null 2>&1 || true; echo "Bot restarted/started." ;;
    13) exit 0 ;;
    *) echo "Pilihan tidak valid." ;;
  esac
  echo -e "\nTekan Enter untuk kembali..."
  read -r
done
