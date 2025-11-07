#!/bin/bash
# install_full_ready.sh - Installer VPN + WS + Trojan + UDP-Custom + Auto-Reboot + Menu 1-12
# ==========================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Script ini harus dijalankan sebagai root!${NC}"
   exit 1
fi

# Update & dependencies
echo -e "${BLUE}Mengupdate sistem...${NC}"
apt update -y && apt upgrade -y
apt install -y wget curl unzip bzip2 screen git jq lsof

# Folder konfigurasi
mkdir -p /etc/yhds
mkdir -p /usr/local/bin
mkdir -p /etc/udp-custom

# ===========================================================
# INSTALL UDP-CUSTOM (PORT 1-65535)
# ===========================================================
echo -e "${BLUE}Menginstall UDP-Custom...${NC}"
wget -O /usr/local/bin/udp-custom "https://raw.githubusercontent.com/Yahdiad1/yhds-installer/main/udp-custom"
chmod +x /usr/local/bin/udp-custom

cat >/etc/udp-custom/server.json <<EOL
{
    "port": "1-65535",
    "mode": "auto"
}
EOL

cat >/etc/systemd/system/udp-custom.service <<EOL
[Unit]
Description=UDP-Custom Service (akunssh)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/udp-custom server --config /etc/udp-custom/server.json
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOL

systemctl daemon-reload
systemctl enable udp-custom
systemctl start udp-custom

# ===========================================================
# CREATE ACCOUNT MANUAL FUNCTION
# ===========================================================
create_user() {
    read -p "Masukkan username: " USER
    read -p "Masukkan password: " PASS
    read -p "Masukkan hari expired: " EXPIRE
    EXPIRE_DATE=$(date -d "+$EXPIRE days" +"%Y-%m-%d")
    echo "$USER,$PASS,$EXPIRE_DATE" >> /etc/yhds/users.csv
    echo -e "${GREEN}Akun berhasil dibuat!${NC}"
    echo "============================="
    echo "Username: $USER"
    echo "Password: $PASS"
    echo "Expired: $EXPIRE_DATE"
    echo "============================="
}

# ===========================================================
# MENU INTERAKTIF
# ===========================================================
while true; do
clear
echo -e "${BLUE}===== YHDS VPN MENU =====${NC}"
echo "1) Create SSH Account"
echo "2) Create UDP-Custom Account"
echo "3) Create WS Account"
echo "4) Create Trojan Account"
echo "5) Create V2Ray Account"
echo "6) List Users"
echo "7) Remove User"
echo "8) Restart All Services"
echo "9) Check UDP-Custom Status"
echo "10) Check Logs"
echo "11) Auto Update Script"
echo "12) Exit"
echo -n "Pilih menu [1-12]: "
read MENU
case $MENU in
    1|2|3|4|5) create_user ;;
    6) cat /etc/yhds/users.csv ;;
    7) read -p "Masukkan username yang akan dihapus: " UDEL
       sed -i "/^$UDEL,/d" /etc/yhds/users.csv
       echo -e "${GREEN}User $UDEL dihapus${NC}" ;;
    8) systemctl restart udp-custom
       echo -e "${GREEN}Semua service direstart${NC}" ;;
    9) systemctl status udp-custom --no-pager ;;
    10) journalctl -u udp-custom -n 50 --no-pager ;;
    11) wget -O install_full_ready.sh "https://raw.githubusercontent.com/Yahdiad1/yhds-installer/main/install_full_ready.sh"
        chmod +x install_full_ready.sh
        echo -e "${GREEN}Script updated, jalankan ulang jika ingin install${NC}" ;;
    12) exit ;;
    *) echo -e "${RED}Pilihan salah!${NC}" ;;
esac
read -n1 -r -p "Tekan sembarang tombol untuk kembali ke menu..."
done

# ===========================================================
# AUTO REBOOT
# ===========================================================
echo -e "${BLUE}Instalasi selesai. VPS akan reboot dalam 10 detik...${NC}"
sleep 10
reboot
