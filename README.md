# yhds-installer
# YHDS All-In-One Installer

Script ini digunakan untuk install VPS multi-tunnel dengan fitur:

- SSH / WebSocket
- UDP-Custom (akunssh)
- Xray (VLESS / Trojan)
- SlowDNS
- Interactive menu (1-10) untuk manajemen akun dan server

## Cara Pakai

1. Clone repo atau download:

```bash
git clone https://github.com/Yahdiad1/yhds-installer.git
cd yhds-installer/
chmod +x install.sh && ./install.sh.
## install
apt update -y && apt install -y curl wget git
git clone https://github.com/Yahdiad1/yhds-installer.git /root/yhds-installer
cd /root/yhds-installer
chmod +x install.sh
./install.sh
