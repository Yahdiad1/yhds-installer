# YHDS Installer - VPN + WS + Trojan + UDP-Custom

Installer all-in-one untuk VPS. Mendukung SSH, UDP-Custom, WebSocket, Trojan, V2Ray, dan auto-restart services. Akun yang dibuat langsung tampil, siap di-copy.

---

## Fitur

- Menu interaktif 1–12
- Create akun SSH, UDP-Custom, WS, Trojan, V2Ray
- UDP-Custom siap konek **port 1–65535**
- List, remove user
- Restart semua service
- Check status dan logs UDP-Custom
- Auto update script
- VPS otomatis reboot setelah instalasi

---

## Cara Install

Jalankan perintah berikut di VPS root:

```bash
wget -O install_full_ready.sh https://raw.githubusercontent.com/Yahdiad1/yhds-installer/main/install_full_ready.sh
chmod +x install_full_ready.sh
./install_full_ready.sh

## Cara Install v3

Jalankan perintah berikut di VPS root:

```bash

wget -O install_v3.sh https://raw.githubusercontent.com/Yahdiad1/yhds-installer/main/install_v3.sh
chmod +x install_v3.sh
./install_v3.sh
