#!/bin/bash
# ============================================================
#  PANEL VPN - Master Installer (idempotent, aman dijalankan ulang)
#  Untuk Debian 12. Jalankan sebagai root.
#
#  Yang dipasang:
#   1. Paket base (haproxy, nginx, dropbear, python3, sqlite3, dsb)
#   2. Xray-core + 5 instance systemd (edge, vmess, vless, trojan, shadowsocks)
#   3. HAProxy (:80/:443) + nginx (:8080 fallback, :81 file akun & web UI)
#   4. Dropbear 2019.78 dari source (:143/:109) + ws.py (SSH over websocket :10020)
#   5. badvpn-udpgw (opsional, best-effort)
#   6. acme.sh (TLS, butuh DOMAIN diisi manual)
#   7. vpnctl (provisioning akun, format DB identik dgn FighterTunnel)
#   8. panel-api.py (:5888) + panel-bot.py (butuh BOT_TOKEN)
#   9. vpn-quota (enforcement kuota & expiry)
#  10. Web admin UI di http://IP-SERVER:81/panel/
# ============================================================
set -e
cd "$(dirname "$0")"

log() { echo -e "\n=== $1 ==="; }
DOMAIN="${DOMAIN:-}"
echo "DOMAIN=${DOMAIN:-<belum diisi>}"

log "[1/10] Paket base"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq haproxy nginx curl wget unzip python3 \
  python3-pip sqlite3 cron iptables iproute2 dnsutils socat netcat-openbsd \
  cmake build-essential git zlib1g-dev bzip2

log "[2/10] Xray-core"
if [ ! -x /usr/local/bin/xray ]; then
  (cd /tmp
  wget -q -O xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip
  unzip -o -q xray.zip xray -d /tmp
  install -m 755 /tmp/xray /usr/local/bin/xray
  rm -f /tmp/xray.zip /tmp/xray)
fi
/usr/local/bin/xray version | head -1
mkdir -p /etc/xray/{edge,vmess,vless,trojan,shadowsocks,ssh}
# JANGAN timpa config xray yang sudah ada (isinya daftar akun pelanggan!)
for p in edge vmess vless trojan shadowsocks; do
  if [ ! -f /etc/xray/$p/config.json ]; then
    cp xray/$p.json /etc/xray/$p/config.json
    echo "  config baru: /etc/xray/$p/config.json"
  else
    echo "  config lama dipertahankan: /etc/xray/$p/config.json"
  fi
done
cp systemd/xray@.service /etc/systemd/system/
# sertifikat sementara sampai acme.sh diisi domain asli
if [ ! -f /etc/xray/xray.crt ]; then
  openssl req -x509 -newkey rsa:2048 -keyout /etc/xray/xray.key \
    -out /etc/xray/xray.crt -days 3650 -nodes -subj "/CN=localhost" 2>/dev/null
fi
chown -R www-data:www-data /etc/xray
chmod 600 /etc/xray/xray.key
[ -n "$DOMAIN" ] && echo "$DOMAIN" > /etc/xray/domain || touch /etc/xray/domain
touch /etc/xray/ns_domain /etc/xray/city /etc/xray/isp /etc/xray/pubkey
systemctl daemon-reload
for i in edge vmess vless trojan shadowsocks; do systemctl enable --now "xray@$i"; done
# migrasi: pastikan fallback /api/ -> panel-api:5888 ada (untuk bot member via https://domain/api/)
# (sekalian pindahkan fallbacks ke settings.fallbacks — lokasi yang benar menurut Xray)
EDGE_MIGRATED="$(python3 -c "
import json
p = '/etc/xray/edge/config.json'
try:
    cfg = json.load(open(p))
    ib = cfg['inbounds'][0]
    fb = ib.get('fallbacks', []) or ib.get('settings', {}).get('fallbacks', [])
    if not any(f.get('path') == '/api/' for f in fb):
        idx = next((i for i, f in enumerate(fb) if 'path' not in f), len(fb))
        fb.insert(idx, {'dest': 5888, 'path': '/api/'})
    ib.pop('fallbacks', None)
    ib.setdefault('settings', {})['fallbacks'] = fb
    json.dump(cfg, open(p, 'w'))
    print('YES')
except Exception:
    pass
" 2>/dev/null)"
if [ "$EDGE_MIGRATED" = "YES" ]; then
  echo "  migrasi edge.json: fallback /api/ ditambahkan, restart xray@edge"
  systemctl restart xray@edge
fi
# migrasi: multi path zero-config — catch-all edge -> nginx 10009
# (/whatever/vmess -> rewrite ke /vmess -> xray inner)
EDGE_MP="$(python3 -c "
import json
p = '/etc/xray/edge/config.json'
try:
    cfg = json.load(open(p))
    ib = cfg['inbounds'][0]
    fb = ib.get('fallbacks', []) or ib.get('settings', {}).get('fallbacks', [])
    fb = [f for f in fb if not (f.get('dest') == 10009 and 'path' in f)]
    changed = False
    for f in fb:
        if 'path' not in f and f.get('dest') != 10009:
            f['dest'] = 10009
            changed = True
    ib.pop('fallbacks', None)
    ib.setdefault('settings', {})['fallbacks'] = fb
    json.dump(cfg, open(p, 'w'))
    print('YES' if changed else 'OK')
except Exception:
    pass
" 2>/dev/null)"
if [ "$EDGE_MP" = "YES" ]; then
  echo "  migrasi edge.json: catch-all -> nginx multipath :10009, restart xray@edge"
  systemctl restart xray@edge
fi
# migrasi: fallback /ssh-ws -> ws.py :10020 direct (SSH over WS via 443).
# Catatan: fallback path-based Xray ke nginx :10009 terbukti bermasalah,
# jadi canonical langsung ke ws.py; multipath tetap via nginx :10009 (catch-all).
# Alias FighterTunnel /fightertunnelssh juga ditambahkan (migrasi seamless).
EDGE_SSHWS="$(python3 -c "
import json
p = '/etc/xray/edge/config.json'
try:
    cfg = json.load(open(p))
    ib = cfg['inbounds'][0]
    fb = ib.get('settings', {}).get('fallbacks', [])
    changed = False
    for path in ('/ssh-ws', '/fightertunnelssh'):
        cur = next((f for f in fb if f.get('path') == path), None)
        if not cur or cur.get('dest') != 10020:
            if cur:
                fb.remove(cur)
            idx = next((i for i, f in enumerate(fb) if 'path' not in f), len(fb))
            fb.insert(idx, {'path': path, 'dest': 10020})
            changed = True
    if changed:
        json.dump(cfg, open(p, 'w'))
    print('YES' if changed else 'OK')
except Exception:
    pass
" 2>/dev/null)"
if [ "$EDGE_SSHWS" = "YES" ]; then
  echo "  migrasi edge.json: fallback /ssh-ws + /fightertunnelssh -> :10020, restart xray@edge"
  systemctl restart xray@edge
fi
# migrasi: catch-all 443 -> ws.py :10020 direct (bug-host payload, ala FighterTunnel)
# Catatan: multipath 443 (/whatever/vmess) tetap via nginx :10009 di port 80;
# di 443, prioritas ke kompatibilitas bug-host.
EDGE_CATCHALL="$(python3 -c "
import json
p = '/etc/xray/edge/config.json'
try:
    cfg = json.load(open(p))
    fb = cfg['inbounds'][0]['settings']['fallbacks']
    cur = next((f for f in fb if 'path' not in f), None)
    if cur and cur.get('dest') == 10020:
        print('OK')
    else:
        if cur:
            cur['dest'] = 10020
        json.dump(cfg, open(p, 'w'))
        print('YES')
except Exception:
    pass
" 2>/dev/null)"
if [ "$EDGE_CATCHALL" = "YES" ]; then
  echo "  migrasi edge.json: catch-all -> :10020, restart xray@edge"
  systemctl restart xray@edge
fi

log "[3/10] HAProxy + nginx"
cp haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg
haproxy -c -f /etc/haproxy/haproxy.cfg
# bersihkan SEMUA site nginx lama, hanya panel.conf yang dipakai
rm -f /etc/nginx/sites-enabled/*
cp nginx/panel.conf /etc/nginx/sites-enabled/panel.conf
mkdir -p /var/www/html/panel
cp web/index.html web/style.css web/app.js /var/www/html/panel/
chmod -R a+rX /var/www/html/panel  # nginx (www-data) harus bisa baca file web UI
nginx -t
systemctl enable nginx haproxy
# restart (bukan start) agar config nginx baru dipakai & port 80 dilepas untuk haproxy
systemctl restart nginx
systemctl reset-failed haproxy || true
systemctl restart haproxy
systemctl is-active haproxy nginx

log "[4/10] Dropbear 2019.78 + ws.py"
grep -qE "^/bin/false$" /etc/shells || echo "/bin/false" >> /etc/shells
grep -qE "^/usr/sbin/nologin$" /etc/shells || echo "/usr/sbin/nologin" >> /etc/shells
# Dropbear 2019.78 dari source (standar script komunitas, ganti versi distro)
systemctl stop dropbear 2>/dev/null || true
systemctl disable dropbear 2>/dev/null || true
apt-get remove -y dropbear 2>/dev/null || true
mkdir -p /etc/dropbear
if [ ! -f /etc/dropbear/.version-2019.78 ]; then
  echo "  compile Dropbear 2019.78 dari source..."
  (cd /tmp && rm -rf dropbear-2019.78 dropbear-2019.78.tar.bz2
   wget -q https://matt.ucc.asn.au/dropbear/releases/dropbear-2019.78.tar.bz2
   tar xjf dropbear-2019.78.tar.bz2 && cd dropbear-2019.78
   ./configure --prefix=/usr >/dev/null 2>&1
   make -j"$(nproc)" >/dev/null 2>&1
   make install >/dev/null 2>&1
   cd /tmp && rm -rf dropbear-2019.78 dropbear-2019.78.tar.bz2) \
  && touch /etc/dropbear/.version-2019.78 \
  && echo "  Dropbear 2019.78 OK" \
  || echo "  Dropbear 2019.78 GAGAL compile"
fi
# fallback: kalau binary tidak ada (compile gagal), pakai dropbear distro
if [ ! -x /usr/sbin/dropbear ]; then
  echo "  fallback: pasang dropbear distro"
  apt-get install -y dropbear 2>/dev/null || echo "  dropbear tidak tersedia"
fi
for t in rsa ecdsa ed25519; do
  [ -f /etc/dropbear/dropbear_${t}_host_key ] || \
    /usr/bin/dropbearkey -t $t -f /etc/dropbear/dropbear_${t}_host_key >/dev/null 2>&1 || true
done
cat > /etc/systemd/system/dropbear.service <<'EOF'
[Unit]
Description=Dropbear SSH 2019.78 (:143/:109)
After=network.target
[Service]
Type=simple
ExecStart=/usr/sbin/dropbear -F -E -p 143 -p 109 -W 65536
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
install -m 755 scripts/ws.py /usr/local/bin/ws.py
cp systemd/vpn-ws.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable vpn-ws dropbear
systemctl restart vpn-ws dropbear

log "[5/10] badvpn-udpgw (opsional)"
if [ ! -x /usr/local/bin/badvpn-udpgw ]; then
  (cd /tmp && rm -rf badvpn badvpn.tar.gz
   wget -q -O badvpn.tar.gz https://github.com/ambrop72/badvpn/archive/refs/heads/master.tar.gz
   tar xzf badvpn.tar.gz && mv badvpn-master badvpn
   mkdir -p badvpn/build && cd badvpn/build
   cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=/usr/bin/gcc >/dev/null 2>&1
   make -j"$(nproc)" >/dev/null 2>&1
   install -m 755 udpgw/badvpn-udpgw /usr/local/bin/badvpn-udpgw) \
   && echo "badvpn OK" || echo "badvpn GAGAL (opsional, bisa dipasang manual nanti)"
fi
if [ -x /usr/local/bin/badvpn-udpgw ]; then
  cat > /etc/systemd/system/badvpn.service <<'EOF'
[Unit]
Description=BadVPN UDP gateway (:7100)
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 1000 --max-connections-for-client 10
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now badvpn
fi

log "[6/10] acme.sh"
if [ ! -x /root/.acme.sh/acme.sh ]; then
  curl -s https://get.acme.sh | sh -s email=admin@localhost >/dev/null 2>&1 || true
fi
# paksa default CA ke Let's Encrypt (ZeroSSL butuh EAB credentials)
[ -x /root/.acme.sh/acme.sh ] && /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
[ -x /root/.acme.sh/acme.sh ] && echo "acme.sh OK (CA: Let's Encrypt; issue via menu > 8.Pengaturan > 1)"

log "[7/10] vpnctl (provisioning) + menu (menu terminal)"
install -m 755 scripts/vpnctl /usr/local/bin/vpnctl
install -m 755 scripts/vpn-menu /usr/local/bin/vpn-menu
ln -sf /usr/local/bin/vpn-menu /usr/local/bin/menu
install -m 755 scripts/vpn-backup /usr/local/bin/vpn-backup
install -m 755 scripts/vpn-quota.py /usr/local/bin/vpn-quota.py
mkdir -p /var/backups/vpn-panel
# cron backup harian jam 03:00 (bisa diubah/dimatikan via menu > 8 > 7 > 2)
if [ ! -f /etc/cron.d/vpn-backup ]; then
  printf '# Backup akun VPN otomatis (dibuat via menu)\n0 3 * * * root /usr/local/bin/vpn-backup\n' > /etc/cron.d/vpn-backup
  chmod 644 /etc/cron.d/vpn-backup
fi

log "[8/10] API :5888 + bot Telegram"
install -m 755 api/panel-api.py /usr/local/bin/panel-api.py
install -m 755 bot/panel-bot.py /usr/local/bin/panel-bot.py
cp systemd/panel-api.service systemd/panel-bot.service systemd/vpn-quota.service /etc/systemd/system/
[ -f /etc/xray/api.key ] || tr -dc A-Za-z0-9 </dev/urandom | head -c 32 > /etc/xray/api.key
chmod 600 /etc/xray/api.key
mkdir -p /etc/vpn-panel
[ -f /etc/vpn-panel/bot.env ] || printf "# Isi dengan token dari @BotFather dan ID Telegram admin\nBOT_TOKEN=\nADMIN_IDS=\n" > /etc/vpn-panel/bot.env
chmod 600 /etc/vpn-panel/bot.env
if ! python3 -c "import telegram" 2>/dev/null; then
  pip3 install --break-system-packages "python-telegram-bot>=20" 2>&1 | tail -2 \
    || pip3 install --break-system-packages --ignore-installed "python-telegram-bot>=20" 2>&1 | tail -2
fi
python3 -c "import telegram" 2>/dev/null \
  && echo "  python-telegram-bot OK" \
  || echo "  ⚠️ python-telegram-bot GAGAL dipasang — bot Telegram tidak akan jalan sampai ini diinstall manual"
systemctl daemon-reload
systemctl enable panel-api vpn-quota
systemctl restart panel-api vpn-quota
# bot hanya dinyalakan kalau token sudah diisi
if grep -q "^BOT_TOKEN=.." /etc/vpn-panel/bot.env 2>/dev/null; then
  systemctl enable panel-bot
  systemctl restart panel-bot
else
  echo "bot Telegram BELUM dinyalakan (isi BOT_TOKEN di /etc/vpn-panel/bot.env dulu)"
fi

log "[9/10] Verifikasi service"
for s in xray@edge xray@vmess xray@vless xray@trojan xray@shadowsocks \
         haproxy nginx dropbear vpn-ws panel-api vpn-quota; do
  printf "%-18s %s\n" "$s" "$(systemctl is-active "$s")"
done

log "[10/10] SELESAI 🎉"
echo ""
echo "API key server : $(cat /etc/xray/api.key)"
echo "Web admin UI   : http://$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')/panel/"
echo "API endpoint   : http://IP/api/ (atau http://IP:5888/ langsung)"
echo ""
echo "LANGKAH SELANJUTNYA (semua via perintah 'menu' > 8.Pengaturan, tanpa edit manual):"
echo " 1. Set domain + TLS -> menu 8 > 1 (all-in-one)"
echo " 2. Bot Telegram     -> menu 8 > 3 (isi BOT_TOKEN & ADMIN_IDS)"
echo ""
echo "Ketik 'menu' kapan saja untuk buka menu."
