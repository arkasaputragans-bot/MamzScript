# 🛡️ Panel VPN Sendiri

Sistem panel VPN lengkap (klon FighterTunnel) — 100% open script, tanpa binary
tertutup. Database & format file dibuat **identik** dengan sistem lama sehingga
bisa backup/restore tukar-pakai.

## Arsitektur

```
Internet
  ├─ :443 ──→ HAProxy (TCP passthrough) ──→ Xray edge (TLS + fallbacks)
  │                                              ├─ /vmess,/vless,/trojan,/ss-ws → instance masing-masing
  │                                              └─ /vmess-grpc,/vless-grpc,/trojan-grpc (gRPC)
  ├─ :80 ───→ HAProxy (HTTP routing by path) ──→ Xray WS / ws.py (/ssh-ws) / nginx
  ├─ :81 ───→ nginx → file akun (.txt) + Web Admin UI (/panel/)
  ├─ :143/:109 → Dropbear 2019.78 (SSH)
  ├─ :22 ───→ OpenSSH
  └─ :5888 ─→ panel-api.py (REST API untuk bot & web UI)
```

Komponen:
| Komponen | Fungsi |
|---|---|
| `xray@edge/vmess/vless/trojan/shadowsocks` | 5 instance Xray-core |
| `haproxy` | Pintu depan :80/:443 |
| `nginx` | Fallback web :8080, file akun & web UI :81 |
| `dropbear` | SSH ringan 2019.78 :143/:109 |
| `vpn-ws` (ws.py) | SSH over WebSocket |
| `badvpn` | UDP gateway :7100 (gaming) |
| `vpnctl` | CLI provisioning akun (pengganti binary apicreate dkk) |
| `panel-api.py` | REST API :5888 (format respons identik dgn api.js asli) |
| `panel-bot.py` | Bot Telegram (ganti app.js) |
| `vpn-quota` | Enforcement kuota & hapus akun expired |

## Instalasi (sebagai root)

Via GitHub:

```bash
git clone https://github.com/arkasaputragans-bot/MamzScript.git
cd mamzscript
chmod +x install.sh
./install.sh
```

Via file tarball:

```bash
tar xzf panel-vpn.tar.gz && cd panel-vpn/files
chmod +x install.sh
./install.sh
```

Domain + sertifikat TLS tiap server diatur setelah install via menu
(`Set domain + pasang TLS`).

Script idempotent — aman dijalankan ulang.

## Database (format identik sistem lama)

**DB akun = file teks** (satu baris per akun):
```
/etc/ssh/.ssh.db                  →  ### <user> <expired YYYY-MM-DD>
/etc/xray/vmess/.vmess.db         →  ### <user> <expired> <uuid>
/etc/xray/vless/.vless.db         →  ### <user> <expired> <uuid>
/etc/xray/trojan/.trojan.db       →  ### <user> <expired> <uuid>
/etc/xray/shadowsocks/.shadowsocks.db → ### <user> <expired> <uuid>
```
**Metadata per user**: `/etc/xray/<proto>/<user>` = kuota (bytes),
`/etc/xray/<proto>/<user>IP` = limit IP.

**DB bot (SQLite)** `/etc/vpn-panel/servers.db`:
```sql
CREATE TABLE Server (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT, auth TEXT);
```

**Backup**: copy file-file `.db` + `/etc/vpn-panel/servers.db` + `/etc/xray/*/config.json`.
**Restore**: paste kembali — langsung jalan, tanpa migrasi.

## vpn-menu (menu terminal interaktif) ⭐

Jalankan `vpn-menu`, tinggal pilih nomor:
```
  1. Buat akun baru      5. List semua akun
  2. Hapus akun          6. Suspend / unsuspend akun
  3. Perpanjang akun     7. Status service
  4. Cek detail akun     0. Keluar
```
Tinggal jawab yang ditanya (username, masa aktif, kuota, limit IP) —
hasilnya langsung tampil rapi beserta link akunnya.

## 🔀 Multi Path (zero-config)

Path canonical (`/vmess`, `/vless`, `/trojan`, `/ss-ws`, `/ssh-ws`) selalu aktif.
Selain itu, **path bebas berpola `/<bebas>/<proto>` otomatis konek tanpa
didaftarkan** — mis. `/whatever/vmess`, `/abc123/vless`, `/rahasia/trojan`.
Berguna kalau path standar diblokir/dibatasi ISP, atau buat trik CDN/bug host:
user 1 bisa pakai `/vmess`, user 2 pakai `/whatever/vmess`, dst.

Berlaku di port 80 (non-TLS) & 443 (TLS). Alias: `shadowsocks` (= `ss-ws`),
`ssh` (= `ssh-ws`, hanya port 80).

Teknis: Xray wajib exact-match path, jadi pola custom di-*rewrite* ke canonical
sebelum sampai Xray (HAProxy `set-path` di :80; nginx 127.0.0.1:10009 di :443
via fallback catch-all xray-edge).

## vpnctl (CLI)

```bash
vpnctl create <proto> <user> <hari> <kuota_gb> <limit_ip> [password-ssh]
vpnctl delete <proto> <user>
vpnctl renew  <proto> <user> <hari_tambahan>
vpnctl check  <proto> <user>
vpnctl list   <proto>
vpnctl suspend   <proto> <user>   # bekukan (kuota habis)
vpnctl unsuspend <proto> <user>   # aktifkan lagi
# proto: ssh | vmess | vless | trojan | shadowsocks
```

## REST API (:5888)

Auth: query param `auth` = isi `/etc/xray/api.key`. Tanpa auth → 401.

```
GET /createvmess?user=&exp=&quota=&iplimit=&auth=
GET /createssh?user=&password=&exp=&iplimit=&auth=
GET /checkvmess?user=&auth=      GET /deletevmess?user=&auth=
GET /renewvmess?user=&exp=&auth=
GET /status?auth=                # dashboard: status service + jumlah akun
GET /servers?auth=               # list server
GET /addserver?domain=&authkey=&auth=
GET /delserver?id=&auth=
```
(Ganti `vmess` dengan `vless`/`trojan`/`shadowsocks`/`ssh` untuk protokol lain.)

## Bot Telegram

1. Buat bot ke @BotFather → dapatkan token.
2. Isi `/etc/vpn-panel/bot.env`:
   ```
   BOT_TOKEN=123456:ABC...
   ADMIN_IDS=111111,222222   # ID Telegram admin (opsional)
   ```
3. `systemctl enable --now panel-bot`
4. Di bot: `/addserver <domain> <auth-key-server-tujuan>`
5. Perintah: `/menu` → Buat/Hapus/Perpanjang/Cek akun.

## Web Admin UI

Buka `http://IP-SERVER/panel/` (port 80) → login dengan host API
(otomatis terisi `IP/api`) + API key. Bisa: dashboard status service,
CRUD akun semua protokol, kelola server.

## TLS / Domain

```bash
echo "vpn.contoh.id" > /etc/xray/domain
/root/.acme.sh/acme.sh --issue -d vpn.contoh.id --standalone
/root/.acme.sh/acme.sh --install-cert -d vpn.contoh.id \
  --fullchain-file /etc/xray/xray.crt --key-file /etc/xray/xray.key
systemctl restart xray@edge
```

## File konfigurasi penting

| File | Isi |
|---|---|
| `/etc/xray/api.key` | Kunci auth API :5888 |
| `/etc/xray/domain`, `ns_domain`, `city`, `isp`, `pubkey` | Info server (muncul di pesan bot) |
| `/etc/vpn-panel/bot.env` | Token bot Telegram |
| `/etc/haproxy/haproxy.cfg` | Routing :80/:443 |
| `/etc/xray/<proto>/config.json` | Daftar client Xray (diatur otomatis oleh vpnctl) |

## Troubleshooting

- `systemctl status xray@vmess` — cek instance Xray
- `journalctl -u panel-api -n 50` — log API
- `journalctl -u vpn-quota -n 50` — log quota
- `haproxy -c -f /etc/haproxy/haproxy.cfg` — validasi config HAProxy
- `/usr/local/bin/xray run -test -config /etc/xray/vmess/config.json` — validasi config Xray
