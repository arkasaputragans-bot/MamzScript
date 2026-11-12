# SlowDNS MamzPanel — SSH lewat DNS (HTTP Custom)

Modul SlowDNS untuk MamzScript: server menerima query DNS dari aplikasi
HTTP Custom (Android), membuka sesi Noise/KCP, lalu meneruskannya ke
Dropbear lokal. Cocok untuk kartu kuota edukasi yang hanya membuka
jalur DNS.

## Cara kerja singkat

1. Klien (HTTP Custom) mengirim query DNS `<data>.ns-domainmu` ke
   nameserver VPS ini (UDP 53).
2. `iptables` REDIRECT UDP 53 → 5300, tempat engine mamz mendengarkan.
3. Engine mamz memvalidasi sesi, lalu meneruskan stream SSH ke
   Dropbear `127.0.0.1:143` (port SSH utama MamzScript, install.sh
   langkah 4).
4. Akun SSH yang dipakai adalah akun SSH biasa panel (dibuat lewat
   `menu` / `vpnctl`) — tidak ada akun khusus SlowDNS.

Yang TIDAK dilakukan modul ini: bukan resolver DNS umum, bukan proxy
terbuka, tidak mengubah DNS sistem server.

## Engine: mamz (fork bersih, satu-satunya)

- Engine yang dipakai: **mamz** — fork bersih DNSTT upstream (CC0)
  yang dibangun 11 Nov 2026 dari spesifikasi hasil bongkar binary
  referensi. Terverifikasi lab **61/61** (matriks 39/39 — 6 tipe,
  mode fixed, MTU, FORMERR; replay handshake 18/18; tunnel E2E 4/4
  payload TCP bolak-balik lewat tunnel TXT). Laporan:
  `slowdns/src/mamz/TEST-REPORT.md`.
- **Validasi live: LULUS 12 Nov 2026** — tap-test HTTP Custom dari HP
  melawan engine mamz di VPS tes: konek (server mencatat sesi masuk).
- Engine **dnstt** (DNSTT upstream Bam, TXT-only) SENGAJA tidak
  dipakai: klien HC melakukan kalibrasi dulu dan server dnstt
  orisinal tidak menjawab semua tipenya, sehingga sesi tidak pernah
  mulai.
- Binary **tidak dibawa paket**: install.sh langkah [10/11]
  **membangun engine dari source** (`slowdns/src/mamz`, butuh
  Go >= 1.21 — dipasang otomatis lewat apt, atau tarball resmi
  go.dev bila apt tidak menyediakan) menjadi binary statis
  `/usr/local/bin/mamz-slowdns-server`. Tiap build beda hash, jadi
  tidak ada pin sha256 — yang dicek manager adalah file ELF yang
  valid (magic + ukuran).
- **Potato DICOPOT 12 Nov 2026.** Engine lama (binary prebuilt
  A4NSTORE) dihapus dari repo: lisensi sewanya habis 13 Nov 2026 dan
  binary sewaan tidak boleh didistribusikan ulang di repo publik.
  Jangan masukkan lagi binary potato ke repo ini tanpa izin tertulis
  dari A4N.

## File di direktori ini

| File | Keterangan |
|---|---|
| `slowdns-manager.py` | Manager (port dari A4NSTORE, sudah diadaptasi; lihat bawah) |
| `src/mamz/` | Source engine mamz (modul Go `mamzslowdns`: `go.mod`, `go.sum`, `dns/`, `noise/`, `turbotunnel/`, `mamz-slowdns-server/`, `cmd/`, `COPYING`, `README.md`, `TEST-REPORT.md`) |
| `mamz-slowdns.service` | Template unit layanan (di-render manager saat `start`) |
| `mamz-slowdns-network.service` | Unit oneshot aturan firewall (REDIRECT UDP 53→5300) |
| `mamz-slowdns-reconcile.service` | Unit pemulihan konfigurasi (tiap 5 menit) |
| `mamz-slowdns-reconcile.timer` | Timer reconcile (5 menit, +90 dtk setelah boot) |
| `README.md` | File ini |

Jalur di server (sesudah install.sh):

- Manager: `/usr/local/bin/slowdns-manager.py` (755)
- Binary mamz: `/usr/local/bin/mamz-slowdns-server` (755, hasil build)
- Go (bila dipasang tarball): `/usr/local/go` (PATH ditambah install.sh)
- Staging binary: `/usr/local/lib/mamzpanel/slowdns/mamz-slowdns-server`
- Config + kunci: `/etc/mamzpanel/slowdns/` (`config.json`, `server.key`,
  `server.pub` — dir 0700, kunci 0600)
- Salinan runtime kunci: `/var/lib/mamz-slowdns/server.key` (0700)
- User sistem: `mamzslowdns`
- Unit: `/etc/systemd/system/mamz-slowdns*.service` + `.timer`

## Setup (lewat menu, tanpa edit file manual)

Buka `menu` > **8 Pengaturan** > **8 SlowDNS**:

1. **Setup nameserver** — isi nameserver (hostname yang menjawab
   query, punya `ns`, mis. `ns1-domainmu.my.id`), domain tunnel
   (suffix query HC, mis. `ns-domainmu.my.id`), dan IP publik VPS
   (otomatis terdeteksi). Manager mencetak 2 record yang harus dibuat
   di DNS domainmu:
   - `A  <nameserver> -> <IP VPS>` (DNS only, TTL 300)
   - `NS <domain tunnel> -> <nameserver>` (TTL 300)

   **JANGAN** buat record A di domain tunnel itu sendiri (apex zona
   terdelegasi) — record itu dapat menutupi delegasi NS.
2. **Aktifkan SlowDNS SSH** — manager memeriksa delegasi lewat
   `dns_ready()` (tanya otoritas induk, baca AUTHORITY+ANSWER),
   memeriksa Dropbear `:143` hidup, membuat kunci bila belum ada,
   lalu menyalakan service.
3. **Detail + public key** — menampilkan NameServer (domain tunnel),
   kunci publik HEX (utama — HC menerima hex, terbukti di tap-test)
   dan base32 (cadangan), port, Mode DNS, engine, upstream SSH.
4. **Nonaktifkan** — mematikan service + menghapus aturan firewall,
   config dan kunci dipertahankan (bisa diaktifkan lagi kapan saja).
5. **Mode DNS (tipe record)** — Auto (bawaan, semua 6 tipe) atau
   paksa satu tipe (TXT/NULL/CNAME/NS/MX/SRV). Berlaku langsung bila
   layanan aktif (unit ditulis ulang + restart).

Isi ke HTTP Custom (mode SlowDNS): Nameserver = domain tunnel, Public
key = kunci HEX (atau base32), Resolver `1.1.1.1`, Type `Auto`,
SSH host = domain biasa server, port `22` (cadangan `90`), akun SSH
biasa panel.

## Perintah manager (terminal)

```bash
slowdns-manager.py setup-manual <ns> <domain-tunnel> <ip-publik>
slowdns-manager.py start ssh <ip-publik>   # engine: mamz (satu-satunya)
slowdns-manager.py set-record-type <auto|txt|null|cname|ns|mx|srv|1-6>
slowdns-manager.py status | details | stop | records <ip>
slowdns-manager.py reconcile [ip-publik]             # IP auto-detect bila kosong
slowdns-manager.py firewall start|stop
slowdns-manager.py validate <dir-config>
slowdns-manager.py install                          # verifikasi binary mamz hasil build
```

Pengujian lokal: `MAMZ_SLOWDNS_ROOT=<dir>` mengarahkan semua path
manager ke direktori lain.

## Perbedaan dari manager A4N (yang di-port)

- Semua branding/nama A4N → MamzPanel (`mamz-slowdns`,
  `/etc/mamzpanel/slowdns`, user `mamzslowdns`, chain `MAMZ_SLOWDNS`).
- Drop-in lisensi `a4n-license.conf` TIDAK ikut; tidak ada guard
  lisensi, tidak ada callback controller, tidak ada unduhan binary
  dari controller.
- Provisioning Cloudflare otomatis DIBUANG — MamzScript tidak punya
  token Cloudflare; mode DNS hanya `manual` (manager mencetak record
  yang harus dibuat user).
- Mode hanya `ssh` (mode `openvpn`/`both`, router, dan unit anak
  dibuang). Upstream SSH `127.0.0.1:143` (Dropbear MamzScript),
  bukan `127.0.0.1:90`.
- **`stop()` diperbaiki:** `stop()` A4N memanggil
  `systemctl disable --now` dengan unit anak ssh/openvpn yang TIDAK
  ADA di mode ssh — perintah abort total, layanan tetap jalan,
  sehingga `setup-manual` menolak ganti hostname (terbukti 11 Nov
  2026). Di port ini semua pemanggilan systemctl dengan daftar unit
  lewat `existing_units()` — hanya unit yang berkasnya ada yang
  disentuh — plus `systemctl stop` langsung sebagai sabuk pengaman.
  Urutan stop → setup-manual → start sudah diuji lolos.
- `details()` menampilkan kunci HEX sebagai utama + base32 cadangan
  (manager A4N tidak punya konversi base32).
- Reconcile menerima IP opsional (auto-detect bila kosong) dan tidak
  lagi memanggil runtime menu monolitik.
- `install_engine_binary()` tidak mengunduh dan tidak memverifikasi
  sha256 — ia menyalin dari salinan staging hasil build installer
  dan memeriksa file ELF yang valid.
- Engine `potato` dicopot 12 Nov 2026 (lihat atas); `ENGINES` di
  manager kini hanya berisi `mamz`.

## Batasan yang diketahui

- Arsitektur `amd64` saja (manager menolak arsitektur lain).
- Butuh domain terdelegasi (NS + A) sebelum `start` bisa lolos
  `dns_ready()`. VPS tanpa domain tidak bisa diuji E2E (aktivasi
  akan gagal dengan pesan DNS belum siap — itu wajar, bukan bug).
- Build butuh Go >= 1.21 + akses jaringan ke proxy.golang.org
  (unduh modul Go saat build pertama). Tanpa internet, langkah
  SlowDNS di install.sh dibatalkan dengan pesan jelas — langkah
  lain tetap jalan.
- Resolver publik (1.1.1.1/8.8.8.8) mengembalikan SERVFAIL "No
  Reachable Authority" untuk query NS zona terdelegasi — NORMAL
  untuk DNSTT (engine tidak menjawab query NS polos). HC bicara
  langsung ke IP nameserver, jadi ini bukan penghalang.
- `dig +noall +answer` menyembunyikan referral: NS subdomain
  terdelegasi muncul di AUTHORITY section. Saat memeriksa delegasi,
  baca `+answer +authority` (persis yang dilakukan `dns_ready()`),
  atau gunakan `dig NS <domain>` tanpa filter.
