# Bot Jual-Beli — Multi Tipe Server (FighterTunnel / Railway / Panel)

Satu bot bisa melayani 3 jenis server sekaligus. Modul lama **tidak dihapus**,
tidak diganti — hanya ditambah.

## File-file

| File | Fungsi |
|---|---|
| `modules/create-panel.js` | Modul create untuk tipe `panel` (pengganti unofficial, nama beda biar modul lama aman) |
| `modules/renew-panel.js` | Modul renew untuk tipe `panel` |
| `modules/server-adapter.js` | Dispatcher: meneruskan create/renew/status ke modul yang tepat sesuai kolom `tipe` |
| `patch-adapter.js` | Script patch otomatis untuk file utama bot (`app.js`/`bot.js`/...) |

## Cara pasang (di VPS bot)

1. Download paket terbaru, ambil folder `bot-member/`:
   ```
   tar xzf panel-vpn.tar.gz files/bot-member
   ```
2. Copy 3 file ke folder bot (sejajar dengan folder `modules/`):
   ```
   cp files/bot-member/modules/server-adapter.js  /path/bot/modules/
   cp files/bot-member/modules/create-panel.js    /path/bot/modules/
   cp files/bot-member/modules/renew-panel.js     /path/bot/modules/
   cp files/bot-member/patch-adapter.js           /path/bot/
   ```
   Modul lama (`modules/create.js`, `modules/renew.js`, `modules/railway.js`)
   **jangan dihapus**.
3. Jalankan patch (otomatis backup `app.js` dulu):
   ```
   cd /path/bot && node patch-adapter.js
   ```
   Kalau nama file utamamu bukan app.js/bot.js/index.js:
   ```
   node patch-adapter.js nama-file.js
   ```
4. Restart bot:
   ```
   pm2 restart <nama-bot>     # atau: systemctl restart <nama-bot>
   ```

## Tambah server tipe Panel

Di Telegram (sebagai admin): tambah server seperti biasa, lalu pilih
**🛰️ Panel (script sendiri)** saat ditanya tipe server.

- **Domain/IP**: `sgdo7.mamzvpn.my.id` (atau `43.156.114.36`)
- **Auth**: isi API key panel — lihat di VPS panel:
  ```
  cat /etc/xray/api.key
  ```

Server lama otomatis dianggap `fightertunnel`, jadi tidak ada yang berubah
sampai kamu ubah tipenya (menu Edit Server → Tipe).

## Yang diperbaiki sekalian oleh patch

1. **Renew VLESS/Trojan** yang tadinya salah memanggil `renewvmess` → sekarang
   memanggil fungsi renew yang benar per protokol.
2. **Saldo tidak lagi terpotong saat API gagal** — error dari server
   diteruskan sebagai pesan ❌ dan transaksi dibatalkan.
3. **Cek status server** untuk tipe `panel` memakai auth API (bukan cuma
   menebak port 22).
4. Daftar server menampilkan label tipe tiap server.
