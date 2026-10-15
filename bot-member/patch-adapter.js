/**
 * patch-adapter.js — Pasang server-adapter (multi-tipe server) ke bot jual-beli.
 *
 * v2: + tombol "Edit Tipe Server" di menu admin + proteksi handler generik
 *     agar callback editserver_tipe_<id> tidak diserobot.
 *
 * Cara pakai (di folder bot, VPS bot):
 *   1. Copy ke folder bot: modules/server-adapter.js, modules/create-panel.js,
 *      modules/renew-panel.js  (modul lama JANGAN dihapus)
 *   2. Jalankan:  node patch-adapter.js [nama-file-bot.js]
 *      (tanpa argumen: otomatis cari app.js / bot.js / index.js / main.js)
 *   3. Restart bot (pm2 restart <nama> / systemctl restart <nama>)
 *
 * Script ini mem-backup file bot ke <file>.bak-<waktu> sebelum mengubah.
 * Aman dijalankan ulang: langkah yang sudah diterapkan akan di-skip.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const arg = process.argv[2];
const candidates = arg ? [arg] : ['app.js', 'bot.js', 'index.js', 'main.js', 'bot-member.js'];
const botFile = candidates.find(f => fs.existsSync(f));
if (!botFile) {
    console.error('❌ File bot tidak ditemukan. Jalankan: node patch-adapter.js <nama-file-bot.js>');
    process.exit(1);
}
console.log('📄 Target:', botFile);

// --- cek modul ---
for (const m of ['modules/server-adapter.js', 'modules/create-panel.js', 'modules/renew-panel.js']) {
    if (!fs.existsSync(m)) console.warn('⚠️  Belum ada:', m, '(copy dulu ke folder modules/)');
}

let src = fs.readFileSync(botFile, 'utf8');
const orig = src;
let changed = [];
const mark = (name, done, note) => { changed.push(`${done ? '✅' : '⏭️ '} ${name}${note ? ' — ' + note : ''}`); };

// 1) Migrasi kolom Server.tipe
if (src.includes('ADD COLUMN tipe')) mark('Migrasi kolom Server.tipe', false, 'sudah ada');
else {
    const re = /^.*CREATE TABLE IF NOT EXISTS Server.*$/m;
    if (!re.test(src)) mark('Migrasi kolom Server.tipe', false, 'baris CREATE TABLE tidak ketemu!');
    else {
        src = src.replace(re, m0 => m0 +
            '\n// [adapter] migrasi: tambah kolom tipe (fightertunnel/railway/panel)' +
            '\ndb.all(`PRAGMA table_info(Server)`, [], (e, cols) => {' +
            '\n  if (!e && cols && !cols.some(c => c.name === \'tipe\')) {' +
            '\n    db.run(`ALTER TABLE Server ADD COLUMN tipe TEXT DEFAULT \'fightertunnel\'`, () =>' +
            '\n      console.log(\'[adapter] kolom Server.tipe ditambahkan\'));' +
            '\n  }' +
            '\n});');
        mark('Migrasi kolom Server.tipe', true);
    }
}

// 2) checkServerStatus jadi sadar-tipe (sisipkan cabang di baris pertama fungsi)
if (src.includes('[adapter] cek per-tipe')) mark('checkServerStatus sadar-tipe', false, 'sudah ada');
else {
    const anchor = 'async function checkServerStatus(serverOrHost) {';
    if (!src.includes(anchor)) mark('checkServerStatus sadar-tipe', false, 'fungsi tidak ketemu!');
    else {
        src = src.replace(anchor, anchor +
            '\n    // [adapter] cek per-tipe: object server (ada kolom tipe) -> pakai adapter' +
            '\n    if (typeof serverOrHost === \'object\' && serverOrHost !== null && serverOrHost.tipe) {' +
            '\n        try { return await require(\'./modules/server-adapter\').checkStatus(serverOrHost); }' +
            '\n        catch (e) { return false; }' +
            '\n    }');
        mark('checkServerStatus sadar-tipe', true);
    }
}

// 3) Call-site: kirim object server, bukan cuma domain
let n3 = 0;
if (src.includes('checkServerStatus(s.domain)')) { src = src.split('checkServerStatus(s.domain)').join('checkServerStatus(s)'); n3++; }
if (src.includes('checkServerStatus(server.domain)')) { src = src.split('checkServerStatus(server.domain)').join('checkServerStatus(server)'); n3++; }
mark('Call-site checkServerStatus -> object server', n3 > 0, n3 + ' diganti');

// 4) Routing create/renew -> adapter (ganti blok isRailway)
if (src.includes("require('./modules/server-adapter')") && src.includes('adapter.createAccount')) {
    mark('Routing create/renew -> adapter', false, 'sudah ada');
} else {
    const re = /const isRailway[\s\S]*?\n {16}\}\n/;
    if (!re.test(src)) mark('Routing create/renew -> adapter', false, 'blok isRailway tidak ketemu!');
    else {
        src = src.replace(re,
            "const adapter = require('./modules/server-adapter'); // [adapter] 1 bot, 3 tipe server\n" +
            "                if (state.action !== 'renew') {\n" +
            "                    res = await adapter.createAccount(server.tipe, state.type, {\n" +
            "                        username: state.username, password: state.password,\n" +
            "                        exp, quota, ip, serverId: state.serverId, server });\n" +
            "                } else {\n" +
            "                    res = await adapter.renewAccount(server.tipe, state.type, {\n" +
            "                        username: state.username, exp, quota, ip,\n" +
            "                        serverId: state.serverId, server });\n" +
            "                }\n");
        mark('Routing create/renew -> adapter', true, 'blok isRailway diganti (bug renew vless/trojan ikut keperbaiki)');
    }
}

// 5) Pesan error asli diteruskan ke user (saldo aman karena adapter melempar Error)
if (src.includes("e.message.startsWith('❌')")) mark('Pesan error asli ke user', false, 'sudah ada');
else if (!src.includes("ctx.reply('❌ Gagal memproses permintaan.');")) mark('Pesan error asli ke user', false, 'pola tidak ketemu');
else {
    src = src.split("ctx.reply('❌ Gagal memproses permintaan.');")
             .join("ctx.reply((e && e.message && e.message.startsWith('❌')) ? e.message : '❌ Gagal memproses permintaan.');");
    mark('Pesan error asli ke user', true);
}

// 6) Alur tambah server: pilih tipe (langkah add_tipe)
if (src.includes("callback_data: 'srvtipe_")) mark('Pilih tipe saat tambah server', false, 'sudah ada');
else {
    const old6 = `if (state.step === 'add_harga') { if(isNaN(text)) return ctx.reply('❌ Wajib Angka!'); db.run("INSERT INTO Server (domain,auth,nama_server,quota,iplimit,batas_create_akun,harga,total_create_akun) VALUES (?,?,?,?,?,?,?,0)", [state.domain, state.auth, state.nama, state.quota, state.ip, state.create, text], () => ctx.reply('✅ Server Berhasil Disimpan.')); delete userState[userId]; return; }`;
    if (!src.includes(old6)) mark('Pilih tipe saat tambah server', false, 'pola add_harga tidak ketemu!');
    else {
        src = src.replace(old6,
            `if (state.step === 'add_harga') { if(isNaN(text)) return ctx.reply('❌ Wajib Angka!'); state.harga = text; state.step = 'add_tipe'; return ctx.reply('Pilih tipe server:', { reply_markup: { inline_keyboard: [[{ text: '🛡️ FighterTunnel', callback_data: 'srvtipe_fightertunnel' }, { text: '🚂 Railway', callback_data: 'srvtipe_railway' }],[{ text: '🛰️ Panel (script sendiri)', callback_data: 'srvtipe_panel' }]] }}); }`);
        mark('Pilih tipe saat tambah server', true);
    }
}
// 6b) Handler tombol pilih tipe (tambah setelah baris bot.action('addserver'...))
if (src.includes("bot.action(/srvtipe_")) mark('Handler tombol srvtipe', false, 'sudah ada');
else {
    const re = /^.*bot\.action\('addserver'.*$/m;
    if (!re.test(src)) mark('Handler tombol srvtipe', false, 'baris addserver tidak ketemu!');
    else {
        src = src.replace(re, m0 => m0 +
            `\n// [adapter] pilih tipe server saat tambah server` +
            `\nbot.action(/srvtipe_(.+)/, (ctx) => {` +
            `\n  const userId = ctx.from.id, st = userState[userId];` +
            `\n  if (!st || st.step !== 'add_tipe') return ctx.answerCbQuery();` +
            `\n  const tipe = ctx.match[1];` +
            `\n  db.run("INSERT INTO Server (domain,auth,nama_server,quota,iplimit,batas_create_akun,harga,total_create_akun,tipe) VALUES (?,?,?,?,?,?,?,?,?)",` +
            `\n    [st.domain, st.auth, st.nama, st.quota, st.ip, st.create, st.harga, 0, tipe],` +
            `\n    () => ctx.editMessageText('✅ Server tersimpan (tipe: ' + tipe + ').').catch(()=>{}));` +
            `\n  delete userState[userId];` +
            `\n  ctx.answerCbQuery();` +
            `\n});`);
        mark('Handler tombol srvtipe', true);
    }
}

// 7) Edit tipe server: tambah ke daftar edit + handler
if (src.includes("'editserver_tipe'")) mark('Tambah editserver_tipe ke daftar', false, 'sudah ada');
else {
    const old7 = "'editserver_total_create_akun', 'deleteserver'";
    if (!src.includes(old7)) mark('Tambah editserver_tipe ke daftar', false, 'daftar editActions tidak ketemu!');
    else {
        src = src.replace(old7, "'editserver_total_create_akun', 'editserver_tipe', 'deleteserver'");
        mark('Tambah editserver_tipe ke daftar', true);
    }
}
if (src.includes('bot.action(/setipe_')) mark('Handler edit tipe server', false, 'sudah ada');
else {
    const re = /^.*bot\.action\(\/deleteserver_.*$/m;
    if (!re.test(src)) mark('Handler edit tipe server', false, 'baris deleteserver tidak ketemu!');
    else {
        src = src.replace(re, m0 => m0 +
            `\n// [adapter] ubah tipe server` +
            `\nbot.action(/editserver_tipe_(\\d+)/, (ctx) => {` +
            `\n  const sid = ctx.match[1];` +
            `\n  ctx.editMessageText('Pilih tipe baru:', { reply_markup: { inline_keyboard: [` +
            `\n    [{ text: '🛡️ FighterTunnel', callback_data: 'setipe_fightertunnel_' + sid },` +
            `\n     { text: '🚂 Railway', callback_data: 'setipe_railway_' + sid }],` +
            `\n    [{ text: '🛰️ Panel (script sendiri)', callback_data: 'setipe_panel_' + sid }],` +
            `\n    [{ text: '🔙 Batal', callback_data: 'admin' }]] }});` +
            `\n});` +
            `\nbot.action(/setipe_(.+)_(\\d+)/, (ctx) => {` +
            `\n  db.run("UPDATE Server SET tipe = ? WHERE id = ?", [ctx.match[1], ctx.match[2]], () => {` +
            `\n    ctx.answerCbQuery('Tipe diperbarui!'); try { sendAdminMenu(ctx); } catch(e){}` +
            `\n  });` +
            `\n});`);
        mark('Handler edit tipe server', true);
    }
}

// 8) Tampilkan tipe di list server (opsional, kosmetik)
if (src.includes('[adapter] label tipe')) mark('Label tipe di list server', false, 'sudah ada');
else {
    const marker = 'txt += `🌐';
    const i = src.indexOf(marker);
    if (i === -1) mark('Label tipe di list server', false, 'pola list tidak ketemu');
    else {
        const eol = src.indexOf('\n', i);
        src = src.slice(0, eol + 1) +
            "                txt += `🏷️ Tipe: ${(require('./modules/server-adapter').TIPE_LABEL[s.tipe]||s.tipe||'FighterTunnel')}\\n`; // [adapter] label tipe\n" +
            src.slice(eol + 1);
        mark('Label tipe di list server', true);
    }
}

// 9) [v2] Tombol "Edit Tipe Server" di menu admin (menu-nya hardcoded)
if (src.includes("callback_data: 'editserver_tipe'") && src.includes('Edit Tipe Server')) {
    mark('Tombol Edit Tipe di menu admin', false, 'sudah ada');
} else {
    const lines = src.split('\n');
    const idx = lines.findIndex(l => l.includes('Total Create') && l.includes('callback_data'));
    if (idx === -1) mark('Tombol Edit Tipe di menu admin', false, 'baris menu tidak ketemu!');
    else {
        const indent = lines[idx].match(/^\s*/)[0];
        lines.splice(idx + 1, 0,
            indent + "[{ text: '🏷️ Edit Tipe Server', callback_data: 'editserver_tipe' }], // [adapter] v2");
        src = lines.join('\n');
        mark('Tombol Edit Tipe di menu admin', true);
    }
}

// 10) [v2] Handler generik editserver_* jangan serobot callback editserver_tipe_<id>
if (src.includes('(?!tipe_)')) mark('Proteksi handler edit tipe', false, 'sudah ada');
else if (!src.includes('bot.action(/editserver_(\\w+)_(\\d+)/')) {
    mark('Proteksi handler edit tipe', false, 'handler generik tidak ketemu!');
} else {
    src = src.split('bot.action(/editserver_(\\w+)_(\\d+)/')
             .join('bot.action(/editserver_((?!tipe_)\\w+)_(\\d+)/');
    mark('Proteksi handler edit tipe', true);
}

if (src === orig) { console.log('\nTidak ada perubahan.'); process.exit(0); }

// backup + tulis
const bak = `${botFile}.bak-${Date.now()}`;
fs.copyFileSync(botFile, bak);
console.log('💾 Backup:', bak);
fs.writeFileSync(botFile, src);

// verifikasi sintaks
try {
    execSync(`node --check ${botFile}`, { stdio: 'pipe' });
    console.log('✅ Sintaks OK');
} catch (e) {
    fs.copyFileSync(bak, botFile);
    console.error('❌ Sintaks GAGAL, file dikembalikan dari backup.');
    process.exit(1);
}

console.log('\n' + changed.join('\n'));
console.log('\nSelesai. Restart bot: pm2 restart <nama>  (atau: systemctl restart <nama>)');
