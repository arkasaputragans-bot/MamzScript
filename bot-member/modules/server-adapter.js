/**
 * server-adapter.js — Dispatcher: 1 bot jual-beli untuk banyak jenis server.
 *
 * Tipe server yang didukung (kolom `tipe` di tabel Server):
 *   - "fightertunnel" : modul lama (./create, ./renew) — JANGAN DIHAPUS/DIGANTI
 *   - "railway"       : modul ./railway
 *   - "panel"         : modul ./create-panel & ./renew-panel (script panel sendiri)
 *
 * Cara pakai di app.js:
 *   const adapter = require('./modules/server-adapter');
 *   const res = await adapter.createAccount(server.tipe, state.type,
 *       { username, password, exp, quota, ip, serverId, server });
 *   const res2 = await adapter.renewAccount(server.tipe, state.type,
 *       { username, exp, quota, ip, serverId, server });
 *   const online = await adapter.checkStatus(server);
 *
 * Semua fungsi me-LEMpar Error bila gagal, jadi bungkus dengan try/catch.
 * Pesan error selalu diawali "❌" sehingga aman ditampilkan ke user.
 */
'use strict';

const axios = require('axios');
const net = require('net');

const TIPE_LABEL = {
    fightertunnel: 'FighterTunnel',
    railway: 'Railway',
    panel: 'Panel',
};

function normTipe(t) {
    t = String(t || 'fightertunnel').toLowerCase().trim();
    return TIPE_LABEL[t] ? t : 'fightertunnel';
}

// Lazy require: modul yang tidak dipakai tidak ikut di-load
// (mis. bot tanpa railway.js tetap jalan untuk tipe lain).
function loadMod(tipe, kind) {
    if (tipe === 'railway') return require('./railway');
    if (tipe === 'panel') return require(kind === 'create' ? './create-panel' : './renew-panel');
    return require(kind === 'create' ? './create' : './renew'); // fightertunnel (default)
}

const CREATE_KEY = { ssh: 'createssh', vmess: 'createvmess', vless: 'createvless', trojan: 'createtrojan' };
const RENEW_KEY  = { ssh: 'renewssh',  vmess: 'renewvmess',  vless: 'renewvless',  trojan: 'renewtrojan' };

// Normalisasi hasil modul: string error "❌..." atau kosong => throw,
// sehingga saldo TIDAK terpotong untuk transaksi yang gagal.
async function runChecked(fn, args) {
    let res;
    try {
        res = await fn(...args);
    } catch (e) {
        throw new Error('❌ ' + (e && e.message ? e.message.replace(/^❌\s*/, '') : 'Gagal menghubungi server.'));
    }
    if (typeof res === 'string' && res.trim().startsWith('❌')) throw new Error(res.trim());
    if (res === null || res === undefined || res === '' || res === false) {
        throw new Error('❌ Gagal: server tidak merespon.');
    }
    return res;
}

async function createAccount(tipe, proto, o) {
    tipe = normTipe(tipe);
    proto = String(proto || '').toLowerCase();
    if (tipe === 'railway') {
        const rw = loadMod('railway');
        if (typeof rw.createRailwayAccount !== 'function') throw new Error('❌ Modul railway tidak tersedia.');
        return runChecked(rw.createRailwayAccount, [o.server.domain, o.server.auth, o.username, o.exp, proto]);
    }
    const key = CREATE_KEY[proto];
    if (!key) throw new Error('❌ Protokol tidak didukung: ' + proto);
    const mod = loadMod(tipe, 'create');
    const fn = mod[key];
    if (typeof fn !== 'function') throw new Error('❌ Modul tipe ' + tipe + ' tidak punya fungsi ' + key + '.');
    const args = proto === 'ssh'
        ? [o.username, o.password, o.exp, o.ip, o.serverId]
        : [o.username, o.exp, o.quota, o.ip, o.serverId];
    return runChecked(fn, args);
}

async function renewAccount(tipe, proto, o) {
    tipe = normTipe(tipe);
    proto = String(proto || '').toLowerCase();
    if (tipe === 'railway') {
        const rw = loadMod('railway');
        if (typeof rw.renewRailwayAccount !== 'function') throw new Error('❌ Modul railway tidak tersedia.');
        return runChecked(rw.renewRailwayAccount, [o.server.domain, o.server.auth, o.username, o.exp]);
    }
    const key = RENEW_KEY[proto];
    if (!key) throw new Error('❌ Protokol tidak didukung: ' + proto);
    const mod = loadMod(tipe, 'renew');
    const fn = mod[key];
    if (typeof fn !== 'function') throw new Error('❌ Modul tipe ' + tipe + ' tidak punya fungsi ' + key + '.');
    const args = proto === 'ssh'
        ? [o.username, o.exp, o.ip, o.serverId]
        : [o.username, o.exp, o.quota, o.ip, o.serverId];
    return runChecked(fn, args);
}

function cleanDomain(d) {
    return String(d || '').replace(/^https?:\/\//i, '').replace(/\/.*$/, '').trim();
}

// Cek status per tipe server:
//  - panel         : http://domain/api/status?auth=KEY (API panel butuh auth)
//  - lainnya       : https://domain/api/status (tanpa auth, cocok FighterTunnel/Railway)
//  - fallback akhir: port 22 terbuka
async function checkStatus(server) {
    const domain = cleanDomain(server && server.domain);
    if (!domain) return false;
    const tipe = normTipe(server && server.tipe);

    if (tipe === 'panel' && server.auth) {
        try {
            const res = await axios.get(
                'http://' + domain + '/api/status?auth=' + encodeURIComponent(server.auth),
                { timeout: 6000 });
            if (res.data && (res.data.status === true || res.data.status === 'success')) return true;
        } catch (e) { /* lanjut ke cek berikutnya */ }
    }
    try {
        const res = await axios.get('https://' + domain + '/api/status', { timeout: 4000 });
        if (res.data && res.data.status === true) return true;
    } catch (e) { /* lanjut ke fallback port 22 */ }

    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(2500);
        socket.connect(22, domain, () => { socket.destroy(); resolve(true); });
        socket.on('error', () => { socket.destroy(); resolve(false); });
        socket.on('timeout', () => { socket.destroy(); resolve(false); });
    });
}

module.exports = { createAccount, renewAccount, checkStatus, TIPE_LABEL, normTipe };
