/**
 * modules/renew-panel.js — pengganti modul renew ter-encrypt (unofficial)
 * Signature PERSIS seperti aslinya, dipanggil dari bot jual-beli (app.js):
 *
 *   const { renewssh, renewvmess, renewvless, renewtrojan } = require('./modules/renew-panel');
 *   await renewssh(username, exp, ip, serverId);
 *   await renewvmess(username, exp, quota, ip, serverId);
 *   await renewvless(username, exp, quota, ip, serverId);
 *   await renewtrojan(username, exp, quota, ip, serverId);
 *
 * - serverId -> lookup domain & auth dari ./sellvpn.db (tabel Server)
 * - request ke panel API: https://domain/api/... (fallback http)
 * - return: string Markdown siap dikirim via ctx.reply(res, {parse_mode:'Markdown'})
 */
const axios = require('axios');
const sqlite3 = require('sqlite3').verbose();

const DB_PATH = './sellvpn.db';
const TIMEOUT = 15000;

function cleanDomain(d) {
  return String(d || '').replace(/^https?:\/\//i, '').replace(/\/.*$/, '').trim();
}

function getServer(serverId) {
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(DB_PATH, sqlite3.OPEN_READONLY, (err) => {
      if (err) return reject(new Error('❌ DB bot tidak ditemukan (./sellvpn.db)'));
      db.get('SELECT domain, auth, nama_server FROM Server WHERE id = ?', [serverId], (err2, row) => {
        db.close();
        if (err2 || !row) return reject(new Error('❌ Server tidak ditemukan.'));
        row.domain = cleanDomain(row.domain);
        if (!row.domain) return reject(new Error('❌ Domain server kosong.'));
        resolve(row);
      });
    });
  });
}

async function apiCall(domain, auth, endpoint, params) {
  const qs = new URLSearchParams({ ...params, auth }).toString();
  const urls = [
    `https://${domain}/api/${endpoint}?${qs}`,
    `http://${domain}/api/${endpoint}?${qs}`,
    `http://${domain}:5888/${endpoint}?${qs}`,
  ];
  let lastErr = null;
  for (const url of urls) {
    try {
      const res = await axios.get(url, { timeout: TIMEOUT });
      return res.data;
    } catch (e) { lastErr = e; }
  }
  throw new Error('❌ Server tidak dapat dijangkau (cek https/http/api port).');
}

function fmtDate(ymd) {
  const bulan = ['Jan','Feb','Mar','Apr','Mei','Jun','Jul','Agu','Sep','Okt','Nov','Des'];
  const p = String(ymd || '').split('-');
  if (p.length !== 3) return ymd;
  return `${parseInt(p[2])} ${bulan[parseInt(p[1]) - 1] || p[1]} ${p[0]}`;
}

async function doRenew(proto, endpoint, params, serverId) {
  const server = await getServer(serverId);
  let res;
  try {
    res = await apiCall(server.domain, server.auth, endpoint, params);
  } catch (e) {
    return e.message;
  }
  if (!res || (res.status !== 'success' && res.status !== true)) {
    return `❌ Gagal: ${res && (res.message || res.error) ? (res.message || res.error) : 'respons tidak valid'}`;
  }
  const d = res.data || {};
  const label = { ssh: 'SSH', vmess: 'VMESS', vless: 'VLESS', trojan: 'TROJAN' }[proto] || proto.toUpperCase();
  return `✅ *${label} BERHASIL DIPERPANJANG*\n` +
    `━━━━━━━━━━━━━━━━━━\n` +
    `👤 Username : \`${d.username || params.user}\`\n` +
    `📅 Expired s/d : \`${fmtDate(d.expired)}\`\n` +
    `━━━━━━━━━━━━━━━━━━`;
}

async function renewssh(username, exp, ip, serverId) {
  return doRenew('ssh', 'renewssh',
    { user: username, exp: String(exp), iplimit: String(ip) }, serverId);
}
async function renewvmess(username, exp, quota, ip, serverId) {
  return doRenew('vmess', 'renewvmess',
    { user: username, exp: String(exp), quota: String(quota), iplimit: String(ip) }, serverId);
}
async function renewvless(username, exp, quota, ip, serverId) {
  return doRenew('vless', 'renewvless',
    { user: username, exp: String(exp), quota: String(quota), iplimit: String(ip) }, serverId);
}
async function renewtrojan(username, exp, quota, ip, serverId) {
  return doRenew('trojan', 'renewtrojan',
    { user: username, exp: String(exp), quota: String(quota), iplimit: String(ip) }, serverId);
}

module.exports = { renewssh, renewvmess, renewvless, renewtrojan };
