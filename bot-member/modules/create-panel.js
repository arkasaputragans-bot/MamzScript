/**
 * modules/create-panel.js — pengganti modul create ter-encrypt (unofficial)
 * Signature PERSIS seperti aslinya, dipanggil dari bot jual-beli (app.js):
 *
 *   const { createssh, createvmess, createvless, createtrojan } = require('./modules/create-panel');
 *   await createssh(username, password, exp, ip, serverId);
 *   await createvmess(username, exp, quota, ip, serverId);
 *   await createvless(username, exp, quota, ip, serverId);
 *   await createtrojan(username, exp, quota, ip, serverId);
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
  // "2026-11-13" -> "13 Nov 2026"
  const bulan = ['Jan','Feb','Mar','Apr','Mei','Jun','Jul','Agu','Sep','Okt','Nov','Des'];
  const p = String(ymd || '').split('-');
  if (p.length !== 3) return ymd;
  return `${parseInt(p[2])} ${bulan[parseInt(p[1]) - 1] || p[1]} ${p[0]}`;
}

function header(proto, d) {
  return `✅ *${proto} BERHASIL DIBUAT*\n` +
    `━━━━━━━━━━━━━━━━━━\n` +
    `👤 Username : \`${d.username}\`\n` +
    `🌐 Domain : \`${d.domain || '-'}\`\n` +
    `📅 Expired : \`${fmtDate(d.expired)}\`\n` +
    `📊 Quota : \`${d.quota || '-'}\`\n` +
    `🔢 Limit IP : \`${d.ip_limit || '-'}\`\n` +
    `━━━━━━━━━━━━━━━━━━\n`;
}

function linkBlock(label, link) {
  if (!link) return '';
  return `*${label}:*\n\`${link}\`\n\n`;
}

async function doCreate(proto, endpoint, params, serverId) {
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
  let msg = header(label, d);
  if (proto === 'ssh') {
    msg += `🔑 Password : \`${d.password}\`\n`;
    msg += `━━━━━━━━━━━━━━━━━━\n`;
    msg += `📌 *Cara pakai:* gunakan aplikasi HTTP Custom / SSH client\n`;
    msg += `Host: \`${d.domain}\` | Port TLS: \`443\` | Port NONTLS: \`80\`\n`;
  } else if (proto === 'vmess') {
    msg += `🆔 UUID : \`${d.uuid}\`\n━━━━━━━━━━━━━━━━━━\n`;
    msg += linkBlock('Link TLS (WS)', d.vmess_tls_link);
    msg += linkBlock('Link NONTLS (WS)', d.vmess_nontls_link);
    msg += linkBlock('Link gRPC', d.vmess_grpc_link);
  } else if (proto === 'vless') {
    msg += `🆔 UUID : \`${d.uuid}\`\n━━━━━━━━━━━━━━━━━━\n`;
    msg += linkBlock('Link TLS (WS)', d.vless_tls_link);
    msg += linkBlock('Link NONTLS (WS)', d.vless_nontls_link);
    msg += linkBlock('Link gRPC', d.vless_grpc_link);
  } else if (proto === 'trojan') {
    msg += `🔑 Password : \`${d.uuid}\`\n━━━━━━━━━━━━━━━━━━\n`;
    msg += linkBlock('Link TLS (WS)', d.trojan_tls_link);
    msg += linkBlock('Link NONTLS (WS)', d.trojan_nontls_link);
    msg += linkBlock('Link gRPC', d.trojan_grpc_link);
  }
  return msg.trim();
}

function trialHeader(proto, d, minutes) {
  return `✅ *${proto} TRIAL BERHASIL DIBUAT*\n` +
    `━━━━━━━━━━━━━━━━━━\n` +
    `👤 Username : \`${d.username}\`\n` +
    `🌐 Domain : \`${d.domain || '-'}\`\n` +
    `⏰ Durasi : \`${minutes} Menit\` (otomatis terhapus)\n` +
    `📊 Quota : \`${d.quota || '-'}\`\n` +
    `🔢 Limit IP : \`${d.ip_limit || '-'}\`\n` +
    `━━━━━━━━━━━━━━━━━━\n`;
}

// Trial berbasis menit via endpoint panel /trial<proto> (auto-hapus di server).
// Panel versi lama (belum ada endpoint trial) -> fallback create biasa exp 1 hari.
async function doTrial(proto, params, serverId, minutes) {
  const server = await getServer(serverId);
  let res;
  try {
    res = await apiCall(server.domain, server.auth, 'trial' + proto, params);
  } catch (e) {
    try {
      if (proto === 'ssh') {
        return await doCreate('ssh', 'createssh',
          { user: params.user, password: params.password, exp: '1', iplimit: params.iplimit }, serverId);
      }
      return await doCreate(proto, 'create' + proto,
        { user: params.user, exp: '1', quota: params.quota, iplimit: params.iplimit }, serverId);
    } catch (e2) { return e.message; }
  }
  if (!res || (res.status !== 'success' && res.status !== true)) {
    return `❌ Gagal: ${res && (res.message || res.error) ? (res.message || res.error) : 'respons tidak valid'}`;
  }
  const d = res.data || {};
  const names = { ssh: 'SSH', vmess: 'VMESS', vless: 'VLESS', trojan: 'TROJAN' };
  let msg = trialHeader(names[proto] || proto.toUpperCase(), d, minutes);
  if (proto === 'ssh') {
    msg += `🔑 Password : \`${d.password || ''}\`\n\n` +
      `💡 *Cara Pakai:*\n` +
      `Isi Hostname dengan domain di atas, Username & Password sesuai akun ini.\n` +
      `Untuk payload/bug SNI gunakan host sesuai operator kamu.\n`;
  } else if (proto === 'vmess') {
    msg += `🆔 UUID : \`${d.uuid || ''}\`\n━━━━━━━━━━━━━━━━━━\n`;
    msg += linkBlock('Link TLS (WS)', d.vmess_tls_link);
    msg += linkBlock('Link NONTLS (WS)', d.vmess_nontls_link);
    msg += linkBlock('Link gRPC', d.vmess_grpc_link);
  } else if (proto === 'vless') {
    msg += `🆔 UUID : \`${d.uuid || ''}\`\n━━━━━━━━━━━━━━━━━━\n`;
    msg += linkBlock('Link TLS (WS)', d.vless_tls_link);
    msg += linkBlock('Link NONTLS (WS)', d.vless_nontls_link);
    msg += linkBlock('Link gRPC', d.vless_grpc_link);
  } else if (proto === 'trojan') {
    msg += `🔑 Password : \`${d.uuid || ''}\`\n━━━━━━━━━━━━━━━━━━\n`;
    msg += linkBlock('Link TLS (WS)', d.trojan_tls_link);
    msg += linkBlock('Link NONTLS (WS)', d.trojan_nontls_link);
    msg += linkBlock('Link gRPC', d.trojan_grpc_link);
  }
  return msg.trim();
}

async function trialssh(username, password, minutes, quota, ip, serverId) {
  return doTrial('ssh',
    { user: username, password: password || '', menit: String(minutes), quota: String(quota), iplimit: String(ip) },
    serverId, minutes);
}

async function trialvmess(username, minutes, quota, ip, serverId) {
  return doTrial('vmess',
    { user: username, menit: String(minutes), quota: String(quota), iplimit: String(ip) },
    serverId, minutes);
}

async function trialvless(username, minutes, quota, ip, serverId) {
  return doTrial('vless',
    { user: username, menit: String(minutes), quota: String(quota), iplimit: String(ip) },
    serverId, minutes);
}

async function trialtrojan(username, minutes, quota, ip, serverId) {
  return doTrial('trojan',
    { user: username, menit: String(minutes), quota: String(quota), iplimit: String(ip) },
    serverId, minutes);
}

async function createssh(username, password, exp, ip, serverId) {
  return doCreate('ssh', 'createssh',
    { user: username, password, exp: String(exp), iplimit: String(ip) }, serverId);
}
async function createvmess(username, exp, quota, ip, serverId) {
  return doCreate('vmess', 'createvmess',
    { user: username, exp: String(exp), quota: String(quota), iplimit: String(ip) }, serverId);
}
async function createvless(username, exp, quota, ip, serverId) {
  return doCreate('vless', 'createvless',
    { user: username, exp: String(exp), quota: String(quota), iplimit: String(ip) }, serverId);
}
async function createtrojan(username, exp, quota, ip, serverId) {
  return doCreate('trojan', 'createtrojan',
    { user: username, exp: String(exp), quota: String(quota), iplimit: String(ip) }, serverId);
}

module.exports = { createssh, createvmess, createvless, createtrojan, trialssh, trialvmess, trialvless, trialtrojan };
