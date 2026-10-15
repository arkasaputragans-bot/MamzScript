/* Panel VPN - web admin UI (vanilla JS, memanggil API :5888) */
const PROTOS = ["vmess", "vless", "trojan", "shadowsocks", "ssh"];
const LABEL = { vmess:"VMess", vless:"VLESS", trojan:"Trojan",
                shadowsocks:"Shadowsocks", ssh:"SSH" };
let apiHost = "", apiKey = "", curProto = "vmess";

const $ = id => document.getElementById(id);
const toast = m => { const t=$("toast"); t.textContent=m; t.classList.remove("hidden");
  setTimeout(()=>t.classList.add("hidden"), 2500); };

async function api(path, params={}) {
  params.auth = apiKey;
  const qs = new URLSearchParams(params).toString();
  let url;
  if (apiHost.includes("/")) {
    // format "host/prefix" mis. "1.2.3.4/api" -> http://1.2.3.4/api/<path>
    const i = apiHost.indexOf("/");
    const h = apiHost.slice(0, i), pre = apiHost.slice(i + 1).replace(/\/+$/, "");
    url = `http://${h}/${pre}/${path}?${qs}`;
  } else {
    url = `http://${apiHost}/${path}?${qs}`;
  }
  const r = await fetch(url);
  if (!r.ok && r.status === 401) throw new Error("API key salah / tidak punya akses");
  return r.json();
}

/* ---------- login ---------- */
$("btn-login").onclick = async () => {
  apiHost = $("api-host").value.trim();
  apiKey = $("api-key").value.trim();
  if (!apiHost || !apiKey) { $("login-err").textContent = "Isi host dan API key."; return; }
  try {
    const r = await api("status");
    if (r.status !== "success" && r.status !== true) throw new Error(r.message || "gagal");
    sessionStorage.setItem("vpn_host", apiHost);
    sessionStorage.setItem("vpn_key", apiKey);
    $("login-view").classList.add("hidden");
    $("app-view").classList.remove("hidden");
    loadDashboard(); loadAccounts(); loadServers();
  } catch(e) { $("login-err").textContent = "Gagal konek: " + e.message; }
};
$("btn-logout").onclick = () => location.reload();
(function init(){
  const h = sessionStorage.getItem("vpn_host"), k = sessionStorage.getItem("vpn_key");
  if (h && k) { $("api-host").value=h; $("api-key").value=k; }
  else { $("api-host").value = location.hostname + "/api"; }
})();

/* ---------- tabs ---------- */
document.querySelectorAll(".tab[data-tab]").forEach(b => b.onclick = () => {
  document.querySelectorAll(".tab[data-tab]").forEach(x=>x.classList.remove("active"));
  b.classList.add("active");
  document.querySelectorAll(".tabpane").forEach(p=>p.classList.add("hidden"));
  $("tab-"+b.dataset.tab).classList.remove("hidden");
});

/* ---------- dashboard ---------- */
async function loadDashboard() {
  try {
    const r = await api("status");
    const d = r.data;
    $("svc-grid").innerHTML = Object.entries(d.services).map(([s,st]) =>
      `<div class="cell"><span class="dot ${st==="active"?"on":"off"}"></span>${s}<b>${st}</b></div>`).join("");
    $("acct-grid").innerHTML = PROTOS.map(p =>
      `<div class="cell">${LABEL[p]}<b>${d.accounts[p] ?? "?"}</b></div>`).join("");
  } catch(e) { toast("Dashboard: "+e.message); }
}

/* ---------- akun ---------- */
$("proto-pills").innerHTML = PROTOS.map(p =>
  `<button class="pill ${p===curProto?"active":""}" data-p="${p}">${LABEL[p]}</button>`).join("");
document.querySelectorAll("#proto-pills .pill").forEach(b => b.onclick = () => {
  document.querySelectorAll("#proto-pills .pill").forEach(x=>x.classList.remove("active"));
  b.classList.add("active"); curProto = b.dataset.p; loadAccounts();
});

let acctCache = [];
async function loadAccounts() {
  try {
    const r = await api("list"+curProto);
    acctCache = r.data || [];
    renderAccounts();
  } catch(e) { toast("Akun: "+e.message); }
}
function renderAccounts() {
  const q = ($("acct-search").value || "").toLowerCase();
  const rows = acctCache.filter(a => a.username.toLowerCase().includes(q));
  $("acct-count").textContent = `${rows.length} akun`;
  $("acct-body").innerHTML = rows.map(a =>
    `<tr><td><code>${a.username}</code></td><td>${a.expired}</td><td class="acts">
      <button class="btn sm" onclick="detailAcct('${a.username}')">Detail / Copy</button>
      <button class="btn sm" onclick="renewAcct('${a.username}')">Perpanjang</button>
      <button class="btn sm danger" onclick="delAcct('${a.username}')">Hapus</button>
    </td></tr>`).join("") || `<tr><td colspan="3">Belum ada akun.</td></tr>`;
}

/* ---------- detail akun + copy link ---------- */
const LINK_LABEL = { tls:"WS TLS", nontls:"WS Non-TLS", grpc:"gRPC" };
const esc = s => String(s ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;")
  .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
let lastDetail = null;

async function copyText(t, label) {
  try { await navigator.clipboard.writeText(t); }
  catch(e) {
    const ta = document.createElement("textarea");
    ta.value = t; document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); } catch(_){}
    ta.remove();
  }
  toast((label || "Disalin") + " ✓");
}

function detailLinks(d, proto) {
  return Object.keys(d).filter(k => k.endsWith("_link")).map(k => {
    const variant = k.slice(proto.length + 1, -5);
    return { label: `${LABEL[proto]} · ${LINK_LABEL[variant] || variant}`, link: d[k] };
  });
}
function sshRows(d) {
  return [["Host", d.domain], ["Port SSH", "22"], ["Port WS", "80"],
          ["Username", d.username], ["Password", d.password || "-"]];
}
function buildCopyAll(d, proto) {
  if (proto === "ssh")
    return sshRows(d).map(([l,v]) => `${l}: ${v}`).join("\n");
  const head = [`${d.username} (${LABEL[proto]})`, `Expired: ${d.expired}`, ""];
  const body = detailLinks(d, proto).flatMap(({label, link}) => [`[${label}]`, link, ""]);
  return head.concat(body).join("\n").trim();
}
function detailHTML(d, proto) {
  const info = `<div class="info-grid">
      <div><span>Username</span><b>${esc(d.username)}</b></div>
      <div><span>Expired</span><b>${esc(d.expired)}</b></div>
      <div><span>Kuota</span><b>${esc(d.quota)}</b></div>
      <div><span>IP Limit</span><b>${esc(d.ip_limit)}</b></div>
      <div><span>Domain</span><b>${esc(d.domain)}</b></div>
    </div>`;
  let rows;
  if (proto === "ssh") {
    rows = sshRows(d).map(([l, v], i) =>
      `<div class="link-row"><span class="link-label">${esc(l)}</span>
       <code class="link-text">${esc(v)}</code>
       <button class="btn sm" data-cp="ssh:${i}">Copy</button></div>`).join("");
  } else {
    rows = detailLinks(d, proto).map(({label, link}, i) =>
      `<div class="link-row"><span class="link-label">${esc(label)}</span>
       <code class="link-text" title="${esc(link)}">${esc(link)}</code>
       <button class="btn sm" data-cp="link:${i}">Copy</button></div>`).join("")
       || `<p class="muted">Tidak ada link.</p>`;
  }
  return info + rows +
    `<button class="btn primary wide" data-cp="all">📋 Copy Semua</button>`;
}
$("modal-fields").addEventListener("click", e => {
  const b = e.target.closest("[data-cp]");
  if (!b || !lastDetail) return;
  const { d, proto } = lastDetail, k = b.dataset.cp;
  if (k === "all") copyText(buildCopyAll(d, proto), "Semua disalin");
  else if (k.startsWith("link:")) copyText(detailLinks(d, proto)[+k.slice(5)].link, "Link disalin");
  else if (k.startsWith("ssh:")) copyText(sshRows(d)[+k.slice(4)][1], "Disalin");
});
function openDetailModal(d, proto) {
  lastDetail = { d, proto };
  $("modal-card").classList.add("wide");
  openModal(`Akun ${d.username} (${LABEL[proto]})`, detailHTML(d, proto), null);
}
function openModal(title, html, onOk) {
  $("modal-title").textContent = title;
  $("modal-fields").innerHTML = html;
  $("modal").classList.remove("hidden");
  $("modal-ok").style.display = onOk ? "" : "none";
  $("modal-ok").onclick = onOk || (()=>{});
}
function closeModal(){
  $("modal").classList.add("hidden");
  $("modal-card").classList.remove("wide");
  lastDetail = null;
}

async function detailAcct(u) {
  try {
    const r = await api("check"+curProto, {user:u});
    if (r.status !== "success") { toast(r.message || "Gagal"); return; }
    openDetailModal(r.data, curProto);
  } catch(e) { toast(e.message); }
}
async function delAcct(u) {
  if (!confirm(`Hapus akun ${u}?`)) return;
  try { const r = await api("delete"+curProto,{user:u});
    toast(r.status==="success" ? "Terhapus." : r.message); loadAccounts(); loadDashboard();
  } catch(e) { toast(e.message); }
}
async function renewAcct(u) {
  const days = prompt(`Perpanjang ${u} berapa hari?`, "30");
  if (!days) return;
  try { const r = await api("renew"+curProto,{user:u,exp:days});
    toast(r.status==="success" ? "Diperpanjang s/d "+r.data.expired : r.message);
    loadAccounts();
  } catch(e) { toast(e.message); }
}

/* ---------- modal buat akun ---------- */
$("btn-create").onclick = () => {
  const isSsh = curProto === "ssh";
  const fields = `
    <label>Username<input id="f-user"></label>
    <label>Masa aktif (hari)<input id="f-exp" value="30"></label>
    ${isSsh ? `<label>Password<input id="f-pass"></label>`
            : `<label>Kuota (GB, 0=unlimited)<input id="f-quota" value="0"></label>`}
    <label>Limit IP (0=unlimited)<input id="f-ip" value="0"></label>`;
  openModal("Buat Akun "+LABEL[curProto], fields, async () => {
    const p = { user:$("f-user").value.trim(), exp:$("f-exp").value.trim(),
                iplimit:$("f-ip").value.trim() };
    if (isSsh) p.password = $("f-pass").value.trim(); else p.quota = $("f-quota").value.trim();
    if (!p.user) { toast("Username wajib diisi"); return; }
    try {
      const r = await api("create"+curProto, p);
      if (r.status==="success") {
        closeModal(); toast("Akun dibuat.");
        openDetailModal(r.data, curProto);
        loadAccounts(); loadDashboard();
      } else toast("Gagal: "+r.message);
    } catch(e) { toast(e.message); }
  });
};
/* (openModal & closeModal didefinisikan di bagian detail akun) */
$("modal-cancel").onclick = closeModal;
$("modal").onclick = e => { if (e.target.id==="modal") closeModal(); };

/* ---------- server ---------- */
async function loadServers() {
  try {
    const r = await api("servers");
    $("srv-body").innerHTML = (r.data||[]).map(s =>
      `<tr><td>${s.id}</td><td><code>${s.domain}</code></td><td>
        <button class="btn sm danger" onclick="delSrv(${s.id})">Hapus</button></td></tr>`
      ).join("") || `<tr><td colspan="3">Belum ada server.</td></tr>`;
  } catch(e) { toast("Server: "+e.message); }
}
async function delSrv(id) {
  if (!confirm("Hapus server ini?")) return;
  try { await api("delserver",{id}); toast("Dihapus."); loadServers(); }
  catch(e) { toast(e.message); }
}
$("btn-addsrv").onclick = async () => {
  const domain=$("srv-domain").value.trim(), auth=$("srv-auth").value.trim();
  if (!domain||!auth) { toast("Isi domain & auth"); return; }
  try { const r = await api("addserver",{domain,auth});
    toast(r.status==="success"?"Ditambahkan.":r.message);
    $("srv-domain").value=""; $("srv-auth").value=""; loadServers();
  } catch(e) { toast(e.message); }
};
