#!/usr/bin/env python3
"""API server panel VPN — pengganti api.js (Node.js).

Listen di 0.0.0.0:5888. Endpoint & format respons dibuat IDENTIK dengan
sistem FighterTunnel agar bot lama bisa dipakai tanpa perubahan.

Auth: query param `auth` harus sama dengan isi /etc/xray/api.key,
jika tidak -> 401 halaman HTML "Akses Ditolak" (persis seperti aslinya).

Endpoint:
  /createssh?user=&password=&exp=&iplimit=&auth=
  /createvmess?user=&exp=&quota=&iplimit=&auth=[&uuid=]
  /createvless?...  /createtrojan?...  /createshadowsocks?...
  (uuid/&password= opsional: UUID custom utk vmess/vless, password custom utk trojan/ss)
  /check<proto>?user=&auth=
  /delete<proto>?user=&auth=
  /renew<proto>?user=&exp=&auth=
  /lock<proto>?user=&auth=    (bekukan akun; data & masa aktif tetap)
  /unlock<proto>?user=&auth=  (aktifkan lagi akun yang di-lock)
"""
import json
import os
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

PORT = 5888
API_KEY_FILE = "/etc/xray/api.key"
VPNCTL = "/usr/local/bin/vpnctl"

PROTOS = ("ssh", "vmess", "vless", "trojan", "shadowsocks")

DENIED_HTML = ('<html><body><h1 style="text-align: center;">Akses Ditolak</h1>'
               '<p style="text-align: center;">Anda tidak memiliki izin untuk '
               'mengakses halaman ini.</p></body></html>')


def read_key():
    try:
        with open(API_KEY_FILE) as f:
            return f.read().strip()
    except OSError:
        return ""


def read_meta(name):
    try:
        with open(f"/etc/xray/{name}") as f:
            return f.read().strip()
    except OSError:
        return ""


def vpnctl(*args):
    p = subprocess.run([VPNCTL, *args], capture_output=True, text=True, timeout=120)
    try:
        return json.loads(p.stdout.strip().splitlines()[-1])
    except (IndexError, ValueError):
        return {"status": "error", "message": p.stderr.strip() or "vpnctl gagal"}


def enrich(data):
    """Tambahkan field domain/ns_domain/city/pubkey seperti API asli."""
    data.setdefault("domain", read_meta("domain"))
    data.setdefault("ns_domain", read_meta("ns_domain"))
    data.setdefault("city", read_meta("city"))
    data.setdefault("pubkey", read_meta("pubkey"))
    return data


class Handler(BaseHTTPRequestHandler):
    timeout = 30  # koneksi nggantung dibuang dlm 30s — jangan sampai memblokir API
    server_version = "VPNPanel/1.0"

    def log_message(self, fmt, *args):
        pass  # diam, biar log systemd bersih

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _deny(self):
        body = DENIED_HTML.encode()
        self.send_response(401)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if q.get("auth", "") != read_key():
            return self._deny()

        path = u.path.strip("/")
        # Dukung akses via https://domain/api/<endpoint> (xray fallback
        # meneruskan path apa adanya tanpa strip prefix).
        if path == "api" or path.startswith("api/"):
            path = path[3:].strip("/")
        if path == "status":
            return self.handle_status()
        if path == "servers":
            return self.handle_servers("list", q)
        if path == "addserver":
            return self.handle_servers("add", q)
        if path == "delserver":
            return self.handle_servers("del", q)
        # --- CREATE ---
        for proto in PROTOS:
            if path == f"list{proto}":
                res = vpnctl("list", proto)
                code = 200 if res.get("status") == "success" else 500
                return self._send(code, res)
            if path == f"create{proto}":
                return self.handle_create(proto, q)
            if path == f"trial{proto}":
                return self.handle_trial(proto, q)
            if path == f"check{proto}":
                return self.handle_simple("check", proto, q)
            if path == f"delete{proto}":
                return self.handle_simple("delete", proto, q)
            if path == f"renew{proto}":
                return self.handle_simple("renew", proto, q)
            if path == f"lock{proto}":
                return self.handle_simple("suspend", proto, q)
            if path == f"unlock{proto}":
                return self.handle_simple("unsuspend", proto, q)
        self._send(404, {"status": "error", "message": "unknown endpoint"})

    def handle_servers(self, action, q):
        """Kelola DB Server (skema identik: id, domain, auth)."""
        import sqlite3
        db_path = "/etc/vpn-panel/servers.db"
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        con = sqlite3.connect(db_path)
        con.execute("CREATE TABLE IF NOT EXISTS Server ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT, auth TEXT)")
        if action == "list":
            rows = con.execute("SELECT id, domain FROM Server").fetchall()
            con.close()
            return self._send(200, {"status": "success",
                                    "data": [{"id": i, "domain": d} for i, d in rows]})
        if action == "add":
            domain, auth = q.get("domain", ""), q.get("auth", "")
            if not domain or not auth:
                con.close()
                return self._send(400, {"status": "error",
                                        "message": "domain & auth diperlukan"})
            con.execute("INSERT INTO Server (domain, auth) VALUES (?, ?)", (domain, auth))
            con.commit()
            con.close()
            return self._send(200, {"status": "success", "message": "Server ditambahkan"})
        if action == "del":
            sid = q.get("id", "")
            con.execute("DELETE FROM Server WHERE id=?", (sid,))
            con.commit()
            con.close()
            return self._send(200, {"status": "success", "message": "Server dihapus"})
        con.close()
        return self._send(400, {"status": "error", "message": "unknown action"})

    def handle_status(self):
        """Ringkasan untuk dashboard: status service + jumlah akun per protokol."""
        import subprocess as sp
        services = {}
        for s in ["xray@edge", "xray@vmess", "xray@vless", "xray@trojan",
                  "xray@shadowsocks", "haproxy", "nginx", "dropbear",
                  "vpn-ws", "panel-api", "vpn-quota"]:
            try:
                r = sp.run(["systemctl", "is-active", s],
                           capture_output=True, text=True, timeout=5)
                services[s] = r.stdout.strip()
            except Exception:
                services[s] = "unknown"
        accounts = {}
        for proto in PROTOS:
            try:
                res = vpnctl("list", proto)
                accounts[proto] = len(res.get("data", [])) if res.get("status") == "success" else -1
            except Exception:
                accounts[proto] = -1
        # "status": true (boolean) agar kompatibel dengan bot member
        # yang mengecek res.data.status === true
        return self._send(200, {"status": True,
                                "data": {"services": services, "accounts": accounts}})

    def handle_create(self, proto, q):
        user = q.get("user", "")
        exp = q.get("exp", "")
        iplimit = q.get("iplimit", "0")
        if proto == "ssh":
            password = q.get("password", "")
            if not user or not password or not exp:
                return self._send(400, {"error": "Username, expiry, iplimit, dan password diperlukan"})
            res = vpnctl("create", "ssh", user, exp, "0", iplimit, password)
            if res.get("status") == "success":
                d = enrich(res["data"])
                return self._send(200, {"status": "success",
                                        "message": "SSH account successfully created",
                                        "data": d})
            return self._send(500, {"status": "error", "message": res.get("message")})
        quota = q.get("quota", "0")
        if not user or not exp:
            return self._send(400, {"error": "Username, expiry, quota, dan iplimit diperlukan"})
        custom = q.get("uuid", "") or q.get("password", "")
        args = ["create", proto, user, exp, quota, iplimit]
        if custom:
            args.append(custom)
        res = vpnctl(*args)
        if res.get("status") == "success":
            d = enrich(res["data"])
            names = {"vmess": "Vmess", "vless": "Vless",
                     "trojan": "Trojan", "shadowsocks": "Shadowsocks"}
            return self._send(200, {"status": "success",
                                    "message": f"{names[proto]} account successfully created",
                                    "data": d})
        return self._send(500, {"status": "error", "message": res.get("message")})

    def handle_trial(self, proto, q):
        user = q.get("user", "")
        if not user:
            return self._send(400, {"error": "Username diperlukan"})
        try:
            m = int(q.get("menit", "60"))
        except ValueError:
            return self._send(400, {"error": "menit harus angka"})
        if m < 1 or m > 1440:
            return self._send(400, {"error": "menit harus 1-1440"})
        quota = q.get("quota", "1")
        iplimit = q.get("iplimit", "1")
        args = ["trial", proto, user, str(m), quota, iplimit]
        custom = q.get("password", "") or q.get("uuid", "")
        if custom:
            args.append(custom)
        res = vpnctl(*args)
        if res.get("status") == "success":
            d = enrich(res.get("data", {}))
            out = {"status": "success",
                   "message": res.get("message") or f"Trial {proto} {m} menit dibuat",
                   "data": d, "trial_minutes": m}
            if res.get("trial_warning"):
                out["trial_warning"] = res["trial_warning"]
            return self._send(200, out)
        return self._send(500, {"status": "error", "message": res.get("message")})

    def handle_simple(self, action, proto, q):
        user = q.get("user", "")
        if not user:
            return self._send(400, {"error": "Username diperlukan"})
        args = [action, proto, user]
        if action == "renew":
            if not q.get("exp"):
                return self._send(400, {"error": "exp diperlukan"})
            args.append(q["exp"])
        res = vpnctl(*args)
        code = 200 if res.get("status") == "success" else 500
        return self._send(code, res)


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    srv.daemon_threads = True
    print(f"VPN panel API listening on :{PORT}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
