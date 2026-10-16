#!/usr/bin/env python3
"""Bot Telegram panel VPN — pengganti app.js (Node.js).

Skema database SQLite IDENTIK dengan aslinya:
  CREATE TABLE Server (id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT, auth TEXT)

Alur: /menu -> Create/Delete/Renew/Check -> pilih protokol -> pilih server
      -> isi data -> panggil API :5888 -> tampilkan akun dengan format rapi.

Konfigurasi: /etc/vpn-panel/bot.env berisi:
  BOT_TOKEN=123456:ABC...
  ADMIN_IDS=123456789,987654321
"""
import logging
import os
import shutil
import sqlite3
import subprocess
import tempfile
import urllib.parse
import urllib.request
import json

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import (Application, CallbackQueryHandler, CommandHandler,
                          ContextTypes, ConversationHandler, MessageHandler, filters)

logging.basicConfig(level=logging.WARNING)

API_PORT = 5888
DB_PATH = "/etc/vpn-panel/servers.db"
PROTOS = ["ssh", "vmess", "vless", "trojan", "shadowsocks"]
PROTO_LABEL = {"ssh": "SSH", "vmess": "VMESS", "vless": "VLESS",
               "trojan": "TROJAN", "shadowsocks": "SHADOWSOCKS"}

# states
(ACT, PROTO, SERVER, USERNAME, EXP, QUOTA, IPLIMIT, PASSWORD) = range(8)


def load_env():
    cfg = {}
    try:
        with open("/etc/vpn-panel/bot.env") as f:
            for line in f:
                line = line.strip()
                if line and "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    cfg[k.strip()] = v.strip()
    except OSError:
        pass
    return cfg


ENV = load_env()
ADMIN_IDS = {int(x) for x in ENV.get("ADMIN_IDS", "").split(",") if x.strip().isdigit()}


def db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.execute("CREATE TABLE IF NOT EXISTS Server ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT, auth TEXT)")
    return con


def is_admin(uid):
    return not ADMIN_IDS or uid in ADMIN_IDS


def api_get(domain, path, params):
    qs = urllib.parse.urlencode(params)
    url = f"http://{domain}:{API_PORT}/{path}?{qs}"
    with urllib.request.urlopen(url, timeout=120) as r:
        return json.loads(r.read().decode())


# ---------- menu ----------

def main_menu_kb():
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🍏 Buat Akun", callback_data="act_create"),
         InlineKeyboardButton("🍎 Hapus Akun", callback_data="act_delete")],
        [InlineKeyboardButton("🍊 Perpanjang", callback_data="act_renew"),
         InlineKeyboardButton("🍌 Cek Akun", callback_data="act_check")],
    ])


def proto_kb(act):
    return InlineKeyboardMarkup([
        [InlineKeyboardButton(PROTO_LABEL[p], callback_data=f"proto_{act}_{p}")]
        for p in PROTOS
    ] + [[InlineKeyboardButton("⬅️ Kembali", callback_data="back_menu")]])


def server_kb(act, proto):
    con = db()
    rows = con.execute("SELECT id, domain FROM Server").fetchall()
    con.close()
    if not rows:
        return None
    kb = [[InlineKeyboardButton(dom, callback_data=f"srv_{act}_{proto}_{sid}")]
          for sid, dom in rows]
    kb.append([InlineKeyboardButton("⬅️ Kembali", callback_data="back_menu")])
    return InlineKeyboardMarkup(kb)


async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        await update.message.reply_text("⛔ Bukan admin.")
        return ConversationHandler.END
    await update.message.reply_text(
        "🚀 *Selamat datang di Panel VPN Bot!*\nPilih layanan:\n\n"
        "💾 Backup: /backup\n"
        "♻️ Restore: kirim file `.tar.gz` / `.db` ke chat ini",
        parse_mode="Markdown", reply_markup=main_menu_kb())
    return ACT


async def on_act(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    data = q.data
    if data == "back_menu":
        await q.edit_message_text("🚀 *Panel VPN Bot*\nPilih layanan:",
                                  parse_mode="Markdown", reply_markup=main_menu_kb())
        return ACT
    act = data.split("_", 1)[1]  # create|delete|renew|check
    ctx.user_data["act"] = act
    await q.edit_message_text("Pilih protokol:", reply_markup=proto_kb(act))
    return PROTO


async def on_proto(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    _, act, proto = q.data.split("_", 2)
    ctx.user_data["proto"] = proto
    kb = server_kb(act, proto)
    if kb is None:
        await q.edit_message_text("⚠️ Belum ada server. Tambahkan dulu dengan /addserver")
        return ConversationHandler.END
    await q.edit_message_text("Pilih server:", reply_markup=kb)
    return SERVER


async def on_server(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    await q.answer()
    _, act, proto, sid = q.data.split("_", 3)
    con = db()
    row = con.execute("SELECT domain, auth FROM Server WHERE id=?", (sid,)).fetchone()
    con.close()
    if not row:
        await q.edit_message_text("❌ Server tidak ditemukan.")
        return ConversationHandler.END
    ctx.user_data["domain"], ctx.user_data["auth"] = row
    ctx.user_data["sid"] = sid
    await q.edit_message_text("Masukkan *username* (huruf+angka, tanpa spasi):",
                              parse_mode="Markdown")
    return USERNAME


async def on_username(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    user = update.message.text.strip()
    if not user.isalnum():
        await update.message.reply_text("❌ Username tidak valid. Coba lagi:")
        return USERNAME
    ctx.user_data["username"] = user
    act = ctx.user_data["act"]
    if act in ("delete", "check"):
        return await finish(update, ctx)
    await update.message.reply_text("Masa aktif (hari, mis. 30):")
    return EXP


async def on_exp(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not update.message.text.strip().isdigit():
        await update.message.reply_text("❌ Masukkan angka hari:")
        return EXP
    ctx.user_data["exp"] = update.message.text.strip()
    act = ctx.user_data["act"]
    if act == "renew":
        return await finish(update, ctx)
    if ctx.user_data["proto"] == "ssh":
        await update.message.reply_text("Masukkan *password* akun SSH:",
                                        parse_mode="Markdown")
        return PASSWORD
    await update.message.reply_text("Kuota (GB, 0 = unlimited):")
    return QUOTA


async def on_quota(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    try:
        float(update.message.text.strip())
    except ValueError:
        await update.message.reply_text("❌ Masukkan angka GB:")
        return QUOTA
    ctx.user_data["quota"] = update.message.text.strip()
    await update.message.reply_text("Limit IP (0 = unlimited):")
    return IPLIMIT


async def on_iplimit(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not update.message.text.strip().isdigit():
        await update.message.reply_text("❌ Masukkan angka:")
        return IPLIMIT
    ctx.user_data["iplimit"] = update.message.text.strip()
    return await finish(update, ctx)


async def on_password(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data["password"] = update.message.text.strip()
    await update.message.reply_text("Limit IP (0 = unlimited):")
    return IPLIMIT


async def finish(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    d = ctx.user_data
    act, proto = d["act"], d["proto"]
    msg_obj = update.message or update.callback_query.message
    await msg_obj.reply_text("⏳ Memproses...")
    try:
        if act == "create":
            params = {"user": d["username"], "exp": d["exp"],
                      "iplimit": d.get("iplimit", "0"), "auth": d["auth"]}
            if proto == "ssh":
                params["password"] = d["password"]
            else:
                params["quota"] = d.get("quota", "0")
            res = api_get(d["domain"], f"create{proto}", params)
            text = format_created(proto, res) if res.get("status") == "success" \
                else f"❌ Gagal: {res.get('message')}"
        elif act == "delete":
            res = api_get(d["domain"], f"delete{proto}",
                          {"user": d["username"], "auth": d["auth"]})
            text = f"✅ Akun *{d['username']}* dihapus." if res.get("status") == "success" \
                else f"❌ {res.get('message')}"
        elif act == "renew":
            res = api_get(d["domain"], f"renew{proto}",
                          {"user": d["username"], "exp": d["exp"], "auth": d["auth"]})
            if res.get("status") == "success":
                text = (f"✅ Akun *{d['username']}* diperpanjang.\n"
                        f"Expired baru: `{res['data']['expired']}`")
            else:
                text = f"❌ {res.get('message')}"
        else:  # check
            res = api_get(d["domain"], f"check{proto}",
                          {"user": d["username"], "auth": d["auth"]})
            if res.get("status") == "success":
                dd = res["data"]
                text = (f"🔍 *{d['username']}*\nExpired: `{dd['expired']}`\n"
                        f"Kuota: `{dd.get('quota')}`\nIP limit: `{dd.get('ip_limit')}`")
            else:
                text = f"❌ {res.get('message')}"
    except Exception as e:  # noqa: BLE001
        text = f"❌ Error: {e}"
    await msg_obj.reply_text(text, parse_mode="Markdown",
                             reply_markup=main_menu_kb())
    ctx.user_data.clear()
    return ACT


def format_created(proto, res):
    d = res["data"]
    label = PROTO_LABEL[proto]
    lines = [f"🌟 *AKUN {label} PREMIUM* 🌟", "",
             f"👤 Username: `{d['username']}`",
             f"🌐 Domain: `{d['domain']}`"]
    if proto == "ssh":
        lines += [f"🔑 Password: `{d['password']}`",
                  "🔌 Port: `22, 143, 109`", "📡 SSH-WS: port `80/443` path `/ssh-ws`"]
    else:
        lines += [f"🆔 UUID: `{d['uuid']}`", "🔌 Port TLS: `443`", "🔓 Port non-TLS: `80`"]
        for k in ("vmess_tls_link", "vless_tls_link", "trojan_tls_link",
                  "shadowsocks_tls_link", "vmess_nontls_link",
                  "vless_nontls_link", "trojan_nontls_link",
                  "shadowsocks_nontls_link", "vmess_grpc_link",
                  "vless_grpc_link", "trojan_grpc_link"):
            if k in d:
                lines += ["", f"`{d[k]}`"]
    q = "Unlimited" if d.get("quota") in ("0 GB", "0") else d.get("quota")
    lines += ["", f"📅 Expired: `{d['expired']}`", f"📦 Kuota: `{q}`",
              f"🌍 IP limit: `{d.get('ip_limit')}`"]
    return "\n".join(lines)


async def addserver(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return
    if len(ctx.args) < 2:
        await update.message.reply_text("Pakai: /addserver <domain> <auth>")
        return
    domain, auth = ctx.args[0], ctx.args[1]
    con = db()
    con.execute("INSERT INTO Server (domain, auth) VALUES (?, ?)", (domain, auth))
    con.commit()
    con.close()
    await update.message.reply_text(f"✅ Server `{domain}` ditambahkan.", parse_mode="Markdown")


async def listserver(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return
    con = db()
    rows = con.execute("SELECT id, domain FROM Server").fetchall()
    con.close()
    text = "🖥️ *Daftar server:*\n" + "\n".join(f"`{i}` — {dm}" for i, dm in rows) \
        if rows else "Belum ada server."
    await update.message.reply_text(text, parse_mode="Markdown")


async def cancel(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data.clear()
    await update.message.reply_text("Dibatalkan.", reply_markup=main_menu_kb())
    return ConversationHandler.END


# ---------- backup & restore ----------

DB_FILE_PROTO = {".ssh.db": "ssh", ".vmess.db": "vmess", ".vless.db": "vless",
                 ".trojan.db": "trojan", ".shadowsocks.db": "shadowsocks"}
VPNCTL = "/usr/local/bin/vpnctl"


def vpnctl_json(*args):
    try:
        p = subprocess.run([VPNCTL, *args], capture_output=True,
                           text=True, timeout=300)
        return json.loads(p.stdout.strip().splitlines()[-1])
    except Exception:  # noqa: BLE001
        return None


def resync_report(res):
    if not res or res.get("status") != "success":
        return "\u26a0\ufe0f Resync tidak tuntas, cek manual via `vpnctl resync`."
    lines = []
    for proto in ["ssh", "vmess", "vless", "trojan", "shadowsocks"]:
        d = res["data"].get(proto, {})
        if "error" in d:
            lines.append(f"\u2022 {proto}: \u274c {d['error']}")
        else:
            lines.append(f"\u2022 {proto}: {d.get('total', 0)} akun "
                         f"({d.get('added', 0)} diaktifkan ulang)")
    return "\n".join(lines)


def restore_report(res, fname):
    if not res or res.get("status") != "success":
        return f"\u274c Restore gagal: `{res.get('message') if res else 'tidak ada respon'}`"
    d = res["data"]
    acc = d.get("accounts", {})
    if acc:
        acc_line = ", ".join(f"{p}={c}" for p, c in acc.items())
    else:
        acc_line = ", ".join(f"{p}={d.get(p, '?')}" for p in
                             ("ssh", "vmess", "vless", "trojan", "shadowsocks")
                             if p in d)
    skip_note = ""
    if d.get("skipped"):
        skip_note = f"\n\u26a0\ufe0f {d.get('skipped_total', len(d['skipped']))} file diabaikan."
    pw_note = ""
    if d.get("ssh_password_restored"):
        pw_note = (f"\n\U0001f511 {d['ssh_password_restored']} akun SSH aktif.")
    if d.get("ssh_new_passwords"):
        pw_lines = "\n".join(f"`{u}`: `{pw}`" for u, pw in d["ssh_new_passwords"].items())
        pw_note += (f"\n\n\U0001f50f Password baru (tidak ada di backup):\n{pw_lines}"
                    f"\n_Teruskan ke pelanggan masing-masing._")
    return (f"\u2705 *Restore selesai!*\n\U0001f4e6 Sumber: `{_md_escape(fname)}`\n"
            f"\U0001f6df DB lama diamankan di `{_md_escape(d.get('safety_dir', '-'))}`\n"
            f"\U0001f465 {acc_line}{skip_note}{pw_note}\n\n"
            f"{resync_report({'status': 'success', 'data': d.get('resync', {})})}\n\n"
            f"_Kirim file `.tar.gz` backup atau file `.db` untuk restore._")


async def on_document(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return
    doc = update.message.document
    fname = (doc.file_name or "").strip()
    status = await update.message.reply_text("📥 File diterima, memvalidasi...")
    tmp = tempfile.mkdtemp(prefix="vpn-restore-")
    try:
        tg_file = await ctx.bot.get_file(doc.file_id)
        local = os.path.join(tmp, os.path.basename(fname) or "upload")
        await tg_file.download_to_drive(local)
        if fname.endswith((".tar.gz", ".tgz")):
            text = restore_report(vpnctl_json("restore", local), fname)
        elif fname in DB_FILE_PROTO:
            text = restore_report(
                vpnctl_json("restoredb", DB_FILE_PROTO[fname], local), fname)
        else:
            text = ("❌ Format tidak dikenal.\nKirim file backup `.tar.gz` "
                    "atau file database `.db` (`.vmess.db`, `.vless.db`, "
                    "`.trojan.db`, `.shadowsocks.db`, `.ssh.db`).")
        await status.edit_text(text, parse_mode="Markdown")
    except Exception as e:  # noqa: BLE001
        await status.edit_text(f"❌ Restore gagal: `{e}`", parse_mode="Markdown")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _md_escape(text):
    """Escape karakter spesial Markdown Telegram."""
    for ch in ("_", "*", "[", "]", "(", ")", "~", "`", ">", "#", "+", "-", "=", "|", "{", "}", ".", "!"):
        text = text.replace(ch, "\\" + ch)
    return text


async def backup_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update.effective_user.id):
        return
    await update.message.reply_text("💾 Membuat backup...")
    try:
        p = subprocess.run(["/usr/local/bin/vpn-backup"], capture_output=True,
                           text=True, timeout=300)
        tail = _md_escape("\n".join(p.stdout.strip().splitlines()[-6:]))
        if p.returncode == 0:
            await update.message.reply_text(
                f"✅ *Backup selesai.*\n```\n{tail}\n```\nFile dikirim ke Telegram bila BOT\_TOKEN terisi.",
                parse_mode="Markdown")
        else:
            await update.message.reply_text(f"❌ Backup gagal:\n```\n{tail}\n```",
                                            parse_mode="Markdown")
    except Exception as e:  # noqa: BLE001
        await update.message.reply_text(f"❌ Error: `{e}`", parse_mode="Markdown")


def main():
    token = ENV.get("BOT_TOKEN", "")
    if not token:
        print("BOT_TOKEN belum diisi di /etc/vpn-panel/bot.env")
        raise SystemExit(1)
    app = Application.builder().token(token).build()
    conv = ConversationHandler(
        entry_points=[CommandHandler(["start", "menu"], start)],
        states={
            ACT: [CallbackQueryHandler(on_act, pattern="^(act_|back_menu)")],
            PROTO: [CallbackQueryHandler(on_proto, pattern="^proto_")],
            SERVER: [CallbackQueryHandler(on_server, pattern="^srv_")],
            USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, on_username)],
            EXP: [MessageHandler(filters.TEXT & ~filters.COMMAND, on_exp)],
            QUOTA: [MessageHandler(filters.TEXT & ~filters.COMMAND, on_quota)],
            IPLIMIT: [MessageHandler(filters.TEXT & ~filters.COMMAND, on_iplimit)],
            PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, on_password)],
        },
        fallbacks=[CommandHandler("cancel", cancel),
                   CommandHandler(["start", "menu"], start)],
    )
    app.add_handler(conv)
    app.add_handler(CommandHandler("addserver", addserver))
    app.add_handler(CommandHandler("listserver", listserver))
    app.add_handler(CommandHandler("backup", backup_cmd))
    app.add_handler(MessageHandler(filters.Document.ALL & ~filters.COMMAND,
                                   on_document))
    print("Bot Telegram panel VPN jalan.", flush=True)
    app.run_polling()


if __name__ == "__main__":
    main()
