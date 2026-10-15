#!/usr/bin/env python3
"""vpn-quota - enforcement kuota & masa berlaku akun (pengganti limitquota).

Loop tiap 60 detik:
  - Baca traffic per user via `xray api stats`, akumulasi di
    /var/lib/vpn-panel/usage.json (karena counter xray reset saat restart).
  - Jika pemakaian >= kuota (dan kuota > 0) -> vpnctl suspend.
  - Tiap 1 jam: hapus akun yang sudah expired via vpnctl delete.
"""
import json
import os
import re
import subprocess
import sys
import time
from datetime import date

import importlib.util
from importlib.machinery import SourceFileLoader

_loader = SourceFileLoader("vpnctl", "/usr/local/bin/vpnctl")
_spec = importlib.util.spec_from_loader("vpnctl", _loader)
_vpnctl = importlib.util.module_from_spec(_spec)
_loader.exec_module(_vpnctl)

PROTOS = _vpnctl.PROTOS
API_PORT = _vpnctl.API_PORT
db_read = _vpnctl.db_read
meta_read = _vpnctl.meta_read
do_suspend = _vpnctl.do_suspend
do_delete = _vpnctl.do_delete
META_DIR = _vpnctl.META_DIR

STATE_FILE = "/var/lib/vpn-panel/usage.json"
LOOP_SEC = 60


def xray_stat(port, name):
    try:
        p = subprocess.run(
            ["/usr/local/bin/xray", "api", "stats",
             f"--server=127.0.0.1:{port}", "-name", name],
            capture_output=True, text=True, timeout=15)
        m = re.search(r'value:\s*"(\d+)"', p.stdout)
        return int(m.group(1)) if m else 0
    except Exception:
        return 0


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(state):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


def suspended(proto, user):
    return os.path.exists(os.path.join(META_DIR[proto], user + ".suspended"))


def check_quota(state):
    changed = False
    for proto in PROTOS:
        if proto == "ssh" or proto not in API_PORT:
            continue
        port = API_PORT[proto]
        for user, (_exp, _secret) in db_read(proto).items():
            if suspended(proto, user):
                continue
            quota_b, _ip = meta_read(proto, user)
            try:
                quota_b = int(quota_b)
            except ValueError:
                quota_b = 0
            if quota_b <= 0:
                continue
            up = xray_stat(port, f"user>>>{user}>>>traffic>>>uplink")
            down = xray_stat(port, f"user>>>{user}>>>traffic>>>downlink")
            key = f"{proto}/{user}"
            prev = state.get(key, {})
            # akumulasi: counter xray bisa reset -> pakai max(prev_total, prev+delta)
            prev_up, prev_down = prev.get("up", 0), prev.get("down", 0)
            total_up = prev_up + max(0, up - prev.get("cur_up", 0))
            total_down = prev_down + max(0, down - prev.get("cur_down", 0))
            state[key] = {"up": total_up, "down": total_down,
                          "cur_up": up, "cur_down": down}
            changed = True
            if total_up + total_down >= quota_b:
                print(f"[quota] {proto}/{user} habis "
                      f"({total_up + total_down}/{quota_b}), suspend", flush=True)
                do_suspend(proto, user)
    if changed:
        save_state(state)


def check_expiry():
    today = date.today().isoformat()
    for proto in PROTOS:
        for user, (exp, _secret) in db_read(proto).items():
            if exp < today:
                print(f"[expiry] {proto}/{user} expired {exp}, hapus", flush=True)
                do_delete(proto, user)


def main():
    print("vpn-quota jalan.", flush=True)
    last_expiry = 0
    while True:
        try:
            check_quota(load_state())
            if time.time() - last_expiry > 3600:
                check_expiry()
                last_expiry = time.time()
        except Exception as e:  # noqa: BLE001
            print(f"[error] {e}", flush=True)
        time.sleep(LOOP_SEC)


if __name__ == "__main__":
    main()
