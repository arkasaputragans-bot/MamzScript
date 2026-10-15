#!/usr/bin/env python3
"""SSH over WebSocket proxy untuk panel VPN.

Alur: haproxy :80 (path /ssh-ws) -> 127.0.0.1:10020 (script ini) -> 127.0.0.1:22 (OpenSSH)
Menangani handshake HTTP Upgrade dan framing WebSocket minimal (RFC 6455).
"""
import socket
import threading
import base64
import hashlib
import struct
import select

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 10020
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 22
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data


def read_ws_frame(sock):
    """Baca satu frame WebSocket dari client, kembalikan (opcode, payload)."""
    hdr = recv_exact(sock, 2)
    b1, b2 = hdr[0], hdr[1]
    opcode = b1 & 0x0F
    masked = (b2 & 0x80) != 0
    length = b2 & 0x7F
    if length == 126:
        length = struct.unpack(">H", recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack(">Q", recv_exact(sock, 8))[0]
    mask = recv_exact(sock, 4) if masked else None
    payload = recv_exact(sock, length) if length else b""
    if masked and mask:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return opcode, payload


def send_ws_frame(sock, payload, opcode=0x2):
    """Kirim satu frame WebSocket ke client (tanpa mask, sesuai RFC)."""
    header = bytes([0x80 | opcode])
    n = len(payload)
    if n < 126:
        header += bytes([n])
    elif n < 65536:
        header += bytes([126]) + struct.pack(">H", n)
    else:
        header += bytes([127]) + struct.pack(">Q", n)
    sock.sendall(header + payload)


def ws_to_ssh(client):
    # --- handshake HTTP Upgrade ---
    # Kompatibel FighterTunnel & payload bug-host/split: baca request secukupnya
    # (jangan blokir lama), lalu SELALU jawab 101 seperti proxy FT.
    # Alasan: payload bug-host mengirim request decoy dulu (tanpa header Upgrade)
    # baru request WS-nya secara pipelining; proxy HTTP di depan (nginx/haproxy)
    # hanya meneruskan request pertama. Validasi ketat = 400 = klien gagal konek.
    req = b""
    client.settimeout(2)
    try:
        while b"\r\n\r\n" not in req:
            chunk = client.recv(4096)
            if not chunk:
                break
            req += chunk
            if len(req) > 16384:
                break
    except (socket.timeout, OSError):
        pass
    client.settimeout(None)
    # Cari key kalau ada (biar accept valid), kalau tidak pakai dummy.
    key = None
    for line in req.decode("latin1").split("\r\n"):
        if line.lower().startswith("sec-websocket-key:"):
            key = line.split(":", 1)[1].strip()
            break
    if not key:
        key = "dGhlIHNhbXBsZSBub25jZQ=="  # dummy ala FighterTunnel
    accept = base64.b64encode(
        hashlib.sha1((key + GUID).encode()).digest()
    ).decode()
    client.sendall(
        ("HTTP/1.1 101 Switching Protocols\r\n"
         "Upgrade: websocket\r\n"
         "Connection: Upgrade\r\n"
         f"Sec-WebSocket-Accept: {accept}\r\n\r\n").encode()
    )

    target = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=10)
    target.setblocking(False)
    client.setblocking(False)

    try:
        while True:
            r, _, _ = select.select([client, target], [], [], 300)
            if not r:
                break
            if client in r:
                try:
                    opcode, payload = read_ws_frame(client)
                except ConnectionError:
                    break
                if opcode == 0x8:  # close
                    break
                elif opcode == 0x9:  # ping -> pong
                    send_ws_frame(client, payload, opcode=0xA)
                elif opcode in (0x1, 0x2, 0x0):  # text/binary/continuation
                    if payload:
                        target.sendall(payload)
            if target in r:
                try:
                    data = target.recv(65536)
                except BlockingIOError:
                    continue
                if not data:
                    break
                # kirim per 32KB agar frame tidak terlalu besar
                for i in range(0, len(data), 32768):
                    send_ws_frame(client, data[i:i + 32768])
    finally:
        for s in (client, target):
            try:
                s.close()
            except Exception:
                pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(128)
    print(f"ws.py listening on {LISTEN_HOST}:{LISTEN_PORT} -> {TARGET_HOST}:{TARGET_PORT}", flush=True)
    while True:
        client, _ = srv.accept()
        threading.Thread(target=ws_to_ssh, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
