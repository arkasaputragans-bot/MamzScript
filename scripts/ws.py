#!/usr/bin/env python3
"""SSH over HTTP Upgrade proxy untuk panel VPN (ala FighterTunnel).

Alur: haproxy :80 / Xray :443 -> 127.0.0.1:10020 (script ini) -> 127.0.0.1:22 (OpenSSH)
Setelah jawab 101, lakukan RAW TCP relay (bukan WebSocket RFC 6455 framing).
"""
import socket
import threading
import select

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 10020
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 22
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def ws_to_ssh(client):
    # --- handshake HTTP Upgrade ---
    # ALA FIGHTERTUNNEL: baca request secukupnya, SELALU jawab 101,
    # SELALU tunnel ke SSH. Jangan pernah 400/putus!
    # Alasan: proxy eksternal (cth. chat.sociomile.com) bisa mengacak/menunda
    # pipelined payload; validasi ketat = 400 + putus = klien gagal.
    # FT terbukti jalan dengan 301 decoy + tunnel tetap jalan.
    req = b""
    client.settimeout(3)
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
    # Response byte-identik dengan FighterTunnel (termasuk typo "Protocol" singular)
    # FT: HTTP/1.1 101 Switching Protocol + Sec-WebSocket-Accept: foo
    client.sendall(
        b"HTTP/1.1 101 Switching Protocol\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: foo\r\n\r\n"
    )

    target = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=10)

    # --- relay RAW TCP ala FighterTunnel (bukan WebSocket framing!) ---
    # Setelah 101, client (DarkTunnel/HTTP Custom) kirim raw SSH bytes.
    # FT terbukti: raw TCP relay, bukan RFC 6455 framing.
    # Pakai blocking socket + select (aman), hindari BlockingIOError sendall.
    try:
        while True:
            r, _, x = select.select([client, target], [], [client, target], 300)
            if x:
                break
            if not r:
                break
            for sock in r:
                try:
                    data = sock.recv(65536)
                except BlockingIOError:
                    continue
                except OSError:
                    return
                if not data:
                    return
                dst = target if sock is client else client
                try:
                    while data:
                        n = dst.send(data)
                        data = data[n:]
                except OSError:
                    return
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
