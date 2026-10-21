#!/usr/bin/env python3
"""vpn-mux — pemilah trafik catch-all port 443 (keluaran fallback Xray edge).

Trafik TLS yang tidak cocok dengan fallback path mana pun (bukan WebSocket
Xray, bukan /ssh-ws) tiba di sini. Dipilah dari byte pertamanya:

- diawali "SSH-"  -> SSH mentah di atas TLS, gaya DarkTunnel/HTTP Custom
  "Direct + SNI bug host" ala FighterTunnel -> diteruskan ke Dropbear :109
- klien diam (menunggu banner server duluan, mis. klien OpenSSH biasa)
  -> Dropbear :109
- selain itu (HTTP/WebSocket multipath /<bebas>/<proto>, website)
  -> nginx :10009, sama seperti perilaku sebelum ada mux ini.
"""
import socket
import threading

LISTEN = ("127.0.0.1", 10017)
DROPBEAR = ("127.0.0.1", 109)
NGINX = ("127.0.0.1", 10009)
FIRST_BYTE_TIMEOUT = 1.0


def pump(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client):
    upstream = None
    try:
        client.settimeout(FIRST_BYTE_TIMEOUT)
        buf = b""
        try:
            while len(buf) < 4:
                chunk = client.recv(4 - len(buf))
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
        if not buf or buf.startswith(b"SSH-"):
            target = DROPBEAR
        else:
            target = NGINX
        upstream = socket.create_connection(target, timeout=10)
        client.settimeout(None)
        upstream.settimeout(None)
        if buf:
            upstream.sendall(buf)
        threading.Thread(
            target=pump, args=(client, upstream), daemon=True
        ).start()
        pump(upstream, client)
    except OSError:
        pass
    finally:
        for s in (client, upstream):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(LISTEN)
    srv.listen(256)
    print(f"vpn-mux jalan di {LISTEN[0]}:{LISTEN[1]}", flush=True)
    while True:
        client, _ = srv.accept()
        threading.Thread(target=handle, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
