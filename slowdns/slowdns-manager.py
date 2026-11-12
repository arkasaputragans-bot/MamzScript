#!/usr/bin/env python3
"""MamzPanel SlowDNS manager — transport SSH lewat DNS (untuk HTTP Custom).

Port dari slowdns-manager.py A4NSTORE v2.8.128, diadaptasi ke MamzScript.
Scaffolding-nya (skema config.json, validasi hostname, dns_ready(),
pembuatan kunci via -gen-key, penulisan unit systemd, firewall iptables,
reconcile) dipakai apa adanya; semua branding, lisensi, callback
controller, provisioning Cloudflare, dan mode OpenVPN/both A4N DIBUANG.
Mode di sini hanya SSH — itulah yang terbukti jalan dengan HTTP Custom
8.0.10 (tap-test 11 Nov 2026 lawan engine potato; validasi live
engine mamz 12 Nov 2026 — tap-test HP user: konek).

Cara pakai (semua lewat menu `menu` > 8 Pengaturan > 8 SlowDNS, atau
langsung dari terminal):
    slowdns-manager.py setup-manual <ns> <domain-tunnel> <ip-publik>
    slowdns-manager.py start ssh <ip-publik> [engine]
    slowdns-manager.py set-record-type <auto|txt|null|cname|ns|mx|srv|1-6>
    slowdns-manager.py status | details | stop | records <ip>
    slowdns-manager.py reconcile [ip-publik]
    slowdns-manager.py firewall start|stop
    slowdns-manager.py validate <dir-config>
    slowdns-manager.py install

Pengujian: set MAMZ_SLOWDNS_ROOT=<dir> untuk mengarahkan semua path
(config, unit systemd, runtime) ke direktori lain.
"""
import argparse
import base64
import contextlib
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request

# --- Identitas MamzPanel (pengganti semua nama/path A4N) ---
CONFIG = 'etc/mamzpanel/slowdns'
SERVICE = 'mamz-slowdns.service'
NETWORK = 'mamz-slowdns-network.service'
HELPER = '/usr/local/bin/slowdns-manager.py'
SYSTEM_USER = 'mamzslowdns'
RUNTIME_DIR = '/var/lib/mamz-slowdns'
# Engine 'mamz': fork DNSTT bersih (CC0), SATU-SATUNYA engine.
# Dibangun 11 Nov 2026 dari upstream v1.20260501.0 mengikuti
# spesifikasi hasil bongkar potato — jawab 6 tipe HC, terverifikasi
# lab 61/61 (lihat slowdns/src/mamz/TEST-REPORT.md) dan validasi
# live HC 12 Nov 2026 (tap-test HP: konek).
# Binary TIDAK dibawa paket: install.sh MEMBANGUN-nya dari source
# (slowdns/src/mamz, butuh Go >= 1.21) ke /usr/local/bin/
# mamz-slowdns-server. 'potato' (binary prebuilt A4N) DICOPOT
# 12 Nov 2026: lisensi sewanya habis 13 Nov 2026 dan binary sewaan
# tidak boleh didistribusikan ulang di repo publik.
MAMZ_BINARY = '/usr/local/bin/mamz-slowdns-server'
STAGED_MAMZ_BINARY = '/usr/local/lib/mamzpanel/slowdns/mamz-slowdns-server'
# Upstream SSH yang dituju sesi tunnel: Dropbear MamzScript.
# install.sh langkah 4: /usr/sbin/dropbear -p 143 -p 109.
# Port 143 adalah port SSH utama; 109 hanya alias lama.
SSH_UPSTREAM = '127.0.0.1:143'
DNS_PORT = 5300
DEFAULT_MTU = 1232

# --- Registry engine: saat ini hanya 'mamz'. Tambah engine baru
# cukup daftarkan namanya, binary-nya, dan flag-nya di sini —
# menu, installer, dan unit systemd tidak perlu disentuh lagi.
# Engine 'dnstt' (DNSTT upstream Bam, TXT-only) SENGAJA tidak
# didaftarkan: klien HC tidak bisa konek lewatnya (kalibrasi slowdns
# tidak dijawab server dnstt orisinal).
# Lihat README.md files/slowdns/.
ENGINES = {
    'mamz': {
        'binary': MAMZ_BINARY,
        'flags': ['-record-type', 'auto'],
        'arch': ('amd64',),
        'dns_types': 'Auto',
        'staged': STAGED_MAMZ_BINARY,
    },
}
DEFAULT_ENGINE = 'mamz'

# Mode DNS (tipe record) yang disimpan di config.json.
# 'auto' = semua 6 tipe (bawaan — yang dipilih kalibrasi HC);
# '1'-'6' dinormalisasi ke nama tipe saat disimpan.
RECORD_TYPES = {'auto': 0, 'txt': 16, 'null': 10, 'cname': 5,
                'ns': 2, 'mx': 15, 'srv': 33,
                '1': 16, '2': 10, '3': 5, '4': 2, '5': 15, '6': 33}
RECORD_TYPE_NAMES = {'auto': 'auto', 'txt': 'txt', 'null': 'null',
                     'cname': 'cname', 'ns': 'ns', 'mx': 'mx',
                     'srv': 'srv', '1': 'txt', '2': 'null',
                     '3': 'cname', '4': 'ns', '5': 'mx', '6': 'srv'}


def normalize_record_type(value):
    """Nilai mode DNS apa pun -> nama kanonis ('auto'/'txt'/...).

    Menerima 'auto', nama tipe, atau angka '1'-'6'. Nilai lain ditolak.
    """
    key = str(value).strip().lower()
    if key not in RECORD_TYPE_NAMES:
        raise ValueError(
            'Mode DNS tidak dikenal: %s. Pakai auto, txt, null, cname, '
            'ns, mx, srv, atau 1-6.' % value)
    return RECORD_TYPE_NAMES[key]


def hostname(value):
    value = value.strip().lower().rstrip('.')
    if not 3 <= len(value) <= 190 or '.' not in value or any(
            not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p)
            for p in value.split('.')):
        raise ValueError(
            'Hostname DNS tidak valid. Gunakan domain lengkap tanpa '
            'https:// atau wildcard.')
    return value


def hex_to_base32(hexkey):
    """Kunci hex 64 karakter (32 byte) -> base32 RFC 4648 (52 karakter).

    HC menerima hex (terbukti di tap-test), jadi hex adalah tampilan
    utama; base32 hanya cadangan. Konversi ini manual — manager A4N
    tidak memilikinya.
    """
    raw = bytes.fromhex(hexkey.strip())
    if len(raw) != 32:
        raise ValueError('Kunci SlowDNS harus 32 byte.')
    return base64.b32encode(raw).decode()


def public_ip():
    """Deteksi IPv4 publik VPS (untuk reconcile tanpa argumen)."""
    for url, parse in (
            ('https://ifconfig.me', lambda t: t.strip()),
            ('http://ip-api.com/json/',
             lambda t: json.loads(t).get('query', ''))):
        try:
            with urllib.request.urlopen(url, timeout=8) as r:
                candidate = parse(r.read().decode())
            ipaddress.IPv4Address(candidate)
            return candidate
        except Exception:
            continue
    try:
        out = subprocess.run(['hostname', '-I'], capture_output=True,
                             text=True, timeout=10).stdout
    except Exception:
        out = ''
    for token in out.split():
        try:
            addr = ipaddress.IPv4Address(token)
            if addr.is_global:
                return str(addr)
        except ValueError:
            continue
    raise ValueError('IP publik VPS tidak terdeteksi. Beri IP secara manual.')


def validate(data):
    if not isinstance(data, dict) or data.get('format') != 1 \
            or type(data.get('enabled')) is not bool:
        raise ValueError('Konfigurasi SlowDNS tidak valid.')
    for k in ('ns', 'domain'):
        hostname(data.get(k, ''))
    if data['ns'] == data['domain'] or data['ns'].endswith('.' + data['domain']):
        raise ValueError('Nameserver harus berada di luar subdomain tunnel.')
    if data.get('mode') != 'ssh':
        raise ValueError('Mode SlowDNS di MamzScript hanya SSH.')
    if data.get('dns_mode') != 'manual':
        raise ValueError('Mode DNS di MamzScript hanya manual (tanpa Cloudflare).')
    if data.get('engine', DEFAULT_ENGINE) not in ENGINES:
        raise ValueError(
            'Mesin SlowDNS tidak dikenal: %s. Yang tersedia: %s.'
            % (data.get('engine'), ', '.join(ENGINES)))
    if data.get('record_type', 'auto') not in RECORD_TYPE_NAMES:
        raise ValueError(
            'Mode DNS tidak dikenal: %s. Pakai auto, txt, null, cname, '
            'ns, mx, srv, atau 1-6.' % data.get('record_type'))
    if type(data.get('mtu')) is not int or not 512 <= data['mtu'] <= 1232:
        raise ValueError('MTU SlowDNS tidak valid.')
    if 'manual_dns' in data and type(data['manual_dns']) is not bool:
        raise ValueError('Status DNS manual tidak valid.')
    return data

class Manager:
    def __init__(self, root=None, run=None):
        # root=None -> '/' (atau MAMZ_SLOWDNS_ROOT untuk pengujian).
        self.root = Path(root if root is not None
                         else os.environ.get('MAMZ_SLOWDNS_ROOT', '/'))
        self.base = self.root / CONFIG
        self.run = run or self.command

    @staticmethod
    def command(args, check=True):
        return subprocess.run(args, check=check, text=True,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=180)

    def path(self, p):
        return self.root / p.lstrip('/')

    def unit_file(self, name):
        return self.path('/etc/systemd/system/' + name)

    def existing_units(self, *names):
        """Hanya unit yang berkasnya benar-benar ada.

        PERBAIKAN BUG A4N: stop() lama memanggil
        `systemctl disable --now` dengan unit anak ssh/openvpn yang
        TIDAK ADA di mode ssh — perintah abort total, layanan tetap
        jalan, setup-manual menolak ganti hostname. Semua pemanggilan
        systemctl dengan daftar unit di file ini WAJIB lewat sini.
        """
        return [u for u in names if self.unit_file(u).exists()]

    @contextlib.contextmanager
    def control_lock(self):
        path = self.path('/run/lock/mamz-slowdns-control.lock')
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('a') as stream:
            if os.name != 'nt':
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX)
            try:
                yield
            finally:
                if os.name != 'nt':
                    fcntl.flock(stream, fcntl.LOCK_UN)

    def write(self, path, value, mode=0o600):
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=path.parent,
                                        delete=False) as f:
            temp = Path(f.name)
            f.write(value.encode() if isinstance(value, str) else value)
        os.chmod(temp, mode)
        os.replace(temp, path)

    def load(self):
        return validate(json.loads((self.base / 'config.json').read_text()))

    def save(self, data):
        validate(data)
        self.base.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.write(self.base / 'config.json', json.dumps(data, indent=2) + '\n')

    def validate_backup(self, base):
        base = Path(base)
        if not base.exists():
            return
        if base.is_symlink() or any(x.is_symlink() for x in base.rglob('*')):
            raise ValueError('Symlink SlowDNS tidak diizinkan.')
        if {p.name for p in base.iterdir()} - {'config.json', 'server.key',
                                               'server.pub'}:
            raise ValueError('Berkas SlowDNS tidak dikenal.')
        data = validate(json.loads((base / 'config.json').read_text()))
        keys = [base / 'server.key', base / 'server.pub']
        if any(p.exists() for p in keys):
            if not all(p.is_file() and re.fullmatch(r'[0-9a-fA-F]{64}\s*',
                                                    p.read_text())
                       for p in keys):
                raise ValueError('Pasangan kunci SlowDNS tidak lengkap/valid.')
        elif data['enabled']:
            raise ValueError('Kunci SlowDNS aktif tidak ditemukan dalam backup.')

    def setup(self, ns, domain, mode='ssh'):
        old = self.load() if (self.base / 'config.json').exists() else None
        if old and old['enabled'] and (old['ns'] != ns or old['domain'] != domain):
            raise ValueError(
                'Nonaktifkan SlowDNS dahulu sebelum mengganti hostname.')
        if mode != 'ssh':
            raise ValueError('Mode SlowDNS di MamzScript hanya SSH.')
        data = {'format': 1, 'ns': hostname(ns), 'domain': hostname(domain),
                'mode': 'ssh', 'mtu': DEFAULT_MTU, 'dns_mode': 'manual',
                'enabled': old['enabled'] if old else False,
                'auto_start': old.get('auto_start', True) if old else True,
                'manual_dns': True,
                'record_type': old.get('record_type')
                if old and old.get('record_type') in RECORD_TYPE_NAMES
                else 'auto',
                'engine': DEFAULT_ENGINE}
        if old and old.get('engine') and old['mode'] == mode:
            data['engine'] = old['engine']
        self.save(data)
        return data

    def dns_ready(self, ip, domain=None):
        data = self.load()
        ip = str(ipaddress.IPv4Address(ip))
        if domain:
            data = {**data, 'domain': hostname(domain)}
        if not ipaddress.ip_address(ip).is_global:
            raise ValueError('Gunakan IPv4 publik VPS.')
        try:
            # Tanya otoritas induk langsung: server DNSTT tidak
            # menjawab query NS polos di apex zona terdelegasi, jadi
            # query NS rekursif akan salah melaporkan delegasi yang
            # sehat sebagai tidak ada. Delegasi yang benar muncul di
            # AUTHORITY section (referral), bukan ANSWER — karena itu
            # +answer +authority DIBACA DUA-DUANYA (pelajaran 11 Nov:
            # filter `dig +noall +answer` saja menyembunyikan referral
            # dan membuat NS terlihat "kosong" padahal ada).
            labels = data['domain'].split('.')
            for offset in range(1, len(labels) - 1):
                parent = '.'.join(labels[offset:])
                found = self.run(['dig', '+time=3', '+tries=1', '+short',
                                  'NS', parent], check=False)
                authorities = found.stdout.split() \
                    if found.returncode == 0 else []
                if not authorities:
                    continue
                authority = hostname(authorities[0])
                answer = self.run(['dig', '+time=3', '+tries=1',
                                   '@' + authority, '+norecurse',
                                   '+noall', '+answer', '+authority',
                                   'NS', data['domain']], check=False)
                targets = set()
                for line in answer.stdout.splitlines():
                    fields = line.split()
                    if len(fields) >= 5 and fields[0].lower().rstrip('.') \
                            == data['domain'] and fields[-2] == 'NS':
                        targets.add(fields[-1].lower().rstrip('.'))
                if answer.returncode != 0 or targets != {data['ns']}:
                    return False
                # Resolver OS bisa meng-cache IP lama / NXDOMAIN setelah
                # migrasi. Validasi A record otoritatif sebagai gantinya.
                address = self.run(['dig', '+time=3', '+tries=1',
                                    '@' + authority, '+norecurse',
                                    '+noall', '+answer',
                                    'A', data['ns']], check=False)
                addresses = set()
                for line in address.stdout.splitlines():
                    fields = line.split()
                    if len(fields) >= 5 and fields[0].lower().rstrip('.') \
                            == data['ns'] and fields[-2] == 'A':
                        addresses.add(fields[-1])
                if addresses:
                    return address.returncode == 0 and addresses == {ip}
                # Nameserver eksternal yang disengaja butuh lookup
                # rekursif sendiri; A yang tidak ada di otoritas ini
                # berarti belum siap.
                if data['ns'] != parent and not data['ns'].endswith('.' + parent):
                    return {r[4][0] for r in socket.getaddrinfo(
                        data['ns'], 53, socket.AF_INET,
                        socket.SOCK_DGRAM)} == {ip}
                return False
            return False
        except (OSError, subprocess.SubprocessError):
            return False

    def keys(self, data=None):
        data = data or self.load()
        binary = ENGINES[data.get('engine', DEFAULT_ENGINE)]['binary']
        pair = [self.base / 'server.key', self.base / 'server.pub']
        if any(p.exists() for p in pair):
            self.validate_backup(self.base)
            return
        # Buat dan validasi pasangan lengkap sebelum mempublikasikan
        # salah satu berkas. Inisialisasi gagal tidak boleh meninggalkan
        # klien dengan setengah kunci.
        with tempfile.TemporaryDirectory(prefix='mamz-slowdns-keygen-') as temp:
            staged = [Path(temp) / 'server.key', Path(temp) / 'server.pub']
            self.run([binary, '-gen-key', '-privkey-file', str(staged[0]),
                      '-pubkey-file', str(staged[1])])
            if not all(p.is_file() and re.fullmatch(r'[0-9a-fA-F]{64}\s*',
                                                    p.read_text())
                       for p in staged):
                raise ValueError(
                    'Pembuatan kunci SlowDNS gagal. Kunci aktif tidak diubah.')
            for src, dest in zip(staged, pair):
                self.write(dest, src.read_bytes())
        self.validate_backup(self.base)
        for p in pair:
            os.chmod(p, 0o600)

    def engine_flags(self, data):
        """Flag binary engine, dengan -record-type dari config.

        Engine mamz menerima -record-type; nilai config (auto/txt/...)
        menggantikan bawaan registry.
        """
        engine = ENGINES[data.get('engine', DEFAULT_ENGINE)]
        rt = normalize_record_type(data.get('record_type', 'auto'))
        flags = []
        skip_next = False
        for tok in engine['flags']:
            if skip_next:
                skip_next = False
                continue
            if tok == '-record-type':
                flags += ['-record-type', rt]
                skip_next = True
                continue
            flags.append(tok)
        if '-record-type' not in engine['flags']:
            flags = ['-record-type', rt] + flags
        return flags + ['-mtu', str(data['mtu'])]

    def service_text(self, data):
        validate(data)
        engine = ENGINES[data.get('engine', DEFAULT_ENGINE)]
        flags = ' '.join(self.engine_flags(data))
        return f'''[Unit]
Description=MamzPanel SlowDNS (ssh)
After=network-online.target {NETWORK} dropbear.service
Wants=network-online.target
Requires={NETWORK}
[Service]
User={SYSTEM_USER}
Group={SYSTEM_USER}
StateDirectory=mamz-slowdns
StateDirectoryMode=0700
ExecStart={engine['binary']} {flags} -udp 0.0.0.0:{DNS_PORT} -privkey-file {RUNTIME_DIR}/server.key {data['domain']} {SSH_UPSTREAM}
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
MemoryMax=128M
TasksMax=64
LimitNOFILE=4096
[Install]
WantedBy=multi-user.target
'''

    def records(self, ip):
        data = self.load()
        return ('A  ' + data['ns'] + ' -> ' + ip + ' (DNS only)\n'
                'NS ' + data['domain'] + ' -> ' + data['ns'])

    def firewall(self, start):
        """Hanya chain/rule milik sendiri; tidak pernah flush firewall host
        atau menyentuh OUTPUT."""
        specs = [('nat', 'MAMZ_SLOWDNS',
                  ['PREROUTING', '-p', 'udp', '--dport', '53', '-m',
                   'addrtype', '--dst-type', 'LOCAL', '-m', 'comment',
                   '--comment', 'Mamz-SlowDNS', '-j', 'MAMZ_SLOWDNS'],
                  ['-p', 'udp', '-j', 'REDIRECT', '--to-ports',
                   str(DNS_PORT)]),
                 ('filter', 'MAMZ_SLOWDNS_IN',
                  ['INPUT', '-p', 'udp', '--dport', str(DNS_PORT), '-m',
                   'comment', '--comment', 'Mamz-SlowDNS',
                   '-j', 'MAMZ_SLOWDNS_IN'],
                  ['-j', 'ACCEPT'])]
        for table, chain, jump, rule in specs:
            base = ['iptables', '-w', '10', '-t', table]
            if start:
                self.run(base + ['-N', chain], check=False)
                if self.run(base + ['-C', chain] + rule,
                            check=False).returncode:
                    self.run(base + ['-A', chain] + rule)
                if self.run(base + ['-C'] + jump,
                            check=False).returncode:
                    self.run(base + ['-I', jump[0], '1'] + jump[1:])
            else:
                if self.run(base + ['-C'] + jump,
                            check=False).returncode == 0:
                    self.run(base + ['-D'] + jump)
                if self.run(base + ['-C', chain] + rule,
                            check=False).returncode == 0:
                    self.run(base + ['-D', chain] + rule)
                self.run(base + ['-X', chain], check=False)

    def start(self, mode, ip, engine=None):
        data = self.load()
        if mode != 'ssh':
            raise ValueError('Mode SlowDNS di MamzScript hanya SSH.')
        engine = engine or data.get('engine', DEFAULT_ENGINE)
        if engine not in ENGINES:
            raise ValueError(
                'Mesin SlowDNS tidak dikenal: %s. Yang tersedia: %s.'
                % (engine, ', '.join(ENGINES)))
        if not self.dns_ready(ip):
            raise ValueError(
                'DNS belum siap. A nameserver harus ke IPv4 VPS ini, '
                'DNS only; NS tunnel harus ke nameserver tersebut.')
        # Tolak resolver otoritatif lain di :53, tapi biarkan
        # systemd-resolved di loopback. Tidak ada NAT UDP/53 menyeluruh
        # selagi DNS publik sedang dipakai.
        listeners = self.run(['ss', '-H', '-lun', 'sport = :53']).stdout.splitlines()
        for line in listeners:
            cols = line.split()
            address = cols[3] if len(cols) > 3 else ''
            if address and not address.startswith(('127.', '[::1]:')):
                raise ValueError(
                    'UDP 53 dipakai layanan DNS lain. Tidak dihentikan otomatis.')
        upstream_host, upstream_port = SSH_UPSTREAM.rsplit(':', 1)
        with socket.create_connection((upstream_host, int(upstream_port)),
                                     timeout=3):
            pass
        self.keys(data)
        self.validate_backup(self.base)
        if self.run(['id', SYSTEM_USER], check=False).returncode:
            self.run(['useradd', '--system', '--user-group',
                      '--no-create-home', '--home-dir', RUNTIME_DIR,
                      '--shell', '/usr/sbin/nologin', SYSTEM_USER])
        helper = self.path(HELPER)
        if helper.is_file():
            shutil.chown(helper, user='root', group=SYSTEM_USER)
            os.chmod(helper, 0o750)
        runtime = self.path(RUNTIME_DIR)
        runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.chown(runtime, user=SYSTEM_USER, group=SYSTEM_USER)
        self.write(runtime / 'server.key',
                   (self.base / 'server.key').read_bytes())
        shutil.chown(runtime / 'server.key', user=SYSTEM_USER,
                     group=SYSTEM_USER)
        original = dict(data)
        data.update(mode='ssh', enabled=True, auto_start=True,
                    engine=engine)
        network = f'''[Unit]
Description=MamzPanel SlowDNS owned firewall rules
After=network-online.target
Before={SERVICE}
[Service]
Type=oneshot
RemainAfterExit=true
ExecStart=/usr/bin/python3 {HELPER} firewall start
ExecStop=/usr/bin/python3 {HELPER} firewall stop
[Install]
WantedBy=multi-user.target
'''
        units = [NETWORK, SERVICE]
        snapshots = {u: self.unit_file(u).read_bytes()
                     if self.unit_file(u).exists() else None
                     for u in units}
        was_active = self.run(['systemctl', 'is-active', '--quiet', SERVICE],
                              check=False).returncode == 0
        self.write(self.unit_file(NETWORK), network, 0o644)
        self.write(self.unit_file(SERVICE), self.service_text(data), 0o644)
        self.run(['systemctl', 'daemon-reload'])
        try:
            self.run(['systemctl', 'enable', '--now', NETWORK])
            self.run(['systemctl', 'enable', SERVICE])
            self.run(['systemctl', 'restart', SERVICE])
            self.run(['systemctl', 'is-active', '--quiet', SERVICE])
            self.save(data)
        except Exception:
            units_now = self.existing_units(*units)
            if units_now:
                self.run(['systemctl', 'stop'] + units_now, check=False)
            for unit, raw in snapshots.items():
                p = self.unit_file(unit)
                if raw is None:
                    with contextlib.suppress(FileNotFoundError):
                        p.unlink()
                else:
                    self.write(p, raw, 0o644)
            self.run(['systemctl', 'daemon-reload'])
            if was_active:
                self.run(['systemctl', 'restart', SERVICE], check=False)
            elif self.existing_units(*units):
                self.run(['systemctl', 'disable', '--now']
                         + self.existing_units(*units), check=False)
            raise ValueError(
                'SlowDNS baru gagal; konfigurasi sebelumnya dipulihkan. '
                'Layanan SSH/Xray biasa tidak diubah.') from None

    def stop(self):
        # PERBAIKAN BUG A4N (lihat existing_units): hanya unit yang
        # berkasnya ada yang disentuh. Di mode ssh unit anak tidak ada,
        # sehingga `disable --now` lama abort total dan layanan tetap
        # jalan. Urutan stop -> setup-manual -> start kini lolos.
        with self.control_lock():
            data = self.load()
            units = self.existing_units(SERVICE, NETWORK)
            if units:
                self.run(['systemctl', 'disable', '--now'] + units,
                         check=False)
            # Sabuk pengaman: pastikan layanan utama benar-benar mati
            # walau disable sempat abort di tengah jalan.
            self.run(['systemctl', 'stop', SERVICE], check=False)
            state = self.run(['systemctl', 'show', SERVICE,
                              '-p', 'ActiveState', '--value'], check=False)
            active = state.stdout.strip()
            if active not in ('inactive', 'failed', ''):
                raise ValueError(
                    'SlowDNS belum berhenti. Periksa status layanan.')
            self.firewall(False)
            data.update(enabled=False, auto_start=False)
            self.save(data)

    def set_record_type(self, value):
        """Simpan Mode DNS baru; terapkan langsung bila layanan aktif.

        Bila layanan sedang jalan, unit ditulis ulang (flag -record-type
        baru) + daemon-reload + restart. Bila tidak aktif, mode hanya
        tersimpan untuk aktivasi berikutnya.
        """
        rt = normalize_record_type(value)
        data = self.load()
        data['record_type'] = rt
        self.save(data)
        active = self.run(['systemctl', 'is-active', '--quiet', SERVICE],
                          check=False).returncode == 0
        if not active:
            return rt
        try:
            self.write(self.unit_file(SERVICE), self.service_text(data),
                       0o644)
            self.run(['systemctl', 'daemon-reload'])
            self.run(['systemctl', 'restart', SERVICE])
            self.run(['systemctl', 'is-active', '--quiet', SERVICE])
        except Exception:
            raise ValueError(
                'Mode DNS tersimpan (%s), tapi layanan gagal restart. '
                'Aktifkan ulang dari menu SlowDNS.' % rt) from None
        return rt

    def reconcile(self, ip=None):
        if not (self.base / 'config.json').exists():
            return
        if ip is None:
            ip = public_ip()
        data = self.load()
        if not data.get('auto_start', True):
            return
        desired = self.service_text(data)
        unit = self.unit_file(SERVICE)
        current = unit.read_text() if unit.exists() else ''
        if not self.dns_ready(ip):
            if current and current != desired:
                units = self.existing_units(SERVICE, NETWORK)
                if units:
                    self.run(['systemctl', 'disable', '--now'] + units,
                             check=False)
                self.firewall(False)
            raise ValueError(
                'SlowDNS menunggu pointing A nameserver dan NS tunnel '
                'ke VPS baru.')
        active = self.run(['systemctl', 'is-active', '--quiet', SERVICE],
                          check=False).returncode == 0
        runtime = self.path(RUNTIME_DIR + '/server.key')
        same_key = runtime.exists() and runtime.read_bytes() == \
            (self.base / 'server.key').read_bytes()
        if active and current == desired and same_key:
            return
        self.ensure_binary(data)
        self.start(data['mode'], ip, data.get('engine', DEFAULT_ENGINE))

    def ensure_binary(self, data):
        install_engine_binary(
            self, data.get('engine', DEFAULT_ENGINE))

    def details(self, as_html=False):
        def pending(reason):
            title = 'SLOWDNS'
            if as_html:
                return ('\n<b>' + title + '</b>\n'
                        '◇━━━━━━━━━━━━━━━◇\n'
                        'Status : <code>' + html.escape(reason) + '</code>\n'
                        'Periksa DNS A/NS dan layanan SSH di menu SlowDNS.\n'
                        '◇━━━━━━━━━━━━━━━◇')
            return ('\n' + title + '\n────────────────────────────\n'
                    'Status          : ' + reason + '\n'
                    'Periksa DNS A/NS dan layanan SSH di menu SlowDNS.\n'
                    '────────────────────────────')
        if not (self.base / 'config.json').exists():
            return pending('Belum dikonfigurasi')
        data = self.load()
        pub = self.base / 'server.pub'
        active = self.run(['systemctl', 'is-active', '--quiet', SERVICE],
                          check=False).returncode == 0
        if not data.get('auto_start', True):
            return pending('OFF — dinonaktifkan pemilik')
        if not data['enabled'] or not pub.is_file() or not active:
            return pending('Belum aktif — menunggu DNS/SSH')
        hexkey = pub.read_text().strip()
        try:
            b32key = hex_to_base32(hexkey)
        except ValueError:
            b32key = '-'
        rt = normalize_record_type(data.get('record_type', 'auto'))
        mode_dns = 'Auto (6 tipe)' if rt == 'auto' else rt.upper()
        # Klien HP memanggil suffix tunnel terdelegasi sebagai
        # "NameServer"; hostname A-record otoritatif adalah
        # infrastruktur, bukan input itu.
        fields = [('NameServer', data['domain']),
                  ('Public key (hex)', hexkey),
                  ('Public key (base32)', b32key),
                  ('Port DNS', '53,5300'),
                  ('Mode DNS', mode_dns),
                  ('Engine', data.get('engine', DEFAULT_ENGINE)),
                  ('Upstream SSH', SSH_UPSTREAM),
                  ('Resolver DNS', '1.1.1.1'),
                  ('Autentikasi', 'Akun SSH')]
        title = 'SLOWDNS • SSH'
        if as_html:
            rows = ['', '<b>' + html.escape(title) + '</b>',
                    '◇━━━━━━━━━━━━━━━◇']
            rows.extend(html.escape(label) + ' : <code>'
                        + html.escape(value) + '</code>'
                        for label, value in fields)
            rows.append('◇━━━━━━━━━━━━━━━◇')
        else:
            rows = ['', title, '────────────────────────────']
            rows.extend(label.ljust(20) + ': ' + value
                        for label, value in fields)
            rows.append('────────────────────────────')
        return '\n'.join(rows)


def install_engine_binary(manager, engine_name):
    """Pasang binary engine dari salinan staging installer.

    Binary DIBANGUN install.sh dari source (slowdns/src/mamz),
    bukan dibawa paket — jadi tidak ada pin sha256 (tiap build
    beda hash). Yang dicek: file ELF amd64 yang masuk akal
    (magic + ukuran). Bila binary utama hilang/rusak, salin dari
    salinan staging installer; bila staging juga tidak ada, minta
    jalankan install.sh langkah SlowDNS untuk membangunnya lagi.
    """
    engine = ENGINES[engine_name]
    dest = manager.path(engine['binary'])
    if _is_valid_binary(dest):
        return
    arch = manager.run(['dpkg', '--print-architecture']).stdout.strip()
    if arch not in engine['arch']:
        raise ValueError(
            'Mesin SlowDNS ini memerlukan arsitektur amd64. '
            'Konfigurasi aktif tidak diubah.')
    staged = manager.path(engine['staged'])
    if not staged.is_file():
        raise ValueError(
            'Binary SlowDNS (%s) tidak ditemukan di salinan staging. '
            'Jalankan install.sh langkah SlowDNS untuk membangunnya lagi.'
            % engine_name)
    raw = staged.read_bytes()
    if len(raw) > 32 * 1024 * 1024 or raw[:4] != b'\x7fELF':
        raise ValueError(
            'Verifikasi berkas SlowDNS gagal. Aktivasi dibatalkan; '
            'konfigurasi aktif tidak diubah.')
    manager.write(dest, raw, 0o755)


def _is_valid_binary(path):
    """Binary engine layak pakai: ada, ELF, ukuran wajar (<32 MB)."""
    try:
        raw = path.read_bytes()
    except OSError:
        return False
    return raw[:4] == b'\x7fELF' and 0 < len(raw) <= 32 * 1024 * 1024


def install_mamz_binary(manager):
    """Pasang binary utama mamz (fork bersih)."""
    install_engine_binary(manager, 'mamz')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=[
        'setup-manual', 'status', 'details', 'start', 'stop', 'reconcile',
        'validate', 'firewall', 'records', 'install', 'set-record-type'])
    parser.add_argument('args', nargs='*')
    parser.add_argument('--html', action='store_true')
    parser.add_argument('--active-only', action='store_true')
    o = parser.parse_args()
    m = Manager()
    try:
        if o.action == 'setup-manual':
            old = m.load() if (m.base / 'config.json').exists() else {}
            data = m.setup(*o.args[:2], mode=old.get('mode', 'ssh'))
            ip = o.args[2]
            data.update(dns_mode='manual', manual_dns=True)
            m.save(data)
            print('Tambahkan record berikut di DNS:')
            print(m.records(ip))
            print('JANGAN buat record A di ' + data['domain'] + ' sendiri '
                  '(apex zona terdelegasi) — record itu dapat menutupi '
                  'delegasi NS.')
            return
        if o.action == 'status':
            if not (m.base / 'config.json').exists():
                print('SlowDNS belum dikonfigurasi.')
                return
            data = m.load()
            active = m.run(['systemctl', 'is-active', '--quiet', SERVICE],
                           check=False).returncode == 0
            print(' Domain tunnel : ' + data['domain']
                  + '\n Nameserver    : ' + data['ns']
                  + '\n Mode          : ' + data['mode'].upper()
                  + '\n Mode DNS      : ' + (
                      'Auto (6 tipe)' if normalize_record_type(
                          data.get('record_type', 'auto')) == 'auto'
                      else normalize_record_type(
                          data.get('record_type', 'auto')).upper())
                  + '\n Engine        : ' + data.get('engine', DEFAULT_ENGINE))
            print(' Status        : ' + ('\033[1;32mAKTIF\033[0m' if active
                                         else '\033[1;31mNONAKTIF\033[0m'))
            return
        if o.action == 'details':
            print(m.details(o.html))
            return
        if o.action == 'stop':
            m.stop()
            print('\033[1;32m✓ SlowDNS berhasil dinonaktifkan.\033[0m')
            return
        if o.action == 'reconcile':
            m.reconcile(o.args[0] if o.args else None)
            return
        if o.action == 'start':
            engine = o.args[2] if len(o.args) > 2 else None
            selected = m.load()
            m.ensure_binary(selected)
            m.start(o.args[0], o.args[1], engine)
            print('SlowDNS aktif.')
            print(m.details())
            return
        if o.action == 'records':
            print(m.records(o.args[0]))
            return
        if o.action == 'validate':
            m.validate_backup(o.args[0])
            return
        if o.action == 'install':
            if (m.base / 'config.json').exists():
                engine = m.load().get('engine', DEFAULT_ENGINE)
            else:
                engine = DEFAULT_ENGINE
            install_engine_binary(m, engine)
            print('Binary SlowDNS terpasang & terverifikasi.')
            return
        if o.action == 'set-record-type':
            rt = m.set_record_type(o.args[0] if o.args else 'auto')
            print('Mode DNS: ' + ('Auto (6 tipe)' if rt == 'auto'
                                  else rt.upper()) + '.')
            return
        if o.action == 'firewall':
            m.firewall(o.args[0] == 'start')
            return
    except (ValueError, OSError, subprocess.SubprocessError) as e:
        print('SlowDNS: ' + str(e))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
