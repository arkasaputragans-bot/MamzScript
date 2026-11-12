# mamz-slowdns-server — clean-room DNSTT fork (engine "mamz")

A SlowDNS tunnel server for MamzScript, built as a clean-room fork of
upstream DNSTT. It replaces the rented A4N `potato` binary (whose licence
expired 13 Nov 2026) with a permanent, licence-free engine that answers
the six DNS record types HTTP Custom 8.0.10 uses (TXT, NULL, CNAME, NS,
MX, SRV), with per-type MTUs matching the reference server.

## Provenance (read this first)

* **Upstream:** DNSTT v1.20260501.0
  (`www.bamsoftware.com/git/dnstt.git`, commit `0c5c52a`), released into
  the public domain (CC0). The `dns/`, `noise/`, and `turbotunnel/`
  packages and `COPYING` are copied from it, with only the import path
  changed (`mamzslowdns`). The Noise+KCP+smux transport, base32
  **StdEncoding** upload decoding, the EDNS minimum of 1232, TTL 60, and
  the `-gen-key` / `-privkey(-file)` / `-pubkey-file` / `-mtu` / `-udp`
  usage are unchanged from upstream.
* **Behaviour specification:** `../BONGKAR-POTATO.md` (§2, §5, §6, §10)
  — the dissection of the rented potato binary — plus
  `../../slowdns-hc/TEMUAN-SLOWDNS-HC.md` §2–§3 (HTTP Custom's
  expectations). The potato binary itself (`work/potato-unpacked`) was
  used **only as a behaviour oracle** (side-by-side black-box tests);
  no code or string was copied from it. This tree contains no A4N code.
* **Name-encoding reference:** VayDNS (`github.com/net2share/vaydns`,
  CC0) was consulted for how a payload is coded into a domain name
  (base32 labels, MX/SRV headers). The fork follows the reference
  server's wire behaviour, not VayDNS's, where they differ (labels carry
  no tunnel-domain suffix; labels are lowercase — see below).

## What changed vs upstream

### `dns/records.go` (new, 362 lines)
* RRType constants: `NS = 2`, `CNAME = 5`, `NULL = 10`, `MX = 15`,
  `SRV = 33`; `RecordTypeSentinel = 0xff0a`.
* `ParseRecordType`: `"auto"` → 0, names `txt`/`null`/`cname`/`ns`/`mx`/
  `srv` (case-insensitive), `"1"`–`"6"` → the six types.
* `RecordMode` / `TypeForRecordMode`: 1=TXT, 2=NULL, 3=CNAME, 4=NS,
  5=MX, 6=SRV.
* `IsTunnelRecordType`.
* `Limits` struct (`NameSize`, `ReceiveSize`, `Token`, `Domain`) with
  `Validate()`, and `ParseCalibrationToken` (label `1-<hex>-<hex>`).
  Field order (NameSize first, then ReceiveSize) is an **assumption**
  (see "Assumptions").
* `EncodeRData` / `DecodeRData` per type, dispatched by QTYPE:
  TXT = character-strings, NULL = raw payload, CNAME/NS = domain name,
  MX = 2-byte preference + name, SRV = 6-byte header + name.
* `encodePayloadAsName`: payload is base32 StdEncoding **without
  padding**, split into labels of ≤ 63 characters, **lowercase**, with
  **no tunnel-domain suffix** (name = labels only, terminated by the
  root). Empty payload = root `00`. MX and SRV prepend their fixed
  header (`0000` / `000000000000`) before the name.
* `ResponseCap`: caps the downstream response size per type —
  TXT = global, NULL = min(global, 1232), name types =
  min(global, 512). This is what produces the MTU table below.

### `mamz-slowdns-server/main.go` (fork of `dnstt-server/main.go`)
* New flags: `-record-type` (default `"auto"`) and `-diagnostics`
  (accepted; logs one line when enabled, otherwise a no-op — see
  "Assumptions"). `-h` output lists the flags in the same order as the
  reference server.
* `run()` starts **seven** listeners: the six tunnel types plus the
  sentinel `0xff0a`, which maps to NULL. Startup logs
  `DNS mode N effective MTU M` once per entry, so mode 2 is printed
  twice (NULL + sentinel) — that is the correct, reference-matching
  behaviour, not a bug.
* `responseFor` → `responseForMode`: in fixed mode, any other type is
  answered NXDOMAIN **silently** (no log); `0xff0a` is mapped to NULL;
  the per-type size class is applied.
* `recvLoop` (rewritten): one `QueuePacketConn` per type, a per-client
  map pinning the session's record type, and a per-client map of the
  calibrated type. It detects calibration probes (trailing label
  starting `1-`, validated against `Limits`) and routes them to the
  NULL handler; the probed type is remembered per client and used for
  that client's later responses. A probe is only routed to a
  fixed-mode listener when its type matches the mode.
* `sendLoop` (rewritten): per-type payload limits from the maps, and
  `EncodeRData` per response type.
* `computeMaxEncodedPayload(limit, qtype)` generalised: binary search
  using the per-type encoder. The EDNS OPT record's advertised size is
  the global maximum when measuring name types, so a 512-byte cap does
  not trigger FORMERR.
* Log wording changed to match the reference: `invalid query encoding:`
  (upstream said `NXDOMAIN: base32 decoding:`). `not authoritative
  for ...` for out-of-domain queries is unchanged.
* `turbotunnel/consts.go`: `QueueSize` 128 → **1024**. Upstream uses
  128, which advertises a KCP window of 64; the reference server
  advertises 512. The larger window is also what the tunnel needs for
  throughput. (Found by the oracle test, not by reading the binary.)
* Session log lines: `begin session <conv>`, `begin stream <conv>:<n>`
  — unchanged.
* Upstream address is a positional argument (the MamzScript manager
  passes `127.0.0.1:143`, the panel Dropbear port, as `SSH_UPSTREAM`).

## Build

Go 1.27.4 (the toolchain in `../work/go/bin/go`):

```sh
cd fork
go build -o bin/mamz-slowdns-server ./mamz-slowdns-server
```

`go vet ./...` is clean apart from pre-existing warnings in the
upstream `noise_test.go`, which are not fork code.

The built binary is checked in at `bin/mamz-slowdns-server`
(sha256 `14e33f7166eef7cd21bf1e7b6bf24f6e9acab893284dc0802e2bd8a3644229fa`).
Note: the task asked for the binary at `fork/mamz-slowdns-server`, but
that path is the server's source directory, so the binary lives in
`bin/` instead.

## Usage

```sh
# Generate a server key (lab keys only — generate fresh ones per install)
./bin/mamz-slowdns-server -gen-key > server.key
./bin/mamz-slowdns-server -privkey-file server.key \
    -udp 0.0.0.0:5300 -record-type auto \
    ns-sgdo7.mamzvpn.my.id 127.0.0.1:143
```

* The key file holds 64 hex characters (32 bytes). The public key is
  the hex value logged at startup (`pubkey <hex>`); the MamzScript
  manager converts it to base32 for the HTTP Custom package.
* `-record-type` accepts `auto` (default), a name (`txt`, `null`,
  `cname`, `ns`, `mx`, `srv`), or a number `1`–`6`. A bogus value is
  rejected with an error.
* `-mtu` sets the global cap (default 1232, matching the reference
  invocation `-mtu 1232`).
* `-diagnostics` is accepted and logs one line; it emits no probes in
  this build.

## MTU table (`-mtu 1232`)

| Mode | Record type | Effective MTU |
|-----:|-------------|--------------:|
| 1 | TXT   | 932 |
| 2 | NULL  | 936 |
| 3 | CNAME | 131 |
| 4 | NS    | 131 |
| 5 | MX    | 129 |
| 6 | SRV   | 127 |

TXT/NULL carry ~932 bytes per response; the name types only ~130
(bounded by the 255-octet DNS name limit). Calibration is
**client-side**: the client probes the types (TXT first) and picks the
best; the server does not need a calibration handler — it only has to
answer all six types, remember the probed type per client, and use the
per-type MTU. A real session therefore runs on TXT (or NULL) in
practice; see `TEST-REPORT.md` (E2E).

## Assumptions and gaps (read before integrating)

1. **Name encoding (CNAME/NS/MX/SRV), non-empty payloads.** Verified
   against the reference server with a live Noise handshake replay
   (the oracle test, 18/18): the fork's downstream KCP packets are
   structurally identical and its name labels are lowercase, like the
   reference. But the exact label *splitting* of a >63-character
   payload was chosen from VayDNS's convention (labels of ≤ 63 chars,
   no domain suffix) and confirmed only through that one oracle run —
   a full HTTP Custom session remains the final proof (see E2E caveat).
2. **Calibration token field order.** `ParseCalibrationToken` reads
   `1-<NameSize>-<ReceiveSize>` (NameSize first). The order is an
   assumption from the token's shape; the server only uses the token to
   pick the probed type, so a swapped order would not break a session.
3. **Base32 label case on upload.** The fork decodes upload labels
   case-insensitively (uppercases first), so it accepts whatever the
   client sends. Downstream labels are lowercase.
4. **ACK window race.** The first ACK a session sends can advertise
   window 30 instead of 512 when it is flushed before `SetWindowSize`
   applies (the KCP default receive window is 32; 32 − 2 segments =
   30). The pristine upstream server shows the identical behaviour, so
   this is inherited KCP timing, not a fork difference, and it only
   affects the first ACK.
5. **`-diagnostics` is a no-op** (documented, logs one line). The
   reference binary accepts the flag; no diagnostic behaviour was
   observed from it.
6. **E2E status.** The tunnel is proven end to end in this sandbox with
   the upstream `dnstt-client` against the fork (`tests/e2e`, 4/4):
   Noise handshake, KCP, smux stream, and a TCP payload echoed through
   the tunnel, all over TXT. A live HTTP Custom 8.0.10 test against a
   non-sandbox host with a delegated domain is still outstanding.
7. **Not integrated.** This tree is the engine only. Integration into
   `files/slowdns/` (manager, systemd units, install step) is done by
   the parent agent after verification; `files/slowdns/` was not
   touched by this task.

## Testing

See `TEST-REPORT.md`: empty-payload matrix vs the reference (auto
22/22, fixed-NULL 7/7, fixed-TXT 7/7, flags 3/3), live-handshake oracle
(18/18), and full E2E (4/4). Test harness and logs live in `tests/`
(and `tests/e2e/`); lab-only keys (`tests/fork.key`, `tests/potato.key`)
must never be used anywhere else.

## Licence

Upstream DNSTT is public domain (CC0, see `COPYING`). This fork's new
code (`dns/records.go`, the server changes) is written from the public
behaviour specification and is likewise free to use; it contains no
A4N code and no part of the rented potato binary.
