# TEST-REPORT — fork DNSTT bersih ("mamz") vs potato (oracle)

Date: 11 Nov 2026. All tests local loopback only; no VPS was touched.
Fork binary sha256: `14e33f7166eef7cd21bf1e7b6bf24f6e9acab893284dc0802e2bd8a3644229fa`
(`fork/bin/mamz-slowdns-server`, Go 1.27.4).

## Method

* **Oracle:** the rented potato binary, unpacked
  (`work/potato-unpacked`, sha256 `a9d19e39…`), run side by side with
  the fork on different UDP ports (fork 15360, potato 15361), domain
  `t.contoh.invalid`, fresh `-gen-key` keys per server, upstream = a
  TCP listener that records bytes (`tests/upstream.py`, 127.0.0.1:18080).
* **Queries:** `dig` (the only UDP sender that works in this sandbox:
  it uses `connect()` + `sendmmsg()`). Responses are read from
  `strace -f -e trace=sendto,sendmsg` on the server, because the sandbox
  blocks the server's UDP `sendto` (EPERM) — the attempted sends are
  visible in strace even though they never reach `dig`.
* **Harness:** `tests/compare.py` (matrix), `tests/oracle.py` (live
  handshake replay), `tests/e2e/run_e2e.py` (full tunnel),
  `tests/strace_decode.py` (strace → DNS response parser),
  `tests/oracle_one.py` (single-case runs against the fork, potato, or
  the pristine upstream server).
* Lab-only keys: `tests/fork.key` / `tests/potato.key`. Never use them
  anywhere else.

## 1. Empty-payload matrix (`tests/compare.py`) — 39/39

### Phase `auto` — 22/22

| # | Check | Fork | Potato | Result |
|---|-------|------|--------|--------|
| 1 | Startup: 7 mode lines incl. mode 2 twice | `1→932, 3→131, 5→129, 6→127, 4→131, 2→936, 2→936` | identical | PASS |
| 2 | Startup: MTU values 932/936/131/131/129/127 | identical | identical | PASS |
| 3 | TXT empty RDATA identical | `00` (75B total, TTL 60) | `00` | PASS |
| 4 | TXT expected empty RDATA `00` | `00` | — | PASS |
| 5 | NULL empty RDATA identical | 0 bytes (74B total, TTL 60) | 0 bytes | PASS |
| 6 | NULL expected empty RDATA | empty | — | PASS |
| 7 | CNAME empty RDATA identical | `00` (75B) | `00` | PASS |
| 8 | CNAME expected empty RDATA `00` | `00` | — | PASS |
| 9 | NS empty RDATA identical | `00` (75B) | `00` | PASS |
| 10 | NS expected empty RDATA `00` | `00` | — | PASS |
| 11 | MX empty RDATA identical | `000000` (77B) | `000000` | PASS |
| 12 | MX expected empty RDATA `000000` | `000000` | — | PASS |
| 13 | SRV empty RDATA identical | 7 zero bytes (81B) | 7 zero bytes | PASS |
| 14 | SRV expected empty RDATA (7 zero bytes) | 7 zero bytes | — | PASS |
| 15 | A → NXDOMAIN, AN=0 | NXDOMAIN, 62B | NXDOMAIN, 62B | PASS |
| 16 | TYPE 65386 (0xff0a) → NXDOMAIN, AN=0, silent | NXDOMAIN, 62B | NXDOMAIN, 62B | PASS |
| 17 | Illegal base32 label → NXDOMAIN | NXDOMAIN, 47B | NXDOMAIN, 47B | PASS |
| 18 | Illegal base32 label → server log line | logged | logged | PASS |
| 19 | Out-of-domain → NXDOMAIN | NXDOMAIN, 43B | NXDOMAIN, 43B | PASS |
| 20 | Out-of-domain → log line | logged | logged | PASS |
| 21 | EDNS bufsize 512 → FORMERR | FORMERR, 62B | FORMERR, 62B | PASS |
| 22 | No EDNS → FORMERR | FORMERR, 51B | FORMERR, 51B | PASS |

### Phase `fixed2` (NULL only) — 7/7

| Check | Fork | Potato | Result |
|-------|------|--------|--------|
| Startup lines identical | `[2→936, 2→936]` | `[2→936, 2→936]` | PASS |
| TXT → silent NXDOMAIN | NXDOMAIN | NXDOMAIN | PASS |
| NULL → answered | NOERROR, empty RDATA | NOERROR, empty RDATA | PASS |
| CNAME → silent NXDOMAIN | NXDOMAIN | NXDOMAIN | PASS |
| NS → silent NXDOMAIN | NXDOMAIN | NXDOMAIN | PASS |
| MX → silent NXDOMAIN | NXDOMAIN | NXDOMAIN | PASS |
| SRV → silent NXDOMAIN | NXDOMAIN | NXDOMAIN | PASS |

### Phase `fixed1` (TXT only) — 7/7

| Check | Fork | Potato | Result |
|-------|------|--------|--------|
| Startup lines identical | `[1→932]` | `[1→932]` | PASS |
| TXT → answered | NOERROR, RDATA `00` | NOERROR, RDATA `00` | PASS |
| NULL → silent NXDOMAIN | NXDOMAIN | NXDOMAIN | PASS |
| CNAME → silent NXDOMAIN | NXDOMAIN | NXDOMAIN | PASS |
| NS → silent NXDOMAIN | NXDOMAIN | NXDOMAIN | PASS |
| MX → silent NXDOMAIN | NXDOMAIN | NXDOMAIN | PASS |
| SRV → silent NXDOMAIN | NXDOMAIN | NXDOMAIN | PASS |

### Phase `flags` — 3/3

| Check | Result |
|-------|--------|
| `-record-type bogus` rejected with error (`invalid -record-type: unknown record type "bogus" …`) | PASS |
| `-record-type txt` accepted, server kept running | PASS |
| `-diagnostics` accepted, one startup log line | PASS |

## 2. Live-handshake oracle (`tests/oracle.py`) — 18/18

A real Noise NK handshake (captured with `cmd/kcpgen`, which drives a
kcp-go client against each server's public key) is replayed as the DNS
upload (ClientID + two KCP datagrams as length-prefixed chunks), then a
poll query. The downstream bundle is decoded per type and the KCP
packets are compared. Each record type has 3 checks; all 6 types pass
all 3.

Downstream packets on **both** servers, every type (deduped, sorted):

| Packet | cmd | frg | wnd | sn | una | data len |
|--------|----:|----:|----:|---:|----:|---------:|
| PUSH | 81 | 0 | 512 | 0 | 2 | 2 (Noise length prefix) |
| PUSH | 81 | 0 | 512 | 1 | 2 | 48 (Noise handshake response) |
| ACK | 82 | 0 | — (see §4) | 1 | 2 | 0 |

| Type | Structural packets identical | Masked bytes identical (+ label case) | `begin session` on both |
|------|------------------------------|---------------------------------------|--------------------------|
| TXT  | PASS | PASS | PASS |
| NULL | PASS | PASS | PASS |
| CNAME | PASS | PASS (uppercase labels: fork 0, potato 0) | PASS |
| NS   | PASS | PASS (uppercase labels: fork 0, potato 0) | PASS |
| MX   | PASS | PASS (uppercase labels: fork 0, potato 0) | PASS |
| SRV  | PASS | PASS (uppercase labels: fork 0, potato 0) | PASS |

"Masked bytes" = packet bytes with conv, KCP timestamp, and the 48-byte
Noise response data zeroed. Raw RDATA can never be byte-identical for
a live handshake (the KCP timestamp and the Noise ephemeral key differ
per session by design); byte-parity of the encoders themselves is
proven by the empty-payload matrix (§1).

## 3. Full E2E (`tests/e2e/run_e2e.py`) — 4/4

Topology (all loopback): TCP probe → `dnstt-client` (upstream, lab
variant) → DNS/UDP 15370 → fork server (lab variant) → TCP echo
upstream (127.0.0.1:18082). The lab variants differ from the shipped
code **only in the UDP transport**: the sandbox blocks `sendto` with a
destination address (EPERM) and only allows sends on a connected
socket, so the lab client dials a connected UDP socket and the lab
server replies from connected sockets bound (SO_REUSEPORT) to its
listening port. The protocol code (Noise/KCP/smux/multi-type) is
identical to the shipped fork. Lab copies live in
`tests/e2e/lab-server/` and `tests/e2e/lab-client/`.

| # | Check | Result |
|---|-------|--------|
| 1 | Server logs `begin session` (Noise handshake via DNS) | PASS |
| 2 | TCP payload echoed back through the tunnel (`HELLO-E2E-MAMZ-SLOWDNS\n`, 23 bytes, sent = received) | PASS |
| 3 | Echo upstream received the payload | PASS |
| 4 | Record types used by the client: query QTYPEs = `['TXT']` (client negotiates TXT, the highest-MTU type, as designed) | PASS |

Client log confirms the full lifecycle: `begin session …` →
`begin stream …:3` → `end stream …:3`. This run was repeated for the
diagnostic (`tests/e2e/diag_net.sh`): 33/33 queries were TXT, echo
returned.

## 4. What the oracle caught and fixed (3 findings)

1. **KCP window 64 → 512.** The fork initially advertised window 64
   (upstream `QueueSize` 128); potato advertises 512. Fixed by
   `QueueSize` 128 → 1024 in `turbotunnel/consts.go` (documented in
   code). After the fix both servers advertise 512 on every PUSH.
2. **Downstream name labels uppercase → lowercase.** The fork initially
   emitted uppercase base32 labels; potato emits lowercase (as does
   VayDNS). Fixed in `encodePayloadAsName` (lowercase after encoding).
   After the fix both servers emit 0 uppercase label letters on all
   four name types.
3. **ACK window is racy, on upstream too (not a fork bug).** The first
   ACK can advertise 30 (= 32 − 2 segments) when it is flushed before
   `SetWindowSize` applies — the KCP default receive window is 32.
   The pristine upstream `dnstt-server` shows the identical value
   (30) under the same oracle; the fork shows 30, 510 or 512 across
   runs, and potato showed 510 in its run. The ACK window is therefore
   excluded from the structural comparison; PUSH windows (512) are
   compared and match.

## 5. Harness bugs fixed during testing (not fork bugs)

* `tests/strace_decode.py` `unesc()` decoded strace's `\v` as the
  ASCII letter `v` (0x76) instead of 0x0B (and `\f` as `f` = 0x66).
  This corrupted the conv byte of any packet whose conv low byte was
  0x0B/0x0C. Fixed by handling `\a \b \e \f \v`.
* `parse_bundle` treated each `[u16be len][item]` flush-buffer as one
  KCP segment, but one flush-buffer can hold several segments
  (e.g. ACK + PUSH in a 50-byte item). Fixed by parsing segments out
  of each item by their own header length.
* `oracle.py` comparison is now: dedupe retransmissions by (cmd, sn),
  sort by (cmd, sn) (the bundle split across the upload/poll responses
  and the retransmit interleaving are timing), mask conv/ts/Noise
  data, exclude the ACK window (see §4).

## 6. Timing-dependent items (same on both servers, not compared)

* ACK window (30/510/512 — the race in §4).
* Number of KCP retransmissions bundled into the poll response (the
  client never ACKs, so the server resends at increasing intervals).
* Which query response the ACK vs the PUSHes land in (sendLoop
  bundling race).
* KCP timestamps and the Noise ephemeral bytes (random per session).

## 7. What is NOT proven yet

* A live **HTTP Custom 8.0.10** session against the fork. The E2E
  proves the tunnel with the upstream `dnstt-client` (which calibrates
  the same way HC does); the final HC check needs a non-sandbox host
  with a delegated domain.
* Calibration-token field order (`ParseCalibrationToken` reads
  NameSize first) is an assumption; it only affects which type is
  remembered per client, not session establishment.
* `-diagnostics` is a documented no-op in this build.

## 8. Result files

| File | Contents |
|------|----------|
| `tests/matrix-auto.txt` | 22/22 auto-phase results |
| `tests/matrix-fixed2.txt` | 7/7 fixed-NULL results |
| `tests/matrix-fixed1.txt` | 7/7 fixed-TXT results |
| `tests/matrix-flags.txt` | 3/3 flag results |
| `tests/oracle-results.txt` | 18/18 oracle results |
| `tests/e2e/e2e-results.txt` | 4/4 E2E results |
| `tests/fork-auto.log`, `potato-auto.log`, `fork-fixed2.log`, `potato-fixed2.log`, `fork-fixed1.log`, `potato-fixed1.log` | server logs per matrix phase |
| `tests/oracle-fork.log`, `tests/oracle-potato.log` | oracle server logs |
| `tests/e2e/e2e-server.log`, `e2e-client.log`, `e2e-echo.log` | E2E logs |
| `tests/*-strace.log` | raw strace captures behind the comparisons |

**Total: 39 (matrix) + 18 (oracle) + 4 (E2E) = 61/61 checks passed.**
