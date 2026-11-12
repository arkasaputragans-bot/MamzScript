// mamz-slowdns-server is the server end of a DNS tunnel.
//
// This is the mamzslowdns fork of dnstt-server (upstream: DNSTT by Bam,
// CC0/public domain). Differences from upstream:
//
//   - Answers six record types (TXT, NULL, CNAME, NS, MX, SRV) instead
//     of TXT only; downstream data is encoded per type (see dns/records.go).
//   - New flags: -record-type (auto, 1-6, or a type name; default auto)
//     and -diagnostics (accepted; currently a no-op, see main).
//   - One KCP listener per record type, each with that type's effective
//     MTU, so a client calibrating to a type gets the matching MTU.
//   - recvLoop remembers each client's calibrated record type (from
//     "1-" calibration-probe tokens) and pins a ClientID to the type
//     its session started on.
//   - The per-type effective MTUs at -mtu 1232 are TXT 932, NULL 936,
//     CNAME 131, NS 131, MX 129, SRV 127.
//
// Usage (same as upstream, plus the two flags above):
//
//	mamz-slowdns-server -gen-key [-privkey-file PRIVKEYFILE] [-pubkey-file PUBKEYFILE]
//	mamz-slowdns-server -udp ADDR [-privkey PRIVKEY|-privkey-file PRIVKEYFILE] DOMAIN UPSTREAMADDR
//
// Example:
//
//	mamz-slowdns-server -gen-key -privkey-file server.key -pubkey-file server.pub
//	mamz-slowdns-server -udp :53 -privkey-file server.key t.example.com 127.0.0.1:8000
//
// To generate a persistent server private key, first run with the -gen-key
// option. By default the generated private and public keys are printed to
// standard output. To save them to files instead, use the -privkey-file and
// -pubkey-file options.
//
//	mamz-slowdns-server -gen-key
//	mamz-slowdns-server -gen-key -privkey-file server.key -pubkey-file server.pub
//
// You can give the server's private key as a file or as a hex string.
//
//	-privkey-file server.key
//	-privkey 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
//
// The -udp option controls the address that will listen for incoming DNS
// queries.
//
// The -mtu option controls the maximum size of response UDP payloads.
// Queries that do not advertise requester support for responses of at least
// this size at least this size will be responded to with a FORMERR. The default
// value is maxUDPPayload.
//
// DOMAIN is the root of the DNS zone reserved for the tunnel. See README for
// instructions on setting it up.
//
// UPSTREAMADDR is the TCP address to which incoming tunnelled streams will be
// forwarded.
package main

import (
	"bytes"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"mamzslowdns/dns"
	"mamzslowdns/noise"
	"mamzslowdns/turbotunnel"
)

const (
	// smux streams will be closed after this much time without receiving data.
	idleTimeout = 2 * time.Minute

	// How to set the TTL field in Answer resource records.
	responseTTL = 60

	// How long we may wait for downstream data before sending an empty
	// response. If another query comes in while we are waiting, we'll send
	// an empty response anyway and restart the delay timer for the next
	// response.
	//
	// This number should be less than 2 seconds, which in 2019 was reported
	// to be the query timeout of the Quad9 DoH server.
	// https://dnsencryption.info/imc19-doe.html Section 4.2, Finding 2.4
	maxResponseDelay = 1 * time.Second

	// How long to wait for a TCP connection to upstream to be established.
	upstreamDialTimeout = 30 * time.Second
)

var (
	// We don't send UDP payloads larger than this, in an attempt to avoid
	// network-layer fragmentation. 1280 is the minimum IPv6 MTU, 40 bytes
	// is the size of an IPv6 header (though without any extension headers),
	// and 8 bytes is the size of a UDP header.
	//
	// Control this value with the -mtu command-line option.
	//
	// https://dnsflagday.net/2020/#message-size-considerations
	// "An EDNS buffer size of 1232 bytes will avoid fragmentation on nearly
	// all current networks."
	//
	// On 2020-04-19, the Quad9 resolver was seen to have a UDP payload size
	// of 1232. Cloudflare's was 1452, and Google's was 4096.
	maxUDPPayload = 1280 - 40 - 8

	// recordMode is the record type selected by -record-type: 0 means
	// "auto" (answer all six tunnel types); otherwise it is one of
	// dns.RRTypeTXT/NULL/CNAME/NS/MX/SRV and only that type is answered.
	recordMode uint16

	// diagnosticsEnabled is set by -diagnostics. The flag is accepted
	// for compatibility with the reference server; this build emits no
	// dummy probes and the flag only logs a line at startup.
	diagnosticsEnabled bool
)

// base32Encoding is a base32 encoding without padding.
var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// generateKeypair generates a private key and the corresponding public key. If
// privkeyFilename and pubkeyFilename are respectively empty, it prints the
// corresponding key to standard output; otherwise it saves the key to the given
// file name. The private key is saved with mode 0400 and the public key is
// saved with 0666 (before umask). In case of any error, it attempts to delete
// any files it has created before returning.
func generateKeypair(privkeyFilename, pubkeyFilename string) (err error) {
	// Filenames to delete in case of error (avoid leaving partially written
	// files).
	var toDelete []string
	defer func() {
		for _, filename := range toDelete {
			fmt.Fprintf(os.Stderr, "deleting partially written file %s\n", filename)
			if closeErr := os.Remove(filename); closeErr != nil {
				fmt.Fprintf(os.Stderr, "cannot remove %s: %v\n", filename, closeErr)
				if err == nil {
					err = closeErr
				}
			}
		}
	}()

	privkey, err := noise.GeneratePrivkey()
	if err != nil {
		return err
	}
	pubkey := noise.PubkeyFromPrivkey(privkey)

	if privkeyFilename != "" {
		// Save the privkey to a file.
		f, err := os.OpenFile(privkeyFilename, os.O_RDWR|os.O_CREATE, 0400)
		if err != nil {
			return err
		}
		toDelete = append(toDelete, privkeyFilename)
		err = noise.WriteKey(f, privkey)
		if err2 := f.Close(); err == nil {
			err = err2
		}
		if err != nil {
			return err
		}
	}

	if pubkeyFilename != "" {
		// Save the pubkey to a file.
		f, err := os.Create(pubkeyFilename)
		if err != nil {
			return err
		}
		toDelete = append(toDelete, pubkeyFilename)
		err = noise.WriteKey(f, pubkey)
		if err2 := f.Close(); err == nil {
			err = err2
		}
		if err != nil {
			return err
		}
	}

	// All good, allow the written files to remain.
	toDelete = nil

	if privkeyFilename != "" {
		fmt.Printf("privkey written to %s\n", privkeyFilename)
	} else {
		fmt.Printf("privkey %x\n", privkey)
	}
	if pubkeyFilename != "" {
		fmt.Printf("pubkey  written to %s\n", pubkeyFilename)
	} else {
		fmt.Printf("pubkey  %x\n", pubkey)
	}

	return nil
}

// readKeyFromFile reads a key from a named file.
func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return noise.ReadKey(f)
}

// handleStream bidirectionally connects a client stream with a TCP socket
// addressed by upstream.
func handleStream(stream *smux.Stream, upstream string, conv uint32) error {
	dialer := net.Dialer{
		Timeout: upstreamDialTimeout,
	}
	upstreamConn, err := dialer.Dial("tcp", upstream)
	if err != nil {
		return fmt.Errorf("stream %08x:%d connect upstream: %v", conv, stream.ID(), err)
	}
	defer upstreamConn.Close()
	upstreamTCPConn := upstreamConn.(*net.TCPConn)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(stream, upstreamTCPConn)
		if err == io.EOF {
			// smux Stream.Write may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy stream←upstream: %v", conv, stream.ID(), err)
		}
		upstreamTCPConn.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(upstreamTCPConn, stream)
		if err == io.EOF {
			// smux Stream.WriteTo may return io.EOF.
			err = nil
		}
		if err != nil && !errors.Is(err, io.ErrClosedPipe) {
			log.Printf("stream %08x:%d copy upstream←stream: %v", conv, stream.ID(), err)
		}
		upstreamTCPConn.CloseWrite()
	}()
	wg.Wait()

	return nil
}

// acceptStreams wraps a KCP session in a Noise channel and an smux.Session,
// then awaits smux streams. It passes each stream to handleStream.
func acceptStreams(conn *kcp.UDPSession, privkey []byte, upstream string) error {
	// Put a Noise channel on top of the KCP conn.
	rw, err := noise.NewServer(conn, privkey)
	if err != nil {
		return err
	}

	// Put an smux session on top of the encrypted Noise channel.
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = idleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024 // default is 65536
	sess, err := smux.Server(rw, smuxConfig)
	if err != nil {
		return err
	}
	defer sess.Close()

	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Printf("AcceptStream temporary error: %v", err)
				continue
			}
			return err
		}
		log.Printf("begin stream %08x:%d", conn.GetConv(), stream.ID())
		go func() {
			defer func() {
				log.Printf("end stream %08x:%d", conn.GetConv(), stream.ID())
				stream.Close()
			}()
			err := handleStream(stream, upstream, conn.GetConv())
			if err != nil {
				log.Printf("stream %08x:%d handleStream: %v", conn.GetConv(), stream.ID(), err)
			}
		}()
	}
}

// acceptSessions listens for incoming KCP connections and passes them to
// acceptStreams.
func acceptSessions(ln *kcp.Listener, privkey []byte, mtu int, upstream string) error {
	for {
		conn, err := ln.AcceptKCP()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				log.Printf("AcceptKCP temporary error: %v", err)
				continue
			}
			return err
		}
		log.Printf("begin session %08x", conn.GetConv())
		// Permit coalescing the payloads of consecutive sends.
		conn.SetStreamMode(true)
		// Disable the dynamic congestion window (limit only by the
		// maximum of local and remote static windows).
		conn.SetNoDelay(
			0, // default nodelay
			0, // default interval
			0, // default resend
			1, // nc=1 => congestion window off
		)
		conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
		if rc := conn.SetMtu(mtu); !rc {
			panic(rc)
		}
		go func() {
			defer func() {
				log.Printf("end session %08x", conn.GetConv())
				conn.Close()
			}()
			err := acceptStreams(conn, privkey, upstream)
			if err != nil && !errors.Is(err, io.ErrClosedPipe) {
				log.Printf("session %08x acceptStreams: %v", conn.GetConv(), err)
			}
		}()
	}
}

// nextPacket reads the next length-prefixed packet from r, ignoring padding. It
// returns a nil error only when a packet was read successfully. It returns
// io.EOF only when there were 0 bytes remaining to read from r. It returns
// io.ErrUnexpectedEOF when EOF occurs in the middle of an encoded packet.
//
// The prefixing scheme is as follows. A length prefix L < 0xe0 means a data
// packet of L bytes. A length prefix L >= 0xe0 means padding of L - 0xe0 bytes
// (not counting the length of the length prefix itself).
func nextPacket(r *bytes.Reader) ([]byte, error) {
	// Convert io.EOF to io.ErrUnexpectedEOF.
	eof := func(err error) error {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}

	for {
		prefix, err := r.ReadByte()
		if err != nil {
			// We may return a real io.EOF only here.
			return nil, err
		}
		if prefix >= 224 {
			paddingLen := prefix - 224
			_, err := io.CopyN(ioutil.Discard, r, int64(paddingLen))
			if err != nil {
				return nil, eof(err)
			}
		} else {
			p := make([]byte, int(prefix))
			_, err = io.ReadFull(r, p)
			return p, eof(err)
		}
	}
}

// responseFor constructs a response dns.Message that is appropriate for query.
// Along with the dns.Message, it returns the query's decoded data payload. If
// the returned dns.Message is nil, it means that there should be no response to
// this query. If the returned dns.Message has an Rcode() of dns.RcodeNoError,
// the message is a candidate for for carrying downstream data in a record
// of the query's type.
func responseFor(query *dns.Message, domain dns.Name) (*dns.Message, []byte) {
	return responseForMode(query, domain, recordMode)
}

// responseForMode is responseFor with an explicit record-type mode, so
// that computeMaxEncodedPayload can measure a type's capacity without
// being subject to the configured -record-type mode. A mode of 0 means
// "auto" (answer all six tunnel types).
func responseForMode(query *dns.Message, domain dns.Name, mode uint16) (*dns.Message, []byte) {
	resp := &dns.Message{
		ID:       query.ID,
		Flags:    0x8000, // QR = 1, RCODE = no error
		Question: query.Question,
	}

	if query.Flags&0x8000 != 0 {
		// QR != 0, this is not a query. Don't even send a response.
		return nil, nil
	}

	// Check for EDNS(0) support. Include our own OPT RR only if we receive
	// one from the requester.
	// https://tools.ietf.org/html/rfc6891#section-6.1.1
	// "Lack of presence of an OPT record in a request MUST be taken as an
	// indication that the requester does not implement any part of this
	// specification and that the responder MUST NOT include an OPT record
	// in its response."
	payloadSize := 0
	for _, rr := range query.Additional {
		if rr.Type != dns.RRTypeOPT {
			continue
		}
		if len(resp.Additional) != 0 {
			// https://tools.ietf.org/html/rfc6891#section-6.1.1
			// "If a query message with more than one OPT RR is
			// received, a FORMERR (RCODE=1) MUST be returned."
			resp.Flags |= dns.RcodeFormatError
			log.Printf("FORMERR: more than one OPT RR")
			return resp, nil
		}
		resp.Additional = append(resp.Additional, dns.RR{
			Name:  dns.Name{},
			Type:  dns.RRTypeOPT,
			Class: 4096, // responder's UDP payload size
			TTL:   0,
			Data:  []byte{},
		})
		additional := &resp.Additional[0]

		version := (rr.TTL >> 16) & 0xff
		if version != 0 {
			// https://tools.ietf.org/html/rfc6891#section-6.1.1
			// "If a responder does not implement the VERSION level
			// of the request, then it MUST respond with
			// RCODE=BADVERS."
			resp.Flags |= dns.ExtendedRcodeBadVers & 0xf
			additional.TTL = (dns.ExtendedRcodeBadVers >> 4) << 24
			log.Printf("BADVERS: EDNS version %d != 0", version)
			return resp, nil
		}

		payloadSize = int(rr.Class)
	}
	if payloadSize < 512 {
		// https://tools.ietf.org/html/rfc6891#section-6.1.1 "Values
		// lower than 512 MUST be treated as equal to 512."
		payloadSize = 512
	}
	// We will return RcodeFormatError if payloadSize is too small, but
	// first, check the name in order to set the AA bit properly.

	// There must be exactly one question.
	if len(query.Question) != 1 {
		resp.Flags |= dns.RcodeFormatError
		log.Printf("FORMERR: too few or too many questions (%d)", len(query.Question))
		return resp, nil
	}
	question := query.Question[0]
	// Check the name to see if it ends in our chosen domain, and extract
	// all that comes before the domain if it does. If it does not, we will
	// return RcodeNameError below, but prefer to return RcodeFormatError
	// for payload size if that applies as well.
	prefix, ok := question.Name.TrimSuffix(domain)
	if !ok {
		// Not a name we are authoritative for.
		resp.Flags |= dns.RcodeNameError
		log.Printf("NXDOMAIN: not authoritative for %s", question.Name)
		return resp, nil
	}
	resp.Flags |= 0x0400 // AA = 1

	if query.Opcode() != 0 {
		// We don't support OPCODE != QUERY.
		resp.Flags |= dns.RcodeNotImplemented
		log.Printf("NOTIMPL: unrecognized OPCODE %d", query.Opcode())
		return resp, nil
	}

	if question.Type == dns.RecordTypeSentinel || !dns.IsTunnelRecordType(question.Type) {
		// We only answer the six tunnel record types (TXT, NULL,
		// CNAME, NS, MX, SRV). Anything else (A, AAAA, OPT probes,
		// or the internal 0xff0a sentinel sent as a wire QTYPE) is
		// silently NXDOMAIN, matching the reference server's
		// observed wire behaviour.
		// No log message here; it's common for recursive resolvers
		// to send NS or A queries when the client only asked for a
		// tunnel type. I suspect this is related to QNAME
		// minimization, but I'm not sure.
		// https://tools.ietf.org/html/rfc7816
		// log.Printf("NXDOMAIN: QTYPE %d not a tunnel type", question.Type)
		resp.Flags |= dns.RcodeNameError
		return resp, nil
	}

	if mode != 0 && question.Type != mode {
		// Fixed -record-type mode: only the configured type is
		// answered; the rest are silently NXDOMAIN.
		resp.Flags |= dns.RcodeNameError
		return resp, nil
	}

	encoded := bytes.ToUpper(bytes.Join(prefix, nil))
	payload := make([]byte, base32Encoding.DecodedLen(len(encoded)))
	n, err := base32Encoding.Decode(payload, encoded)
	if err != nil {
		// Base32 error, make like the name doesn't exist.
		resp.Flags |= dns.RcodeNameError
		log.Printf("NXDOMAIN: invalid query encoding: %v", err)
		return resp, nil
	}
	payload = payload[:n]

	// We require clients to support EDNS(0) with a minimum payload size;
	// otherwise we would have to set a small KCP MTU (only around 200
	// bytes). https://tools.ietf.org/html/rfc6891#section-7 "If there is a
	// problem with processing the OPT record itself, such as an option
	// value that is badly formatted or that includes out-of-range values, a
	// FORMERR MUST be returned."
	if payloadSize < maxUDPPayload {
		resp.Flags |= dns.RcodeFormatError
		log.Printf("FORMERR: requester payload size %d is too small (minimum %d)", payloadSize, maxUDPPayload)
		return resp, nil
	}

	return resp, payload
}

// record represents a DNS message appropriate for a response to a previously
// received query, along with metadata necessary for sending the response.
// recvLoop sends instances of record to sendLoop via a channel. sendLoop
// receives instances of record and may fill in the message's Answer section
// before sending it.
type record struct {
	Resp     *dns.Message
	Addr     net.Addr
	ClientID turbotunnel.ClientID
	// Conn is the per-record-type virtual PacketConn that holds this
	// client's downstream queue (set by recvLoop from the query's
	// effective record type).
	Conn *turbotunnel.QueuePacketConn
}

// detectCalibrationProbe checks whether a query's name prefix (the labels
// before the tunnel domain) ends in a calibration-probe token: a trailing
// label "1-<hex>-<hex>" preceded by a single-byte label. It returns the
// probed record type and true when the token parses and its Limits
// validate; otherwise it returns false and the query is treated as an
// ordinary one. The probed type is the query's QTYPE unless the
// single-byte label is a mode digit '1'-'6', in which case that wins.
// (The token's field order is an assumption; see
// dns.ParseCalibrationToken.)
func detectCalibrationProbe(prefix dns.Name, qtype uint16) (uint16, bool) {
	if len(prefix) < 2 {
		return 0, false
	}
	tokenLabel := prefix[len(prefix)-1]
	if _, ok := dns.ParseCalibrationToken(string(tokenLabel)); !ok {
		return 0, false
	}
	if len(prefix[len(prefix)-2]) != 1 {
		return 0, false
	}
	probed := qtype
	if b := prefix[len(prefix)-2][0]; b >= '1' && b <= '6' {
		if t, ok := dns.TypeForRecordMode(int(b - '0')); ok {
			probed = t
		}
	}
	return probed, true
}

// recvLoop repeatedly calls dnsConn.ReadFrom, extracts the packets contained in
// the incoming DNS queries, and puts them on the incoming queue of the
// QueuePacketConn for the query's record type. Whenever a query calls
// for a response, constructs a partial response and passes it to
// sendLoop over ch.
func recvLoop(domain dns.Name, dnsConn net.PacketConn, ttConns map[uint16]*turbotunnel.QueuePacketConn, ch chan<- *record) error {
	// pinned maps a ClientID to the record type its session started
	// on, so all of a session's packets reach the same KCP listener.
	// calibrated maps a ClientID to the record type a calibration
	// probe announced for it. Both are only touched by this
	// goroutine.
	pinned := make(map[turbotunnel.ClientID]uint16)
	calibrated := make(map[turbotunnel.ClientID]uint16)
	for {
		var buf [4096]byte
		n, addr, err := dnsConn.ReadFrom(buf[:])
		if err != nil {
			return err
		}

		// Got a UDP packet. Try to parse it as a DNS message.
		query, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			log.Printf("cannot parse DNS query: %v", err)
			continue
		}

		resp, payload := responseFor(&query, domain)
		// Extract the ClientID from the payload.
		var clientID turbotunnel.ClientID
		n = copy(clientID[:], payload)
		payload = payload[n:]
		var ttConn *turbotunnel.QueuePacketConn
		if n == len(clientID) {
			// Route this client's packets to the listener for
			// the record type its session runs on.
			routeType := uint16(0)
			if resp != nil && resp.Rcode() == dns.RcodeNoError && len(query.Question) == 1 {
				qtype := query.Question[0].Type
				routeType = qtype
				if prefix, ok := query.Question[0].Name.TrimSuffix(domain); ok {
					if probed, isProbe := detectCalibrationProbe(prefix, qtype); isProbe {
						// A calibration probe is routed to
						// the NULL handler (the sentinel
						// 0xff0a maps to NULL), while the
						// probed type is remembered for
						// the client.
						calibrated[clientID] = probed
						routeType = dns.RRTypeNULL
					}
				}
				if pinnedType, ok := pinned[clientID]; ok {
					routeType = pinnedType
				} else {
					pinned[clientID] = routeType
				}
				if ttConns[routeType] == nil {
					// No listener for the routed type
					// (only possible for a probe in a
					// fixed -record-type mode): fall back
					// to the query's own type.
					routeType = qtype
					pinned[clientID] = routeType
				}
			}
			ttConn = ttConns[routeType]
			// Discard padding and pull out the packets contained in
			// the payload.
			r := bytes.NewReader(payload)
			for {
				p, err := nextPacket(r)
				if err != nil {
					break
				}
				// Feed the incoming packet to KCP.
				if ttConn != nil {
					ttConn.QueueIncoming(p, clientID)
				}
			}
		} else {
			// Payload is not long enough to contain a ClientID.
			if resp != nil && resp.Rcode() == dns.RcodeNoError {
				resp.Flags |= dns.RcodeNameError
				log.Printf("NXDOMAIN: %d bytes are too short to contain a ClientID", n)
			}
		}
		// If a response is called for, pass it to sendLoop via the channel.
		if resp != nil {
			select {
			case ch <- &record{resp, addr, clientID, ttConn}:
			default:
			}
		}
	}
}

// sendLoop repeatedly receives records from ch. Those that represent an error
// response, it sends on the network immediately. Those that represent a
// response capable of carrying data, it packs full of as many packets as will
// fit while keeping the total size under the response-size limit for the
// record's type, then sends it.
func sendLoop(dnsConn net.PacketConn, ch <-chan *record, maxEncodedPayload map[uint16]int) error {
	var nextRec *record
	for {
		rec := nextRec
		nextRec = nil

		if rec == nil {
			var ok bool
			rec, ok = <-ch
			if !ok {
				break
			}
		}

		if rec.Resp.Rcode() == dns.RcodeNoError && len(rec.Resp.Question) == 1 {
			// If it's a non-error response, we can fill the Answer
			// section with downstream packets.

			// Any changes to how responses are built need to happen
			// also in computeMaxEncodedPayload.
			rec.Resp.Answer = []dns.RR{
				{
					Name:  rec.Resp.Question[0].Name,
					Type:  rec.Resp.Question[0].Type,
					Class: rec.Resp.Question[0].Class,
					TTL:   responseTTL,
					Data:  nil, // will be filled in below
				},
			}

			var payload bytes.Buffer
			limit := maxEncodedPayload[rec.Resp.Question[0].Type]
			// We loop and bundle as many packets from OutgoingQueue
			// into the response as will fit. Any packet that would
			// overflow the capacity of the DNS response, we stash
			// to be bundled into a future response.
			timer := time.NewTimer(maxResponseDelay)
			timerExpired := false
			for {
				var p []byte
				unstash := rec.Conn.Unstash(rec.ClientID)
				outgoing := rec.Conn.OutgoingQueue(rec.ClientID)
				// Prioritize taking a packet first from the
				// stash, then from the outgoing queue, then
				// finally check for the expiration of the timer
				// or for a receive on ch (indicating a new
				// query that we must respond to).
				select {
				case p = <-unstash:
				default:
					select {
					case p = <-unstash:
					case p = <-outgoing:
					default:
						select {
						case p = <-unstash:
						case p = <-outgoing:
						case <-timer.C:
							timerExpired = true
						case nextRec = <-ch:
						}
					}
				}
				// We wait for the first packet in a bundle
				// only. The second and later packets must be
				// immediately available or they will be omitted
				// from this bundle.
				if !timerExpired && !timer.Stop() {
					<-timer.C
				}
				timer.Reset(0)
				timerExpired = false

				if len(p) == 0 {
					// timer expired or receive on ch, we
					// are done with this response.
					break
				}

				limit -= 2 + len(p)
				if payload.Len() == 0 {
					// No packet length check for the first
					// packet; if it's too large, we allow
					// it to be truncated and dropped by the
					// receiver.
				} else if limit < 0 {
					// Stash this packet to send in the next
					// response.
					rec.Conn.Stash(p, rec.ClientID)
					break
				}
				if int(uint16(len(p))) != len(p) {
					panic(len(p))
				}
				binary.Write(&payload, binary.BigEndian, uint16(len(p)))
				payload.Write(p)
			}
			if !timerExpired && !timer.Stop() {
				<-timer.C
			}

			rec.Resp.Answer[0].Data = dns.EncodeRData(rec.Resp.Question[0].Type, payload.Bytes())
		}

		buf, err := rec.Resp.WireFormat()
		if err != nil {
			log.Printf("resp WireFormat: %v", err)
			continue
		}
		// Truncate if necessary.
		// https://tools.ietf.org/html/rfc1035#section-4.1.1
		if len(buf) > maxUDPPayload {
			log.Printf("truncating response of %d bytes to max of %d", len(buf), maxUDPPayload)
			buf = buf[:maxUDPPayload]
			buf[2] |= 0x02 // TC = 1
		}

		// Now we actually send the message as a UDP packet.
		_, err = dnsConn.WriteTo(buf, rec.Addr)
		if err != nil {
			// net.ErrClosed means we'll never be able to send on
			// dnsConn, so terminate the loop. Treat all other
			// errors as temporary and simply log them.
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			log.Printf("WriteTo error: %v", err)
			continue
		}
	}
	return nil
}

// computeMaxEncodedPayload computes the maximum amount of downstream
// data, encoded as the RDATA of a record of type qtype, that keeps the
// overall response size less than limit, in the worst case when the
// response answers a query that has a maximum-length name in its
// Question section. Returns 0 in the case that no amount of data makes
// the overall response size small enough.
//
// This function needs to be kept in sync with sendLoop with regard to how it
// builds candidate responses.
func computeMaxEncodedPayload(limit int, qtype uint16) int {
	// 64+64+64+62 octets, needs to be base32-decodable.
	maxLengthName, err := dns.NewName([][]byte{
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		[]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
	})
	if err != nil {
		panic(err)
	}
	{
		// Compute the encoded length of maxLengthName and that its
		// length is actually at the maximum of 255 octets.
		n := 0
		for _, label := range maxLengthName {
			n += len(label) + 1
		}
		n += 1 // For the terminating null label.
		if n != 255 {
			panic(fmt.Sprintf("max-length name is %d octets, should be %d %s", n, 255, maxLengthName))
		}
	}

	// The requester's advertised UDP payload size is set to the global
	// maximum (not to limit): the EDNS value does not change the wire
	// length of the response, and using the global maximum keeps
	// responseFor from answering FORMERR for the probe (name types
	// are measured with a limit of 512, below the 1232 minimum).
	queryLimit := uint16(maxUDPPayload)
	if int(queryLimit) != maxUDPPayload {
		queryLimit = 0xffff
	}
	query := &dns.Message{
		Question: []dns.Question{
			{
				Name:  maxLengthName,
				Type:  qtype,
				Class: dns.ClassIN,
			},
		},
		// EDNS(0)
		Additional: []dns.RR{
			{
				Name:  dns.Name{},
				Type:  dns.RRTypeOPT,
				Class: queryLimit, // requester's UDP payload size
				TTL:   0,          // extended RCODE and flags
				Data:  []byte{},
			},
		},
	}
	// Measure with this type as the mode, so the mode check in
	// responseFor does not reject the probe question.
	resp, _ := responseForMode(query, dns.Name([][]byte{}), qtype)
	// As in sendLoop.
	resp.Answer = []dns.RR{
		{
			Name:  query.Question[0].Name,
			Type:  query.Question[0].Type,
			Class: query.Question[0].Class,
			TTL:   responseTTL,
			Data:  nil, // will be filled in below
		},
	}

	// Binary search to find the maximum payload length that does not result
	// in a wire-format message whose length exceeds the limit.
	low := 0
	high := 32768
	for low+1 < high {
		mid := (low + high) / 2
		resp.Answer[0].Data = dns.EncodeRData(qtype, make([]byte, mid))
		buf, err := resp.WireFormat()
		if err != nil {
			panic(err)
		}
		if len(buf) <= limit {
			low = mid
		} else {
			high = mid
		}
	}

	return low
}

func run(privkey []byte, domain dns.Name, upstream string, dnsConn net.PacketConn) error {
	defer dnsConn.Close()

	log.Printf("pubkey %x", noise.PubkeyFromPrivkey(privkey))

	if diagnosticsEnabled {
		log.Printf("diagnostics enabled: bounded dummy DNS path probes accepted (no probes are emitted by this build)")
	}

	// We have a variable amount of room in which to encode downstream
	// packets in each response, because each response must contain the
	// query's Question section, which is of variable length. But we cannot
	// give dynamic packet size limits to KCP; the best we can do is set a
	// per-record-type maximum which no packet will exceed. We choose that
	// maximum to keep the response size under the cap for the type, even
	// in the worst case of a maximum-length name in the query's Question
	// section.

	// Startup table: the six tunnel types plus the sentinel entry,
	// which maps to NULL. The order matches the reference server
	// (TXT, CNAME, MX, SRV, NS, NULL, 0xff0a).
	startupTypes := []uint16{
		dns.RRTypeTXT, dns.RRTypeCNAME, dns.RRTypeMX,
		dns.RRTypeSRV, dns.RRTypeNS, dns.RRTypeNULL,
		dns.RecordTypeSentinel,
	}

	// We will run acceptSessions, sendLoop, and recvLoop concurrently. The
	// first one to finish closes the done channel.
	doneChan := make(chan struct{})
	var doneOnce sync.Once
	done := func() { doneOnce.Do(func() { close(doneChan) }) }

	maxEncodedPayload := make(map[uint16]int)
	ttConns := make(map[uint16]*turbotunnel.QueuePacketConn)
	var listeners []*kcp.Listener
	for _, entry := range startupTypes {
		effType := entry
		if effType == dns.RecordTypeSentinel {
			// The sentinel entry maps to NULL.
			effType = dns.RRTypeNULL
		}
		if recordMode != 0 && recordMode != effType {
			continue
		}
		if _, ok := maxEncodedPayload[effType]; !ok {
			maxEncodedPayload[effType] = computeMaxEncodedPayload(dns.ResponseCap(maxUDPPayload, effType), effType)
			// 2 bytes accounts for a packet length prefix.
			mtu := maxEncodedPayload[effType] - 2
			if mtu < 80 {
				if mtu < 0 {
					mtu = 0
				}
				return fmt.Errorf("maximum UDP payload size of %d leaves only %d bytes for payload (record type %d)", maxUDPPayload, mtu, effType)
			}
			// Start up the virtual PacketConn and KCP listener
			// for this record type.
			ttConn := turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, idleTimeout*2)
			ln, err := kcp.ServeConn(nil, 0, 0, ttConn)
			if err != nil {
				return fmt.Errorf("opening KCP listener: %v", err)
			}
			listeners = append(listeners, ln)
			ttConns[effType] = ttConn
			mtuForType := mtu
			go func(ln *kcp.Listener) {
				defer done()
				err := acceptSessions(ln, privkey, mtuForType, upstream)
				if err != nil {
					log.Printf("acceptSessions: %v", err)
				}
			}(ln)
		}
		// One log line per table entry, including the duplicate
		// NULL line for the sentinel entry (mode 2 is logged
		// twice in mode auto and in fixed mode 2; that is the
		// reference server's behaviour, not a bug).
		log.Printf("DNS mode %d effective MTU %d", dns.RecordMode(effType), maxEncodedPayload[effType]-2)
	}
	defer func() {
		for _, ln := range listeners {
			ln.Close()
		}
	}()

	ch := make(chan *record, 100)
	defer close(ch)

	// We could run multiple copies of sendLoop; that would allow more time
	// for each response to collect downstream data before being evicted by
	// another response that needs to be sent.
	go func() {
		defer done()
		err := sendLoop(dnsConn, ch, maxEncodedPayload)
		if err != nil {
			log.Printf("sendLoop: %v", err)
		}
	}()

	go func() {
		defer done()
		err := recvLoop(domain, dnsConn, ttConns, ch)
		if err != nil {
			log.Printf("recvLoop: %v", err)
		}
	}()

	// Wait for any of acceptSessions, sendLoop, or recvLoop to return. In
	// normal operation, we don't expect any of these to return.
	<-doneChan

	return nil
}

func main() {
	var genKey bool
	var privkeyFilename string
	var privkeyString string
	var pubkeyFilename string
	var udpAddr string
	var recordTypeStr string

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), `Usage:
  %[1]s -gen-key -privkey-file PRIVKEYFILE -pubkey-file PUBKEYFILE
  %[1]s -udp ADDR -privkey-file PRIVKEYFILE DOMAIN UPSTREAMADDR

Example:
  %[1]s -gen-key -privkey-file server.key -pubkey-file server.pub
  %[1]s -udp :53 -privkey-file server.key t.example.com 127.0.0.1:8000

`, os.Args[0])
		flag.PrintDefaults()
	}
	flag.BoolVar(&genKey, "gen-key", false, "generate a server keypair; print to stdout or save to files")
	flag.IntVar(&maxUDPPayload, "mtu", maxUDPPayload, "maximum size of DNS responses")
	flag.StringVar(&privkeyString, "privkey", "", fmt.Sprintf("server private key (%d hex digits)", noise.KeyLen*2))
	flag.StringVar(&privkeyFilename, "privkey-file", "", "read server private key from file (with -gen-key, write to file)")
	flag.StringVar(&pubkeyFilename, "pubkey-file", "", "with -gen-key, write server public key to file")
	flag.StringVar(&udpAddr, "udp", "", "UDP address to listen on (required)")
	flag.BoolVar(&diagnosticsEnabled, "diagnostics", false, "enable bounded dummy DNS path probes")
	flag.StringVar(&recordTypeStr, "record-type", "auto", "DNS mode: auto, 1-6")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)

	{
		var err error
		recordMode, err = dns.ParseRecordType(recordTypeStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid -record-type: %v\n", err)
			os.Exit(1)
		}
	}

	if genKey {
		// -gen-key mode.
		if flag.NArg() != 0 || privkeyString != "" || udpAddr != "" {
			flag.Usage()
			os.Exit(1)
		}
		if err := generateKeypair(privkeyFilename, pubkeyFilename); err != nil {
			fmt.Fprintf(os.Stderr, "cannot generate keypair: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Ordinary server mode.
		if flag.NArg() != 2 {
			flag.Usage()
			os.Exit(1)
		}
		domain, err := dns.ParseName(flag.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid domain %+q: %v\n", flag.Arg(0), err)
			os.Exit(1)
		}
		upstream := flag.Arg(1)
		// We keep upstream as a string in order to eventually pass it
		// to net.Dial in handleStream. But for the sake of displaying
		// an error or warning at startup, rather than only when the
		// first stream occurs, we apply some parsing and name
		// resolution checks here.
		{
			upstreamHost, _, err := net.SplitHostPort(upstream)
			if err != nil {
				// host:port format is required in all cases, so
				// this is a fatal error.
				fmt.Fprintf(os.Stderr, "cannot parse upstream address %+q: %v\n", upstream, err)
				os.Exit(1)
			}
			upstreamIPAddr, err := net.ResolveIPAddr("ip", upstreamHost)
			if err != nil {
				// Failure to resolve the host portion is only a
				// warning. The name will be re-resolved on each
				// net.Dial in handleStream.
				log.Printf("warning: cannot resolve upstream host %+q: %v", upstreamHost, err)
			} else if upstreamIPAddr.IP == nil {
				// Handle the special case of an empty string
				// for the host portion, which resolves to a nil
				// IP. This is a fatal error as we will not be
				// able to dial this address.
				fmt.Fprintf(os.Stderr, "cannot parse upstream address %+q: missing host in address\n", upstream)
				os.Exit(1)
			}
		}

		if udpAddr == "" {
			fmt.Fprintf(os.Stderr, "the -udp option is required\n")
			os.Exit(1)
		}
		dnsConn, err := net.ListenPacket("udp", udpAddr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "opening UDP listener: %v\n", err)
			os.Exit(1)
		}

		if pubkeyFilename != "" {
			fmt.Fprintf(os.Stderr, "-pubkey-file may only be used with -gen-key\n")
			os.Exit(1)
		}

		var privkey []byte
		if privkeyFilename != "" && privkeyString != "" {
			fmt.Fprintf(os.Stderr, "only one of -privkey and -privkey-file may be used\n")
			os.Exit(1)
		} else if privkeyFilename != "" {
			var err error
			privkey, err = readKeyFromFile(privkeyFilename)
			if err != nil {
				fmt.Fprintf(os.Stderr, "cannot read privkey from file: %v\n", err)
				os.Exit(1)
			}
		} else if privkeyString != "" {
			var err error
			privkey, err = noise.DecodeKey(privkeyString)
			if err != nil {
				fmt.Fprintf(os.Stderr, "privkey format error: %v\n", err)
				os.Exit(1)
			}
		}
		if len(privkey) == 0 {
			log.Println("generating a temporary one-time keypair")
			log.Println("use the -privkey or -privkey-file option for a persistent server keypair")
			var err error
			privkey, err = noise.GeneratePrivkey()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}

		err = run(privkey, domain, upstream, dnsConn)
		if err != nil {
			log.Fatal(err)
		}
	}
}
