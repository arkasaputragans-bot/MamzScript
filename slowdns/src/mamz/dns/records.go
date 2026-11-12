// Multi-record-type SlowDNS support.
//
// This file extends the upstream (CC0, public domain) dns package with the
// record types, RDATA encodings, record-type parsing, and Limits validation
// needed by the mamzslowdns server. The encoding choices are derived from
// the observed wire behaviour of the reference server (see
// slowdns-potato/BONGKAR-POTATO.md §5) and the public VayDNS fork's
// documented name-encoding approach (base32 payload split into ≤63-octet
// labels). They are NOT copied from any proprietary binary.
//
// One deliberate divergence from VayDNS: the reference server encodes the
// payload name as bare labels terminated by the root, WITHOUT appending
// the tunnel domain. Appending the domain would shrink the capacity below
// the observed effective MTUs (TXT 932, NULL 936, CNAME 131, NS 131,
// MX 129, SRV 127 at -mtu 1232), so the domain suffix is omitted here.
package dns

import (
	"bytes"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	// https://tools.ietf.org/html/rfc1035#section-3.2.2
	RRTypeNS    = 2
	RRTypeCNAME = 5
	RRTypeNULL  = 10
	RRTypeMX    = 15
	RRTypeSRV   = 33
)

// RecordTypeSentinel is the internal "auto" marker (0xff0a = 65386). It is
// used as a table entry at startup (mapped to NULL) and as the marker a
// client uses for "not yet calibrated". It is never a valid wire QTYPE:
// queries carrying it are answered NXDOMAIN, matching the reference
// server's observed wire behaviour.
const RecordTypeSentinel = 0xff0a

// ParseRecordType converts a record-type string to a DNS QTYPE number.
// Accepted forms: "auto" (0), the names "txt", "null", "cname", "ns",
// "mx", "srv" (case-insensitive), and the mode numbers "1"-"6"
// (1=TXT, 2=NULL, 3=CNAME, 4=NS, 5=MX, 6=SRV, matching the order the
// client calibrates in: TXT → NULL → CNAME → NS → MX → SRV).
func ParseRecordType(s string) (uint16, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "auto", "0":
		return 0, nil
	case "txt", "1":
		return RRTypeTXT, nil
	case "null", "2":
		return RRTypeNULL, nil
	case "cname", "3":
		return RRTypeCNAME, nil
	case "ns", "4":
		return RRTypeNS, nil
	case "mx", "5":
		return RRTypeMX, nil
	case "srv", "6":
		return RRTypeSRV, nil
	default:
		return 0, fmt.Errorf("unknown record type %q (want auto, txt, null, cname, ns, mx, srv, or 1-6)", s)
	}
}

// RecordMode returns the 1-6 mode number for a record type (the number
// printed in "DNS mode N effective MTU M" at startup). It returns 0 for
// unknown types and for "auto" (0).
func RecordMode(qtype uint16) int {
	switch qtype {
	case RRTypeTXT:
		return 1
	case RRTypeNULL:
		return 2
	case RRTypeCNAME:
		return 3
	case RRTypeNS:
		return 4
	case RRTypeMX:
		return 5
	case RRTypeSRV:
		return 6
	default:
		return 0
	}
}

// TypeForRecordMode is the inverse of RecordMode.
func TypeForRecordMode(mode int) (uint16, bool) {
	switch mode {
	case 1:
		return RRTypeTXT, true
	case 2:
		return RRTypeNULL, true
	case 3:
		return RRTypeCNAME, true
	case 4:
		return RRTypeNS, true
	case 5:
		return RRTypeMX, true
	case 6:
		return RRTypeSRV, true
	default:
		return 0, false
	}
}

// IsTunnelRecordType reports whether qtype is one of the six record types
// the tunnel answers.
func IsTunnelRecordType(qtype uint16) bool {
	return RecordMode(qtype) != 0
}

// Limits describes the per-record-type size limits a client announces in a
// calibration probe token. NameSize is the maximum DNS name size the
// client can send; ReceiveSize is the maximum response size it can
// receive; Token is the raw token label the limits arrived in; Domain is
// the tunnel domain the limits apply to (empty when not announced).
type Limits struct {
	NameSize    int
	ReceiveSize int
	Token       string
	Domain      string
}

// Validate checks that the announced limits are within the ranges the
// server can honour. It mirrors the reference server's Limits.Validate:
// it range-checks only, and never rejects a plausible announcement.
func (l Limits) Validate() error {
	if l.NameSize < 1 || l.NameSize > 255 {
		return fmt.Errorf("invalid NameSize %d (want 1..255)", l.NameSize)
	}
	if l.ReceiveSize < 80 || l.ReceiveSize > 65535 {
		return fmt.Errorf("invalid ReceiveSize %d (want 80..65535)", l.ReceiveSize)
	}
	return nil
}

// ParseCalibrationToken parses a trailing calibration-probe label of the
// form "1-<hex>-<hex>" (three dash-separated parts; the two hex numbers
// are the client's NameSize and ReceiveSize). It returns ok=false when
// the label is not shaped like a token at all, so the caller can treat
// the query as an ordinary one. The field order (NameSize first,
// ReceiveSize second) is an assumption: the token format is only known
// to be "split into 3 parts, ParseUint base 16, then Limits.Validate"
// (see BONGKAR-POTATO.md §4.4); Validate only range-checks, so either
// order validates for any plausible announcement.
func ParseCalibrationToken(label string) (Limits, bool) {
	parts := strings.Split(label, "-")
	if len(parts) != 3 || parts[0] != "1" {
		return Limits{}, false
	}
	nameSize, err1 := strconv.ParseUint(parts[1], 16, 32)
	recvSize, err2 := strconv.ParseUint(parts[2], 16, 32)
	if err1 != nil || err2 != nil {
		return Limits{}, false
	}
	lim := Limits{
		NameSize:    int(nameSize),
		ReceiveSize: int(recvSize),
		Token:       label,
	}
	if err := lim.Validate(); err != nil {
		return Limits{}, false
	}
	return lim, true
}

// DecodeRDataNULL decodes NULL RDATA as a raw byte slice.
// https://tools.ietf.org/html/rfc1035#section-3.3.10
func DecodeRDataNULL(p []byte) ([]byte, error) { return p, nil }

// EncodeRDataNULL encodes a slice of bytes as NULL RDATA: the payload
// verbatim, with no framing.
// https://tools.ietf.org/html/rfc1035#section-3.3.10
func EncodeRDataNULL(p []byte) []byte { return p }

// base32NameEncoding is the base32 encoding used for name-carried
// payloads (no padding). Uppercase output: DNS names are
// case-insensitive and decoders uppercase before decoding, so the case
// of the emitted labels is a wire-level choice only. (Whether the
// reference server emits upper- or lowercase labels is still
// unverified; see fork README "open questions".)
var base32NameEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// encodePayloadAsName base32-encodes a payload into DNS name labels
// (≤63 octets each) terminated by the root label, and returns the
// uncompressed wire-format name. No tunnel-domain suffix is appended:
// the reference server's observed MTUs prove the name is bare labels
// only (see the package comment above). An empty payload encodes as
// the root (a single zero octet).
func encodePayloadAsName(p []byte) []byte {
	const labelLen = 63
	encoded := make([]byte, base32NameEncoding.EncodedLen(len(p)))
	base32NameEncoding.Encode(encoded, p)
	// Labels are emitted lowercase, like the reference server (and VayDNS):
	// DNS names are case-insensitive on the wire, but a byte-exact
	// comparison against the reference shows lowercase labels. The client
	// uppercases before decoding, so either case decodes the same payload.
	// See TEST-REPORT.md (oracle test).
	for i, b := range encoded {
		if b >= 'A' && b <= 'Z' {
			encoded[i] = b + ('a' - 'A')
		}
	}
	var buf bytes.Buffer
	for len(encoded) > labelLen {
		buf.WriteByte(byte(labelLen))
		buf.Write(encoded[:labelLen])
		encoded = encoded[labelLen:]
	}
	if len(encoded) > 0 {
		buf.WriteByte(byte(len(encoded)))
		buf.Write(encoded)
	}
	buf.WriteByte(0)
	return buf.Bytes()
}

// decodePayloadFromName parses an uncompressed wire-format domain name
// (as produced by encodePayloadAsName), joins its labels, and
// base32-decodes them back to the original payload.
func decodePayloadFromName(data []byte) ([]byte, error) {
	r := bytes.NewReader(data)
	name, err := readName(r)
	if err != nil {
		return nil, err
	}
	joined := bytes.ToUpper(bytes.Join(name, nil))
	payload := make([]byte, base32NameEncoding.DecodedLen(len(joined)))
	n, err := base32NameEncoding.Decode(payload, joined)
	if err != nil {
		return nil, err
	}
	return payload[:n], nil
}

// EncodeRDataCNAME encodes a payload as CNAME RDATA (a domain name).
// https://tools.ietf.org/html/rfc1035#section-3.3.1
func EncodeRDataCNAME(p []byte) []byte { return encodePayloadAsName(p) }

// DecodeRDataCNAME decodes CNAME RDATA back to the original payload.
func DecodeRDataCNAME(data []byte) ([]byte, error) { return decodePayloadFromName(data) }

// EncodeRDataNS encodes a payload as NS RDATA (identical format to CNAME).
// https://tools.ietf.org/html/rfc1035#section-3.3.11
func EncodeRDataNS(p []byte) []byte { return encodePayloadAsName(p) }

// DecodeRDataNS decodes NS RDATA back to the original payload.
func DecodeRDataNS(data []byte) ([]byte, error) { return decodePayloadFromName(data) }

// EncodeRDataMX encodes a payload as MX RDATA: [preference:2][exchange:name].
// The preference is 0.
// https://tools.ietf.org/html/rfc1035#section-3.3.9
func EncodeRDataMX(p []byte) []byte {
	nameWire := encodePayloadAsName(p)
	rdata := make([]byte, 2+len(nameWire))
	binary.BigEndian.PutUint16(rdata, 0)
	copy(rdata[2:], nameWire)
	return rdata
}

// DecodeRDataMX decodes MX RDATA back to the original payload.
func DecodeRDataMX(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, io.ErrUnexpectedEOF
	}
	return decodePayloadFromName(data[2:])
}

// EncodeRDataSRV encodes a payload as SRV RDATA:
// [priority:2][weight:2][port:2][target:name], header fields all 0.
// https://tools.ietf.org/html/rfc2782
func EncodeRDataSRV(p []byte) []byte {
	nameWire := encodePayloadAsName(p)
	rdata := make([]byte, 6+len(nameWire))
	// priority, weight, port are all zero (binary.BigEndian of a
	// zero-filled slice is already 0).
	copy(rdata[6:], nameWire)
	return rdata
}

// DecodeRDataSRV decodes SRV RDATA back to the original payload.
func DecodeRDataSRV(data []byte) ([]byte, error) {
	if len(data) < 6 {
		return nil, io.ErrUnexpectedEOF
	}
	return decodePayloadFromName(data[6:])
}

// EncodeRData encodes a payload as the RDATA for the given record type.
// It returns nil for types the tunnel does not answer.
func EncodeRData(qtype uint16, p []byte) []byte {
	switch qtype {
	case RRTypeTXT:
		return EncodeRDataTXT(p)
	case RRTypeNULL:
		return EncodeRDataNULL(p)
	case RRTypeCNAME:
		return EncodeRDataCNAME(p)
	case RRTypeNS:
		return EncodeRDataNS(p)
	case RRTypeMX:
		return EncodeRDataMX(p)
	case RRTypeSRV:
		return EncodeRDataSRV(p)
	default:
		return nil
	}
}

// DecodeRData decodes RDATA for the given record type back to the
// original payload. It is the inverse of EncodeRData and exists for
// testing; the server only encodes.
func DecodeRData(qtype uint16, data []byte) ([]byte, error) {
	switch qtype {
	case RRTypeTXT:
		return DecodeRDataTXT(data)
	case RRTypeNULL:
		return DecodeRDataNULL(data)
	case RRTypeCNAME:
		return DecodeRDataCNAME(data)
	case RRTypeNS:
		return DecodeRDataNS(data)
	case RRTypeMX:
		return DecodeRDataMX(data)
	case RRTypeSRV:
		return DecodeRDataSRV(data)
	default:
		return nil, fmt.Errorf("cannot decode RDATA for type %d", qtype)
	}
}

// ResponseCap returns the response-size limit used when computing the
// maximum encoded payload for qtype, given the global -mtu value.
// TXT is capped only by the global MTU; NULL is capped at
// min(global, 1232); the name-carried types (CNAME/NS/MX/SRV) are
// capped at min(global, 512), because a name RDATA can never exceed
// the 255-octet DNS name limit and the reference server caps those
// responses at 512 bytes (BONGKAR-POTATO.md §5.5).
func ResponseCap(globalMTU int, qtype uint16) int {
	switch qtype {
	case RRTypeTXT:
		return globalMTU
	case RRTypeNULL:
		if globalMTU < 1232 {
			return globalMTU
		}
		return 1232
	case RRTypeCNAME, RRTypeNS, RRTypeMX, RRTypeSRV:
		if globalMTU < 512 {
			return globalMTU
		}
		return 512
	default:
		return globalMTU
	}
}
