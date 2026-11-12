// kcpgen is a development tool (not shipped): it captures the exact KCP
// datagrams a dnstt client emits when starting a Noise handshake against
// a server public key, so the datagrams can be replayed verbatim as DNS
// upload payloads when comparing this fork against the reference server.
//
// Usage:
//
//	kcpgen -pubkey-file server.pub -conv 0xAABBCCDD [-wait-ms 1200]
//
// It prints one hex-encoded datagram per line on stdout, then exits.
// The Noise handshake is started in a goroutine (its Read side blocks
// forever on the recording PacketConn); only the emitted datagrams
// matter.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"mamzslowdns/noise"
	"mamzslowdns/turbotunnel"
)

type recConn struct {
	mu      sync.Mutex
	packets [][]byte
}

func (c *recConn) Read(b []byte) (int, error)         { select {} }
func (c *recConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c *recConn) Close() error                       { return nil }
func (c *recConn) LocalAddr() net.Addr                { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1} }
func (c *recConn) RemoteAddr() net.Addr               { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53} }
func (c *recConn) SetDeadline(t time.Time) error      { return nil }
func (c *recConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *recConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *recConn) ReadFrom(p []byte) (int, net.Addr, error) { select {} }
func (c *recConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := append([]byte(nil), p...)
	c.packets = append(c.packets, cp)
	return len(p), nil
}

func main() {
	var pubkeyFile string
	var conv uint
	var waitMs int
	flag.StringVar(&pubkeyFile, "pubkey-file", "", "read server public key from file (required)")
	flag.UintVar(&conv, "conv", 0xAABBCCDD, "KCP conversation number to use")
	flag.IntVar(&waitMs, "wait-ms", 1200, "how long to wait for handshake datagrams")
	flag.Parse()
	if pubkeyFile == "" {
		fmt.Fprintln(os.Stderr, "-pubkey-file is required")
		os.Exit(1)
	}
	f, err := os.Open(pubkeyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	pubkey, err := noise.ReadKey(f)
	f.Close()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	rec := &recConn{}
	raddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
	conn, err := kcp.NewConn3(uint32(conv), raddr, nil, 0, 0, rec)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	conn.SetStreamMode(true)
	conn.SetNoDelay(0, 0, 0, 1)
	conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
	if rc := conn.SetMtu(132); !rc {
		fmt.Fprintln(os.Stderr, "SetMtu failed")
		os.Exit(1)
	}
	// Start the Noise handshake; it blocks waiting for the server's
	// reply (which never arrives here). The emitted handshake datagrams
	// are what we want.
	go func() {
		_, _ = noise.NewClient(conn, pubkey)
	}()
	time.Sleep(time.Duration(waitMs) * time.Millisecond)
	fmt.Printf("conv %08x\n", conv)
	for i, p := range rec.packets {
		fmt.Printf("datagram %d len %d hex %s\n", i, len(p), hex.EncodeToString(p))
	}
	os.Exit(0)
}
