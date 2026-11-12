// Package turbotunnel is facilities for embedding packet-based reliability
// protocols inside other protocols.
//
// https://github.com/net4people/bbs/issues/9
package turbotunnel

import "errors"

// QueueSize is the size of send and receive queues in QueuePacketConn and
// RemoteMap. Upstream dnstt uses 128; the reference server this fork matches
// uses 1024, which also enlarges the KCP sessions' advertised window
// (QueueSize/2, i.e. 512 instead of 64) and hence the tunnel's throughput.
// See TEST-REPORT.md (oracle test), which showed the reference sending
// window 512 while a QueueSize of 128 advertised only 64.
const QueueSize = 1024

var errClosedPacketConn = errors.New("operation on closed connection")
var errNotImplemented = errors.New("not implemented")

// DummyAddr is a placeholder net.Addr, for when a programming interface
// requires a net.Addr but there is none relevant. All DummyAddrs compare equal
// to each other.
type DummyAddr struct{}

func (addr DummyAddr) Network() string { return "dummy" }
func (addr DummyAddr) String() string  { return "dummy" }
