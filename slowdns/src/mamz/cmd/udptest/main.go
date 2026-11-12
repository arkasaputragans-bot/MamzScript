// Command udptest probes which UDP send paths the sandbox allows.
// A listener on 127.0.0.1:19090 records what arrives; four send methods
// are tried in order, each with its own payload so arrivals are attributed:
//  1. connected net.DialUDP + Write (uses sendto/sendmsg internally)
//  2. unconnected net.ListenUDP + WriteTo (uses sendto/sendmsg)
//  3. raw socket + unix.Sendmmsg with an explicit destination sockaddr
//  4. raw connected socket + unix.Sendmmsg with no address
// This decides whether a full E2E (dnstt-client <-> fork server) is possible
// in this sandbox at all, and which transport a lab client/server must use.
package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:19090")
	ln, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Println("listen failed:", err)
		os.Exit(1)
	}
	defer ln.Close()
	got := make(chan string, 16)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, _, err := ln.ReadFromUDP(buf)
			if err != nil {
				return
			}
			got <- string(buf[:n])
		}
	}()

	drain := func(tag string) {
		time.Sleep(300 * time.Millisecond)
		hit := false
		for {
			select {
			case m := <-got:
				fmt.Printf("  received %q\n", m)
				hit = true
			default:
				if hit {
					fmt.Printf("  -> %s: DELIVERED\n", tag)
				} else {
					fmt.Printf("  -> %s: NOT received\n", tag)
				}
				return
			}
		}
	}

	// 1. connected DialUDP + Write
	fmt.Println("1. connected DialUDP + Write")
	c1, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		fmt.Println("  dial failed:", err)
	} else {
		_, err = c1.Write([]byte("via-write"))
		fmt.Println("  write err:", err)
		c1.Close()
	}
	drain("Write")

	// 2. unconnected ListenUDP + WriteTo
	fmt.Println("2. unconnected WriteTo")
	l2, err := net.ListenUDP("udp", nil)
	if err != nil {
		fmt.Println("  listen failed:", err)
	} else {
		_, err = l2.WriteTo([]byte("via-writeto"), addr)
		fmt.Println("  writeto err:", err)
		l2.Close()
	}
	drain("WriteTo")

	// 3. raw socket + Sendmmsg with destination
	fmt.Println("3. raw Sendmmsg with destination sockaddr")
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		fmt.Println("  socket failed:", err)
	} else {
		sa := &unix.SockaddrInet4{Port: 19090, Addr: [4]byte{127, 0, 0, 1}}
		n, err := sendmmsgOne(fd, []byte("via-sendmmsg"), sa)
		fmt.Printf("  sendmmsg n=%d err=%v\n", n, err)
		unix.Close(fd)
	}
	drain("Sendmmsg")

	// 4. raw socket, connected, Sendmmsg without address
	fmt.Println("4. raw connected socket + Sendmmsg")
	fd2, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		fmt.Println("  socket failed:", err)
	} else {
		sa := &unix.SockaddrInet4{Port: 19090, Addr: [4]byte{127, 0, 0, 1}}
		if err := unix.Connect(fd2, sa); err != nil {
			fmt.Println("  connect err:", err)
		} else {
			n, err := sendmmsgOne(fd2, []byte("via-sendmmsg-conn"), nil)
			fmt.Printf("  sendmmsg n=%d err=%v\n", n, err)
		}
		unix.Close(fd2)
	}
	drain("Sendmmsg-connected")
}
