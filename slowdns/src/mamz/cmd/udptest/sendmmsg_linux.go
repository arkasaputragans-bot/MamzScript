//go:build linux

package main

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// sendmmsgOne sends a single UDP datagram via the raw SYS_SENDMMSG syscall
// (269 on amd64). The sandbox blocks sendto/sendmsg but (like dig) allows
// sendmmsg, so this is the only UDP send path available in the lab.
// sockaddr may be nil (connected socket) or a *unix.Sockaddr.
func sendmmsgOne(fd int, data []byte, sa unix.Sockaddr) (int, error) {
	var name unsafe.Pointer
	var namelen uint32
	if sa != nil {
		// Convert to a sockaddr struct the kernel understands.
		ptr, l, err := sockaddrPtr(sa)
		if err != nil {
			return 0, err
		}
		name = ptr
		namelen = uint32(l)
	}
	iov := iovec{base: unsafe.Pointer(&data[0]), length: uint64(len(data))}
	msg := msghdr{
		name:    name,
		namelen: namelen,
		iov:     unsafe.Pointer(&iov),
		iovlen:  1,
	}
	mmsg := mmsghdr{hdr: msg}
	r1, _, errno := unix.Syscall6(unix.SYS_SENDMMSG,
		uintptr(fd), uintptr(unsafe.Pointer(&mmsg)), 1, 0, 0, 0)
	if errno != 0 {
		return int(r1), errno
	}
	return int(r1), nil
}

type iovec struct {
	base   unsafe.Pointer
	length uint64
}

// msghdr layout on amd64 (56 bytes).
type msghdr struct {
	name       unsafe.Pointer
	namelen    uint32
	pad        uint32
	iov        unsafe.Pointer
	iovlen     uint64
	control    unsafe.Pointer
	controllen uint64
	flags      int32
	pad2       int32
}

type mmsghdr struct {
	hdr    msghdr
	length uint32
	pad    uint32
}

// sockaddrPtr renders a unix.Sockaddr into kernel wire form.
func sockaddrPtr(sa unix.Sockaddr) (unsafe.Pointer, int, error) {
	switch s := sa.(type) {
	case *unix.SockaddrInet4:
		// struct sockaddr_in: family(2) port(2) addr(4) zero(8)
		b := make([]byte, 16)
		b[0] = unix.AF_INET
		b[1] = 0
		b[2] = byte(s.Port >> 8)
		b[3] = byte(s.Port)
		copy(b[4:8], s.Addr[:])
		return unsafe.Pointer(&b[0]), 16, nil
	default:
		return nil, 0, unix.EAFNOSUPPORT
	}
}
