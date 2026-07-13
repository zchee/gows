//go:build darwin

package main

import (
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// notsentLowatSupported reports that TCP_NOTSENT_LOWAT can be applied on this
// platform, so main can reject -notsent-lowat at startup on GOOS values where
// the option is unavailable rather than failing per connection.
const notsentLowatSupported = true

// setNotsentLowat applies TCP_NOTSENT_LOWAT (bytes) to conn's underlying TCP
// socket. It runs on the accept path, once per connection, before the
// WebSocket upgrade; it is never invoked on the message hot path.
func setNotsentLowat(conn net.Conn, bytes int) error {
	rc, err := rawConn(conn)
	if err != nil {
		return err
	}
	var opErr error
	if err := rc.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, bytes)
	}); err != nil {
		return fmt.Errorf("raw conn control: %w", err)
	}
	if opErr != nil {
		return fmt.Errorf("setsockopt TCP_NOTSENT_LOWAT=%d: %w", bytes, opErr)
	}
	return nil
}

// getNotsentLowat reads TCP_NOTSENT_LOWAT back from conn's TCP socket. It is a
// verification-only companion to setNotsentLowat, used to log the effective
// value once and to check the option under test.
func getNotsentLowat(conn net.Conn) (int, error) {
	rc, err := rawConn(conn)
	if err != nil {
		return 0, err
	}
	var (
		value int
		opErr error
	)
	if err := rc.Control(func(fd uintptr) {
		value, opErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT)
	}); err != nil {
		return 0, fmt.Errorf("raw conn control: %w", err)
	}
	if opErr != nil {
		return 0, fmt.Errorf("getsockopt TCP_NOTSENT_LOWAT: %w", opErr)
	}
	return value, nil
}

// rawConn returns conn's syscall.RawConn, requiring conn to expose one (every
// *net.TCPConn does). A connection type without SyscallConn is a programming
// error on this path and is reported rather than silently skipped.
func rawConn(conn net.Conn) (syscall.RawConn, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return nil, fmt.Errorf("connection type %T does not expose a raw syscall conn", conn)
	}
	return sc.SyscallConn()
}
