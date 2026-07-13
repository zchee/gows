//go:build !darwin

package main

import (
	"fmt"
	"net"
	"runtime"
)

// notsentLowatSupported reports that TCP_NOTSENT_LOWAT is unavailable on this
// platform, so main rejects -notsent-lowat at startup here instead of failing
// per connection.
const notsentLowatSupported = false

// setNotsentLowat always fails on non-darwin platforms; main's flag validation
// blocks -notsent-lowat before any connection is accepted, so this path exists
// only to keep the accept hook compiling across GOOS values.
func setNotsentLowat(net.Conn, int) error {
	return fmt.Errorf("TCP_NOTSENT_LOWAT is unsupported on GOOS %s", runtime.GOOS)
}

// getNotsentLowat always fails on non-darwin platforms, mirroring
// setNotsentLowat.
func getNotsentLowat(net.Conn) (int, error) {
	return 0, fmt.Errorf("TCP_NOTSENT_LOWAT is unsupported on GOOS %s", runtime.GOOS)
}
