//go:build windows

package proxy

import (
	"errors"
	"syscall"
)

// Windows surfaces Winsock errors, not the POSIX errnos: a refused connection
// is WSAECONNREFUSED (10061) and a timed-out one is WSAETIMEDOUT (10060).
// syscall.ECONNREFUSED / ETIMEDOUT on Windows are synthetic values that never
// match the real error returned by the network stack, so a plain
// errors.Is(err, syscall.ECONNREFUSED) is dead code there. We test the Winsock
// codes as well (and keep the POSIX constants for forward-compatibility).
const (
	wsaeconnrefused = syscall.Errno(10061)
	wsaetimedout    = syscall.Errno(10060)
)

func isConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, wsaeconnrefused)
}

func isConnTimeout(err error) bool {
	return errors.Is(err, syscall.ETIMEDOUT) || errors.Is(err, wsaetimedout)
}
