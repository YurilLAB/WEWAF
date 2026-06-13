//go:build !windows

package proxy

import (
	"errors"
	"syscall"
)

// isConnRefused / isConnTimeout classify a backend dial error for log
// granularity. On POSIX the kernel returns the standard ECONNREFUSED /
// ETIMEDOUT errnos, so a direct errors.Is suffices.
func isConnRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }
func isConnTimeout(err error) bool { return errors.Is(err, syscall.ETIMEDOUT) }
