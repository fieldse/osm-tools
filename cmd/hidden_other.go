//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !zos && !windows

package cmd

import (
	"fmt"
	"runtime"
)

// disableEcho reports that hidden input is not supported on this platform.
func disableEcho(uintptr) (restore func(), err error) {
	return nil, fmt.Errorf("hidden input is not supported on %s", runtime.GOOS)
}
