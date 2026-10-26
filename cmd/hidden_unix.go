//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || zos

package cmd

import "golang.org/x/sys/unix"

// disableEcho turns off terminal echo on fd, keeping canonical line input and
// signal keys, and returns a func that restores the previous state.
func disableEcho(fd uintptr) (restore func(), err error) {
	old, err := unix.IoctlGetTermios(int(fd), ioctlGetTermios)
	if err != nil {
		return nil, err
	}
	st := *old
	st.Lflag &^= unix.ECHO
	st.Lflag |= unix.ICANON | unix.ISIG
	st.Iflag |= unix.ICRNL
	if err := unix.IoctlSetTermios(int(fd), ioctlSetTermios, &st); err != nil {
		return nil, err
	}
	return func() { _ = unix.IoctlSetTermios(int(fd), ioctlSetTermios, old) }, nil
}
