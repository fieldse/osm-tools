//go:build windows

package cmd

import "golang.org/x/sys/windows"

// disableEcho turns off console echo on fd, keeping line input and Ctrl-C
// handling, and returns a func that restores the previous mode.
func disableEcho(fd uintptr) (restore func(), err error) {
	h := windows.Handle(fd)
	var old uint32
	if err := windows.GetConsoleMode(h, &old); err != nil {
		return nil, err
	}
	st := old&^windows.ENABLE_ECHO_INPUT | windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT
	if err := windows.SetConsoleMode(h, st); err != nil {
		return nil, err
	}
	return func() { _ = windows.SetConsoleMode(h, old) }, nil
}
