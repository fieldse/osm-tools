package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

// errInterrupted marks a Ctrl-C at a prompt. Nothing has been sent or saved at
// that point, so callers report it like declining a confirm.
var errInterrupted = errors.New("interrupted")

// abortOrErr reports a Ctrl-C at a prompt as "aborted" and returns nil; any
// other error passes through. The leading newline lands the message clear of
// the half-finished prompt line the terminal echoed "^C" onto.
func abortOrErr(cmd *cobra.Command, err error) error {
	if errors.Is(err, errInterrupted) {
		fmt.Fprintln(cmd.ErrOrStderr(), "\naborted")
		return nil
	}
	return err
}
