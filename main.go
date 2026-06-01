package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/fieldse/osm-tools/cmd"
	"github.com/fieldse/osm-tools/internal/exitcode"
)

func main() {
	// Root context cancelled on SIGINT/SIGTERM so Ctrl-C cancels in-flight
	// requests and the rate-limiter wait.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	err := cmd.Execute(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "osm:", err)
	}

	// main is the single place exit codes are decided.
	os.Exit(exitcode.FromError(err))
}
