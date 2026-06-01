package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/fieldse/osm-tools/internal/config"
	"github.com/fieldse/osm-tools/internal/osmerr"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// resolveBaseURL returns the API base URL, honoring the OSM_BASE_URL test/staging
// seam when set.
func resolveBaseURL() string {
	if v := os.Getenv("OSM_BASE_URL"); v != "" {
		return v
	}
	return defaultBaseURL
}

// newConfigCmd builds `osm config`, which prompts for an API token and saves it
// to ~/.osm/config.json.
func newConfigCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "config",
		Short: "Save your OSM API token to ~/.osm/config.json",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConfig(cmd)
		},
	}
}

func runConfig(cmd *cobra.Command) error {
	store, err := config.New()
	if err != nil {
		return err
	}

	token, err := promptToken(cmd)
	if err != nil {
		return err
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return osmerr.Usagef("no token entered")
	}
	if !strings.HasPrefix(token, "osm_") {
		fmt.Fprintln(cmd.ErrOrStderr(), "warning: OSM tokens normally start with 'osm_'; saving anyway")
	}

	cfg, err := store.Load()
	if err != nil {
		return err
	}
	cfg.Token = token

	if err := store.Save(cfg); err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Token saved to %s\n", store.Path())
	return nil
}

// promptToken reads a token from the terminal with input hidden. If stdin is not
// a terminal (piped/redirected), it returns a usage error rather than echoing.
func promptToken(cmd *cobra.Command) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", osmerr.Usagef("config requires an interactive terminal to enter the token")
	}

	fmt.Fprint(cmd.OutOrStdout(), "Enter OSM API token: ")
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(cmd.OutOrStdout()) // newline after the hidden input
	if err != nil {
		return "", fmt.Errorf("reading token: %w", err)
	}
	return string(b), nil
}
