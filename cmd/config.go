package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"os"
	"strings"
	"unicode/utf8"

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

// configOptions carries the flags and test seams for one `osm config` run. Nil
// seams fall back to the real store, environment, TTY check and hidden prompt.
type configOptions struct {
	show            bool   // --show
	contactEmail    string // --contact-email value
	contactEmailSet bool   // --contact-email was passed (an empty value clears it)

	store      *config.Store
	getenv     func(string) string
	isTerminal func() bool
	readSecret func(ctx context.Context, w io.Writer) (string, error)
}

// newConfigCmd builds `osm config`, which saves an API token or a default
// contact email to ~/.osm/config.json, or reports the current setup with --show.
func newConfigCmd() *cobra.Command {
	var o configOptions
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Save your OSM API token or default contact email to ~/.osm/config.json",
		Long: "Save your OSM API token to ~/.osm/config.json.\n\n" +
			"If a token is already saved, you are asked before it is replaced.\n" +
			"Use --contact-email to save the default contact_email for `osm submit`;\n" +
			"--contact-email \"\" clears it.\n" +
			"Use --show to see the saved token, the contact email and which token is in use.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			o.contactEmailSet = cmd.Flags().Changed("contact-email")
			return runConfig(cmd, o)
		},
	}
	cmd.Flags().BoolVar(&o.show, "show", false, "show the saved token (masked), the contact email and whether OSM_API_KEY overrides the token")
	cmd.Flags().StringVar(&o.contactEmail, "contact-email", "", "save the default contact_email for osm submit (empty value clears it)")
	return cmd
}

func runConfig(cmd *cobra.Command, o configOptions) error {
	store := o.store
	if store == nil {
		s, err := config.New()
		if err != nil {
			return err
		}
		store = s
	}
	getenv := o.getenv
	if getenv == nil {
		getenv = os.Getenv
	}

	cfg, err := store.Load()
	if err != nil {
		return err
	}
	envKey := strings.TrimSpace(getenv("OSM_API_KEY"))
	envSet := envKey != ""

	if o.show && o.contactEmailSet {
		return osmerr.Usagef("choose one of --show or --contact-email, not both")
	}

	if o.show {
		showConfig(cmd.OutOrStdout(), store.Path(), cfg.Token, cfg.ContactEmail, envKey)
		return nil
	}

	if o.contactEmailSet {
		return saveContactEmail(cmd.OutOrStdout(), store, cfg, o.contactEmail)
	}

	isTerminal := o.isTerminal
	if isTerminal == nil {
		isTerminal = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	}
	if !isTerminal() {
		return osmerr.Usagef("config requires an interactive terminal to enter the token")
	}

	ctx := cmdContext(cmd)
	out := cmd.OutOrStdout()

	if cfg.Token != "" {
		fmt.Fprintf(out, "A token is already saved: %s\n", maskToken(cfg.Token))
		fmt.Fprint(out, "Replace it? [y/N]: ")
		answer, err := readLine(ctx, cmd.InOrStdin())
		if err != nil {
			return abortOrErr(cmd, err)
		}
		if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
			fmt.Fprintln(out, "Kept the saved token.")
			return nil
		}
	}

	readSecret := o.readSecret
	if readSecret == nil {
		readSecret = readHiddenLine
	}
	fmt.Fprint(out, "Enter OSM API token: ")
	token, err := readSecret(ctx, out)
	if errors.Is(err, io.EOF) {
		err = errInterrupted // Ctrl-D aborts like Ctrl-C
	}
	if err != nil {
		return abortOrErr(cmd, err)
	}

	token = strings.TrimSpace(token)
	if token == "" {
		return osmerr.Usagef("no token entered")
	}
	if !strings.HasPrefix(token, "osm_") {
		fmt.Fprintln(cmd.ErrOrStderr(), "warning: OSM tokens normally start with 'osm_'; saving anyway")
	}

	cfg.Token = token
	if err := store.Save(cfg); err != nil {
		return err
	}

	fmt.Fprintf(out, "Token saved to %s\n", store.Path())
	if envSet {
		fmt.Fprintln(cmd.ErrOrStderr(), "note: OSM_API_KEY is set in this shell and overrides the saved token")
	}
	return nil
}

// saveContactEmail stores email as the default contact_email, or clears it when
// email is blank. The token in cfg is kept as is.
func saveContactEmail(w io.Writer, store *config.Store, cfg config.Config, email string) error {
	email = strings.TrimSpace(email)
	if email != "" {
		addr, err := mail.ParseAddress(email)
		if err != nil || addr.Address != email {
			return osmerr.Usagef("%q is not a valid email address", email)
		}
	}
	cfg.ContactEmail = email
	if err := store.Save(cfg); err != nil {
		return err
	}
	if email == "" {
		fmt.Fprintf(w, "Contact email cleared in %s\n", store.Path())
		return nil
	}
	fmt.Fprintf(w, "Contact email saved to %s\n", store.Path())
	return nil
}

// showConfig prints where the token comes from without revealing it, and the
// saved contact email, as list items with the values in one aligned column.
func showConfig(w io.Writer, path, token, contactEmail, envKey string) {
	saved := "none"
	if token != "" {
		saved = maskToken(token)
	}
	contact := "none"
	if contactEmail != "" {
		contact = contactEmail
	}
	env := "not set"
	if envKey != "" {
		env = maskToken(envKey) + " (overrides the saved token)"
	}
	rows := [][2]string{
		{"config file:", path},
		{"saved token:", saved},
		{"contact email:", contact},
		{"OSM_API_KEY:", env},
	}
	width := 0
	for _, r := range rows {
		width = max(width, len(r[0]))
	}
	for _, r := range rows {
		fmt.Fprintf(w, "- %-*s%s\n", width+3, r[0], r[1])
	}
}

// maskPrefixLen is how many leading runes of a token maskToken reveals.
const maskPrefixLen = 5

// maskToken shows the first five characters of a token of 20 or more, then a
// fixed run of asterisks so the token's length is not revealed.
func maskToken(t string) string {
	if utf8.RuneCountInString(t) < 20 {
		return "set (too short to preview)"
	}
	return string([]rune(t)[:maskPrefixLen]) + "*****"
}

// readLine reads one line from r, returning errInterrupted if ctx is cancelled
// first. EOF before any input reads as an empty line.
func readLine(ctx context.Context, r io.Reader) (string, error) {
	line, err := readRawLine(ctx, r)
	if err == io.EOF {
		return "", nil
	}
	return line, err
}

// readRawLine reads one line from r without its line ending, returning io.EOF
// if r ends before any input and errInterrupted if ctx is cancelled first. It
// reads a byte at a time so nothing past the newline is consumed, leaving the
// rest of stdin for the next prompt.
func readRawLine(ctx context.Context, r io.Reader) (string, error) {
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 1)
		for {
			n, err := r.Read(buf)
			if n == 1 {
				if buf[0] == '\n' {
					ch <- result{line: strings.TrimSuffix(sb.String(), "\r")}
					return
				}
				sb.WriteByte(buf[0])
			}
			if err != nil {
				if err == io.EOF && sb.Len() > 0 {
					err = nil
				}
				ch <- result{line: strings.TrimSuffix(sb.String(), "\r"), err: err}
				return
			}
		}
	}()
	select {
	case <-ctx.Done():
		return "", errInterrupted
	case res := <-ch:
		return res.line, res.err
	}
}

// readHiddenLine reads a token from the terminal with echo off. Echo is turned
// off and restored here, on every return path, while the background read only
// consumes bytes, so a Ctrl-C (a ctx cancel from main) cannot leave echo off.
func readHiddenLine(ctx context.Context, w io.Writer) (string, error) {
	restore, err := disableEcho(os.Stdin.Fd())
	if err != nil {
		return "", fmt.Errorf("turning off terminal echo: %w", err)
	}
	defer restore()

	line, err := readRawLine(ctx, os.Stdin)
	if errors.Is(err, errInterrupted) {
		return "", err
	}
	fmt.Fprintln(w) // newline after the hidden input
	if err != nil {
		return "", fmt.Errorf("reading token: %w", err)
	}
	return line, nil
}
