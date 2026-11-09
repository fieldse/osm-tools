package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fieldse/osm-tools/internal/client"
	"github.com/fieldse/osm-tools/internal/config"
	"github.com/fieldse/osm-tools/internal/ecosystem"
	"github.com/fieldse/osm-tools/internal/osmerr"
	"github.com/fieldse/osm-tools/internal/output"
	"github.com/fieldse/osm-tools/internal/report"
	"github.com/fieldse/osm-tools/internal/termsafe"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// submitOptions carries the parsed flags and test seams for one `osm submit`
// invocation. isTerminal is a seam (S9): nil means "use the real
// term.IsTerminal check on stdin"; tests set it to exercise the non-TTY guard
// and the interactive transcript without a real TTY.
type submitOptions struct {
	file        string // positional REPORT.md (template mode)
	fromJSON    string // --from-json (FILE.json or "-")
	interactive bool   // -i / --interactive
	noDefang    bool   // --no-defang
	dryRun      bool   // --dry-run
	yes         bool   // -y / --yes
	emitJSON    bool   // --emit-json (terminal)
	template    bool   // --template (terminal)

	isTerminal func() bool // seam; nil → real check
	stdin      *lineReader // shared line source; lazily built by lines()
}

// stdinIsTerminal resolves the TTY seam, defaulting to the real check.
func (o *submitOptions) stdinIsTerminal() bool {
	if o.isTerminal != nil {
		return o.isTerminal()
	}
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// lines returns the run's single stdin reader, building it on first use. One
// run must never have two readers on stdin: the wizard and the confirm prompt
// both read it, and a second reader's scanner would race the first's for the
// next line — the confirm answer could be swallowed by an abandoned goroutine
// still parked in a read.
func (o *submitOptions) lines(r io.Reader) *lineReader {
	if o.stdin == nil {
		o.stdin = newLineReader(r)
	}
	return o.stdin
}

// lineReader delivers stdin lines over a channel so prompt loops can select on
// ctx.Done(). This indirection is what makes Ctrl-C work at a prompt: main
// installs a signal handler, which suppresses Go's default kill-on-SIGINT and
// only cancels the root context, so a blocking Scan() on stdin would never
// notice the interrupt and would keep prompting forever.
type lineReader struct {
	lines chan string
	quit  chan struct{}
}

// newLineReader starts a goroutine scanning r until EOF or stop.
func newLineReader(r io.Reader) *lineReader {
	lr := &lineReader{
		lines: make(chan string),
		quit:  make(chan struct{}),
	}
	go func() {
		defer close(lr.lines)
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			select {
			case lr.lines <- sc.Text():
			case <-lr.quit:
				return
			}
		}
	}()
	return lr
}

// stop releases the reader goroutine if it is parked on a send. A goroutine
// blocked in a read on a live TTY cannot be unblocked and outlives this call;
// that is fine, since stop is only reached as the command returns.
func (lr *lineReader) stop() { close(lr.quit) }

// next returns the next line, with ok=false at EOF. A cancelled ctx (Ctrl-C)
// returns errInterrupted.
func (lr *lineReader) next(ctx context.Context) (line string, ok bool, err error) {
	select {
	case <-ctx.Done():
		return "", false, errInterrupted
	case l, open := <-lr.lines:
		if !open {
			return "", false, nil
		}
		return l, true, nil
	}
}

// cmdContext returns the command's context, defaulting to Background when unset
// (cobra leaves it nil unless Execute wired one, which tests skip).
func cmdContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}

// submitLong is the Long help for `osm submit`, naming the three input modes.
const submitLong = `File a threat report to OpenSourceMalware.com. Every run previews the
report and asks for confirmation before sending.

Input modes (give exactly one):
  REPORT.md               the markdown template; osm submit --template prints a blank one
  --from-json FILE.json   a JSON report keyed by API field names (see examples/threat-report.json)
  --from-json -           the same JSON report, read from stdin
  -i, --interactive       a guided wizard; needs a terminal`

// newSubmitCmd builds `osm submit` — file a threat report to OSM. This is the
// tool's first write command, so the pipeline is preview → explicit confirm →
// submit, with --dry-run/--emit-json/--template as no-network escape hatches.
func newSubmitCmd(deps *appDeps) *cobra.Command {
	opts := &submitOptions{}

	cmd := &cobra.Command{
		Use:   "submit [REPORT.md]",
		Short: "File a threat report to OpenSourceMalware.com",
		Long:  submitLong,
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				opts.file = args[0]
			}
			return runSubmit(cmd, deps, opts)
		},
	}

	f := cmd.Flags()
	f.BoolVarP(&opts.interactive, "interactive", "i", false, "compose the report through guided prompts")
	f.StringVar(&opts.fromJSON, "from-json", "", "read the report from `FILE.json` (- reads it from stdin)")
	f.BoolVar(&opts.noDefang, "no-defang", false, "skip IOC defanging (on by default)")
	f.BoolVar(&opts.dryRun, "dry-run", false, "run the local pipeline and stop before dedupe/submit (zero network)")
	f.BoolVarP(&opts.yes, "yes", "y", false, "assume yes to every prompt; required in non-TTY/CI runs")
	f.BoolVar(&opts.emitJSON, "emit-json", false, "print the report as JSON and exit. Does NOT submit; nothing is sent")
	f.BoolVar(&opts.template, "template", false, "print the blank report template and exit")

	return cmd
}

// runSubmit drives the shared pipeline: resolve terminal actions → collect →
// validate → defang → dedupe → preview → confirm → submit → result.
func runSubmit(cmd *cobra.Command, deps *appDeps, opts *submitOptions) error {
	// (1) Terminal actions first — no collect, no network.
	if opts.template && opts.emitJSON {
		return osmerr.Usagef("choose one of --template or --emit-json, not both")
	}
	if opts.template {
		fmt.Fprint(cmd.OutOrStdout(), report.Template())
		return nil
	}

	if opts.emitJSON {
		fmt.Fprintln(cmd.ErrOrStderr(), "--emit-json: the report will be printed as JSON and NOT submitted.")
	}

	// Release the stdin reader goroutine once the run is over.
	defer func() {
		if opts.stdin != nil {
			opts.stdin.stop()
		}
	}()

	// (2) Collect the report from the selected input mode.
	r, err := collectReport(cmd, deps, opts)
	if err != nil {
		return abortOrErr(cmd, err)
	}
	r.ContactEmail = config.ResolveContactEmail(r.ContactEmail, deps.contactEmail)

	// (3) Validate: hard errors block; warnings go to stderr.
	warnings, err := report.Validate(r)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s\n", w)
	}

	// (4) Defang the payload unless the caller opted out.
	if !opts.noDefang {
		r = report.DefangPayload(r)
	}

	// (5) Map onto the wire request (after defang).
	req := toSubmitRequest(r)

	// (6) --emit-json: print the assembled request and stop. No network.
	if opts.emitJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false) // this is terminal output, not an HTML <script> body
		return enc.Encode(req)
	}

	// (7) --dry-run: preview and stop. No dedupe, no submit, zero network.
	if opts.dryRun {
		writePreview(cmd.ErrOrStderr(), req)
		fmt.Fprintln(cmd.ErrOrStderr(), "dry-run: nothing submitted")
		return nil
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// Fail fast before ANY network if confirmation is impossible: a non-TTY run
	// without --yes can never answer the prompt, so refuse here rather than
	// letting the dedupe GET (below) leak the resource identifier first.
	if !opts.yes && !opts.stdinIsTerminal() {
		return osmerr.Usagef(
			"refusing to submit without confirmation; pass --yes in non-interactive runs")
	}

	// (8) Best-effort dedupe: a malicious hit on the resource is a heads-up, not
	// a blocker. A missing token here is ignored — it surfaces at submit time.
	if c, cerr := deps.apiClient(); cerr == nil {
		if res, derr := c.Check(ctx, client.Query{
			Type:       req.ReportType,
			Identifier: req.ResourceIdentifier,
		}); derr == nil && res.Malicious {
			threatID := res.Details.ThreatID
			if threatID == "" {
				threatID = res.Details.ID
			}
			fmt.Fprintf(cmd.ErrOrStderr(),
				"note: %s is already flagged malicious (threat %s)\n",
				termsafe.String(req.ResourceIdentifier), termsafe.String(threatID))
		}
	}

	// (9) Confirm.
	ok, err := confirmSubmit(cmd, opts, req)
	if err != nil {
		return abortOrErr(cmd, err)
	}
	if !ok {
		fmt.Fprintln(cmd.ErrOrStderr(), "aborted")
		return nil
	}

	// (10) Real submit needs a token; surface ErrNoToken here (exit 1).
	c, err := deps.apiClient()
	if err != nil {
		return err
	}

	// (11) Submit. An interrupt landing here is NOT a clean abort: the POST may
	// already have reached OSM, so say so rather than implying nothing was filed.
	res, err := c.SubmitThreat(ctx, req)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("interrupted during submit — the report may or may not have been "+
				"filed; verify with 'osm check %s' or 'osm latest'", req.ResourceIdentifier)
		}
		return submitError(err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "threat_id: %s\n", res.ThreatID)
	if res.Status != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "status: %s\n", res.Status)
	}
	return nil
}

// submitError translates a submit-time API error into a readable message while
// keeping it a plain (non-usage) error so it maps to exit 1. The documented
// caps (403 new-user, 409 duplicate, 429 rate/submission) each get a distinct
// explanation; other errors pass through unchanged.
func submitError(err error) error {
	apiErr, ok := err.(*osmerr.APIError)
	if !ok {
		return err
	}
	switch apiErr.StatusCode {
	case 403:
		return fmt.Errorf("submission rejected (403): new and unverified accounts are "+
			"capped at 3 reports until verified; this lifts once your earlier reports "+
			"are verified: %s", apiErr.Body)
	case 409:
		if id := parseExistingThreatID(apiErr.Body); id != "" {
			return fmt.Errorf("a report for this resource already exists (existing threat %s)", id)
		}
		return fmt.Errorf("a report for this resource already exists: %s", apiErr.Body)
	case 429:
		return fmt.Errorf("rate limited (429): you have hit an OSM submission cap "+
			"(60 requests/min, or the free-tier 10 submissions/hour); wait and retry: %s",
			apiErr.Body)
	default:
		return err
	}
}

// parseExistingThreatID pulls existingThreatId out of a 409 body, if present.
func parseExistingThreatID(body string) string {
	var m struct {
		ExistingThreatID string `json:"existingThreatId"`
	}
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return ""
	}
	return m.ExistingThreatID
}

// collectReport dispatches to the selected input mode (template file, JSON, or
// interactive) and returns the assembled report. It enforces strict mode
// mutual-exclusivity and the bare-invocation usage error.
func collectReport(cmd *cobra.Command, deps *appDeps, opts *submitOptions) (report.Report, error) {
	var given []string
	if opts.file != "" {
		given = append(given, fmt.Sprintf("REPORT.md %q", opts.file))
	}
	if opts.fromJSON != "" {
		given = append(given, fmt.Sprintf("--from-json %q", opts.fromJSON))
	}
	if opts.interactive {
		given = append(given, "-i")
	}

	switch {
	case len(given) == 0:
		return report.Report{}, osmerr.Usagef(
			"no input given; choose one: REPORT.md, --from-json FILE.json|-, or -i")
	case len(given) > 1:
		return report.Report{}, osmerr.Usagef(
			"conflicting inputs: %s; give only one of REPORT.md, --from-json or -i",
			strings.Join(given, ", "))
	}

	switch {
	case opts.file != "":
		data, err := os.ReadFile(opts.file)
		if err != nil {
			return report.Report{}, err
		}
		return report.ParseTemplate(data)

	case opts.fromJSON != "":
		var data []byte
		var err error
		if opts.fromJSON == "-" {
			data, err = io.ReadAll(cmd.InOrStdin())
		} else {
			data, err = os.ReadFile(opts.fromJSON)
		}
		if err != nil {
			return report.Report{}, err
		}
		return report.ParseJSON(data)

	default: // interactive
		return collectInteractive(cmd, deps, opts)
	}
}

// fieldPrompt describes one single-line interactive field: what to call it,
// whether a blank answer is acceptable, what a good answer looks like, and what
// to assume when the user just presses Enter.
type fieldPrompt struct {
	name     string
	required bool
	hint     string            // enum options or a short example, shown on its own line
	def      string            // applied when the answer is blank
	valid    func(string) bool // non-nil → re-prompt until the answer satisfies it
}

// header renders the prompt across two or three lines so a long enum never
// overflows the terminal: the name and required/optional sit on the first line,
// the options or example on an indented second line, and the answer is typed
// after a "> " marker. A default (if any) is shown before the marker as
// "(default: x) > "; it is applied when the answer is blank and never typed into
// the input line.
func (p fieldPrompt) header() string {
	kind := "optional"
	if p.required {
		kind = "required"
	}
	s := fmt.Sprintf("%s (%s)\n", p.name, kind)
	if p.hint != "" {
		s += "  " + p.hint + "\n"
	}
	if p.def != "" {
		s += "(default: " + p.def + ") "
	}
	return s + "> "
}

// blockPrompt describes a multi-line field. The example is the point: these are
// the fields people stall on, so we show what a usable answer looks like rather
// than only naming the field.
type blockPrompt struct {
	name     string
	required bool
	help     string
	example  []string
}

// collectInteractive reads the report fields from stdin in the fixed §10 order.
// Prompts go to stderr; single-line fields take one line, and
// description/payload/evidence are multi-line blocks terminated by a lone "."
// or EOF. Required fields and the report_type enum are re-prompted on a bad
// answer so a typo costs one line rather than the whole wizard (Validate would
// otherwise reject it at the very end, after every other field was typed).
func collectInteractive(cmd *cobra.Command, deps *appDeps, opts *submitOptions) (report.Report, error) {
	if !opts.stdinIsTerminal() {
		return report.Report{}, osmerr.Usagef(
			"--interactive needs a TTY; pipe a JSON report with --from-json - instead")
	}

	ctx := cmdContext(cmd)
	out := cmd.ErrOrStderr()
	lr := opts.lines(cmd.InOrStdin())

	fmt.Fprint(out, "Compose a threat report. Fields marked (required) must be answered;\n"+
		"press Enter to skip an (optional) field or to accept its default. Ctrl-C aborts.\n\n")

	// abort is a sticky error (the errWriter idiom): once a prompt is
	// interrupted, every later ask/askBlock returns immediately without
	// printing, and collectInteractive surfaces it below. This keeps ~15 call
	// sites free of repeated error plumbing.
	var abort error

	// ask prompts until the answer is acceptable. On EOF it returns the default
	// rather than looping — an exhausted stdin can never satisfy a re-prompt.
	ask := func(p fieldPrompt) string {
		if abort != nil {
			return ""
		}
		for {
			fmt.Fprint(out, p.header())
			l, ok, err := lr.next(ctx)
			if err != nil {
				abort = err
				return ""
			}
			if !ok {
				return p.def
			}
			v := strings.TrimSpace(l)
			if v == "" {
				v = p.def
			}
			if v == "" && p.required {
				fmt.Fprintf(out, "  %s is required\n", p.name)
				continue
			}
			if v != "" && p.valid != nil && !p.valid(v) {
				fmt.Fprintf(out, "  %q is not a valid %s\n", v, p.name)
				continue
			}
			return v
		}
	}

	// askBlock reads a multi-line answer terminated by a lone "." or EOF. It
	// re-prompts a blank required block only if stdin still has input.
	askBlock := func(p blockPrompt) string {
		if abort != nil {
			return ""
		}
		for {
			kind := "optional"
			if p.required {
				kind = "required"
			}
			fmt.Fprintf(out, "\n%s (%s)\n  %s\n", p.name, kind, p.help)
			fmt.Fprintln(out, "  Example:")
			for _, l := range p.example {
				fmt.Fprintf(out, "    %s\n", l)
			}
			fmt.Fprintln(out, "  End with a single '.' on its own line.")

			var lines []string
			sawInput := false
			for {
				l, ok, err := lr.next(ctx)
				if err != nil {
					abort = err
					return ""
				}
				if !ok || strings.TrimSpace(l) == "." {
					break
				}
				sawInput = true
				lines = append(lines, l)
			}
			v := strings.TrimSpace(strings.Join(lines, "\n"))
			if v == "" && p.required && sawInput {
				fmt.Fprintf(out, "  %s is required\n", p.name)
				continue
			}
			return v
		}
	}

	var r report.Report

	r.Type = ask(fieldPrompt{
		name:     "report_type",
		required: true,
		hint:     "package|container|repository|url|domain|ip|wallet",
		def:      report.TypePackage,
		valid:    report.IsValidType,
	})
	r.ResourceID = ask(fieldPrompt{
		name:     "resource_identifier",
		required: true,
		hint:     resourceHint(r.Type),
	})
	r.PackageName = ask(fieldPrompt{
		name: "package_name",
		hint: "only if it differs from the resource, e.g. utils",
	})
	r.Registry = ask(fieldPrompt{
		name: "registry",
		hint: strings.Join(ecosystem.All(), "|"),
	})
	r.Publisher = ask(fieldPrompt{
		name: "publisher",
		hint: "the attacker's account that published it (not you)\n" +
			"  e.g. npm/PyPI username, GitHub user or org: baduser",
	})
	r.ContactEmail = ask(fieldPrompt{
		name: "contact_email",
		hint: "so OSM can follow up, e.g. you@example.com",
		def:  deps.contactEmail,
	})
	r.SeverityLevel = ask(fieldPrompt{
		name: "severity_level",
		hint: "critical|high|medium|low",
	})
	r.VersionInfo = ask(fieldPrompt{
		name: "version_info",
		hint: "affected versions, e.g. 1.2.3, 1.2.4",
	})
	r.FirstSeen = ask(fieldPrompt{
		name: "first_seen",
		hint: "YYYY-MM-DD",
	})
	r.LastSeen = ask(fieldPrompt{
		name: "last_seen",
		hint: "YYYY-MM-DD",
	})
	r.OSVAdvisoryURL = ask(fieldPrompt{
		name: "osv_advisory_url",
		hint: "e.g. https://osv.dev/vulnerability/GHSA-xxxx",
	})
	r.Tags = splitCommaList(ask(fieldPrompt{
		name: "tags",
		hint: "comma-separated, lowercase kebab-case, e.g. contagious-interview, infostealer, postinstall\n" +
			"  tag list: https://docs.opensourcemalware.com/tags.md",
	}))

	r.Description = askBlock(blockPrompt{
		name:     "threat_description",
		required: true,
		help:     "What the code does, and how you found it.",
		example: []string{
			"The 1.2.3 release added a postinstall script that reads ~/.npmrc",
			"and POSTs it to a hardcoded host. Not present in the GitHub tag.",
		},
	})
	r.PayloadDescription = askBlock(blockPrompt{
		name: "payload_description",
		help: "Indicators — hosts, URLs, IPs, paths. Live links are defanged before sending.",
		example: []string{
			"postinstall -> node scripts/setup.js",
			"exfil endpoint: http://evil.example.com/collect",
			"reads: ~/.npmrc, ~/.aws/credentials",
		},
	})

	// Evidence: one entry per non-empty line until a lone "." or EOF. Leading
	// "- " bullets are stripped because the template writes evidence as a
	// markdown list, so people reach for the same shape here.
	fmt.Fprintf(out, "\n%s (optional)\n  %s\n", "evidence_references",
		"One URL per line — advisories, diffs, registry pages. Never defanged.")
	fmt.Fprintln(out, "  Example:")
	fmt.Fprintln(out, "    https://osv.dev/vulnerability/GHSA-xxxx")
	fmt.Fprintln(out, "    https://github.com/acme/utils/commit/deadbeef")
	fmt.Fprintln(out, "  End with a single '.' on its own line.")
	for abort == nil {
		l, ok, err := lr.next(ctx)
		if err != nil {
			abort = err
			break
		}
		if !ok || strings.TrimSpace(l) == "." {
			break
		}
		l = strings.TrimPrefix(strings.TrimSpace(l), "- ")
		if l = strings.TrimSpace(l); l != "" {
			r.EvidenceRefs = append(r.EvidenceRefs, l)
		}
	}

	if abort != nil {
		return report.Report{}, abort
	}
	return r, nil
}

// resourceHint returns the resource_identifier format for a report type, per the
// OSM submit-threat-report docs.
func resourceHint(reportType string) string {
	switch reportType {
	case report.TypePackage:
		return "name as it appears in the registry, e.g.\n" +
			"    npm:    @scope/package-name  or  package-name\n" +
			"    pypi:   requests-toolkit\n" +
			"    skills: https://www.clawhub.ai/user/skill-name"
	case report.TypeRepository:
		return "host and path, no https://, e.g. github.com/owner/repo"
	case report.TypeURL:
		return "full URL, e.g. https://example.com/payload"
	case report.TypeDomain:
		return "bare domain, e.g. evil-c2-server.com"
	case report.TypeIP:
		return "IP address, e.g. 192.0.2.1"
	case report.TypeWallet:
		return "wallet address, e.g. 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
	case report.TypeContainer, report.TypeDocker:
		return "image reference, e.g. docker.io/owner/image:latest"
	}
	return "what you're reporting"
}

// splitCommaList splits a comma-separated string, trimming each element and
// dropping blanks. Empty input yields a nil slice (matching template parsing).
func splitCommaList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// confirmSubmit renders the preview and returns whether to proceed. --yes
// auto-confirms; a non-TTY without --yes is a usage error rather than a hang.
func confirmSubmit(cmd *cobra.Command, opts *submitOptions, req client.SubmitRequest) (bool, error) {
	if opts.yes {
		return true, nil
	}
	if !opts.stdinIsTerminal() {
		return false, osmerr.Usagef(
			"refusing to submit without confirmation; pass --yes in non-interactive runs")
	}

	out := cmd.ErrOrStderr()
	writePreview(out, req)
	fmt.Fprint(out, "Submit this report? [y/N]: ")

	line, ok, err := opts.lines(cmd.InOrStdin()).next(cmdContext(cmd))
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil // EOF at the prompt is not a yes
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

// writePreview prints the human summary of the request to w, wrapped to the
// current terminal width.
func writePreview(w io.Writer, req client.SubmitRequest) {
	output.SubmitPreview(w, req, terminalWidth())
}

// terminalWidth reports the width of stderr (where the preview goes), or 0 when
// it isn't a terminal — the renderer falls back to a sensible default.
func terminalWidth() int {
	w, _, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil || w <= 0 {
		return 0
	}
	return w
}

// toSubmitRequest maps the canonical report onto the wire request: it joins the
// evidence list into a pipe-delimited string and forwards the rest verbatim (the
// docker→container rename happens inside client.SubmitThreat).
func toSubmitRequest(r report.Report) client.SubmitRequest {
	return client.SubmitRequest{
		ReportType:         r.Type,
		ResourceIdentifier: r.ResourceID,
		ThreatDescription:  r.Description,
		PackageName:        r.PackageName,
		Registry:           r.Registry,
		Publisher:          r.Publisher,
		ContactEmail:       r.ContactEmail,
		PayloadDescription: r.PayloadDescription,
		SeverityLevel:      r.SeverityLevel,
		EvidenceReferences: strings.Join(r.EvidenceRefs, "|"),
		VersionInfo:        r.VersionInfo,
		FirstSeen:          r.FirstSeen,
		LastSeen:           r.LastSeen,
		OSVAdvisoryURL:     r.OSVAdvisoryURL,
		Tags:               r.Tags,
		Contributors:       r.Contributors,
		DownloadCount:      r.DownloadCount,
	}
}
