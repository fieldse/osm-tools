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
	"github.com/fieldse/osm-tools/internal/osmerr"
	"github.com/fieldse/osm-tools/internal/report"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// submitOptions carries the parsed flags and test seams for one `osm submit`
// invocation. isTerminal is a seam (S9): nil means "use the real
// term.IsTerminal check on stdin"; tests set it to exercise the non-TTY guard
// and the interactive transcript without a real TTY.
type submitOptions struct {
	file        string // positional FILE (template mode)
	fromJSON    string // --from-json (FILE or "-")
	interactive bool   // -i / --interactive
	noDefang    bool   // --no-defang
	dryRun      bool   // --dry-run
	yes         bool   // -y / --yes
	emitJSON    bool   // --emit-json (terminal)
	template    bool   // --template (terminal)

	isTerminal func() bool // seam; nil → real check
}

// stdinIsTerminal resolves the TTY seam, defaulting to the real check.
func (o *submitOptions) stdinIsTerminal() bool {
	if o.isTerminal != nil {
		return o.isTerminal()
	}
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// newSubmitCmd builds `osm submit` — file a threat report to OSM. This is the
// tool's first write command, so the pipeline is preview → explicit confirm →
// submit, with --dry-run/--emit-json/--template as no-network escape hatches.
func newSubmitCmd(deps *appDeps) *cobra.Command {
	opts := &submitOptions{}

	cmd := &cobra.Command{
		Use:   "submit [FILE]",
		Short: "File a threat report to OpenSourceMalware.com",
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
	f.StringVar(&opts.fromJSON, "from-json", "", "read a structured JSON report (FILE or - for stdin)")
	f.BoolVar(&opts.noDefang, "no-defang", false, "skip IOC defanging (on by default)")
	f.BoolVar(&opts.dryRun, "dry-run", false, "run the local pipeline and stop before dedupe/submit (zero network)")
	f.BoolVarP(&opts.yes, "yes", "y", false, "assume yes to every prompt; required in non-TTY/CI runs")
	f.BoolVar(&opts.emitJSON, "emit-json", false, "print the assembled report as JSON and exit (never submits)")
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

	// (2) Collect the report from the selected input mode.
	r, err := collectReport(cmd, opts)
	if err != nil {
		return err
	}

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
			fmt.Fprintf(cmd.ErrOrStderr(),
				"note: %s is already flagged malicious (threat %s)\n",
				req.ResourceIdentifier, res.Details.ID)
		}
	}

	// (9) Confirm.
	ok, err := confirmSubmit(cmd, opts, req)
	if err != nil {
		return err
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

	// (11) Submit.
	res, err := c.SubmitThreat(ctx, req)
	if err != nil {
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
func collectReport(cmd *cobra.Command, opts *submitOptions) (report.Report, error) {
	selectors := 0
	if opts.file != "" {
		selectors++
	}
	if opts.fromJSON != "" {
		selectors++
	}
	if opts.interactive {
		selectors++
	}

	switch {
	case selectors == 0:
		return report.Report{}, osmerr.Usagef(
			"no input given; choose one: a template FILE, --from-json FILE|-, or --interactive")
	case selectors > 1:
		return report.Report{}, osmerr.Usagef("choose one input mode: a template FILE, --from-json, or --interactive")
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
		return collectInteractive(cmd, opts)
	}
}

// collectInteractive reads the report fields from stdin in the fixed §10 order.
// Prompts go to stderr; each single-line field takes one line (blank = empty),
// and description/payload/evidence are multi-line blocks terminated by a lone
// "." or EOF.
func collectInteractive(cmd *cobra.Command, opts *submitOptions) (report.Report, error) {
	if !opts.stdinIsTerminal() {
		return report.Report{}, osmerr.Usagef(
			"--interactive needs a TTY; pipe a JSON report with --from-json - instead")
	}

	out := cmd.ErrOrStderr()
	sc := bufio.NewScanner(cmd.InOrStdin())
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	line := func(prompt string) string {
		fmt.Fprintf(out, "%s: ", prompt)
		if !sc.Scan() {
			return ""
		}
		return strings.TrimSpace(sc.Text())
	}

	// Multi-line block: read until a lone "." or EOF, join with "\n".
	block := func(prompt string) string {
		fmt.Fprintf(out, "%s (end with a single '.' on its own line):\n", prompt)
		var lines []string
		for sc.Scan() {
			l := sc.Text()
			if strings.TrimSpace(l) == "." {
				break
			}
			lines = append(lines, l)
		}
		return strings.TrimSpace(strings.Join(lines, "\n"))
	}

	var r report.Report
	r.Type = line("report_type")
	r.ResourceID = line("resource_identifier")
	r.PackageName = line("package_name")
	r.Registry = line("registry")
	r.Publisher = line("publisher")
	r.ContactEmail = line("contact_email")
	r.SeverityLevel = line("severity_level")
	r.VersionInfo = line("version_info")
	r.FirstSeen = line("first_seen")
	r.LastSeen = line("last_seen")
	r.OSVAdvisoryURL = line("osv_advisory_url")
	r.Tags = splitCommaList(line("tags (comma-separated)"))
	r.Description = block("threat_description")
	r.PayloadDescription = block("payload_description")

	// Evidence: one entry per non-empty line until a lone "." or EOF.
	fmt.Fprintf(out, "evidence_references (one per line, end with a single '.'):\n")
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "." {
			break
		}
		if l != "" {
			r.EvidenceRefs = append(r.EvidenceRefs, l)
		}
	}

	return r, nil
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

	reader := bufio.NewReader(cmd.InOrStdin())
	answer, _ := reader.ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
}

// writePreview prints a short human summary of the request to w.
func writePreview(w io.Writer, req client.SubmitRequest) {
	fmt.Fprintln(w, "--- report preview ---")
	fmt.Fprintf(w, "type:        %s\n", req.ReportType)
	fmt.Fprintf(w, "resource:    %s\n", req.ResourceIdentifier)
	if req.SeverityLevel != "" {
		fmt.Fprintf(w, "severity:    %s\n", req.SeverityLevel)
	}
	fmt.Fprintf(w, "description: %s\n", req.ThreatDescription)
	if req.PayloadDescription != "" {
		fmt.Fprintf(w, "payload:     %s\n", req.PayloadDescription)
	}
	if req.EvidenceReferences != "" {
		fmt.Fprintf(w, "evidence:    %s\n", req.EvidenceReferences)
	}
	fmt.Fprintln(w, "----------------------")
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
