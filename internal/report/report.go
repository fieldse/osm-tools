// Package report holds the pure, mode-agnostic core of `osm submit`: the
// canonical threat-report struct, the three input-mode parsers (template file,
// JSON), the validator, and the IOC defanger. Everything here is free of I/O so
// it can be table-tested against fixtures. Nothing in this package imports cmd
// or client; the report_type→wire mapping happens at the client boundary.
package report

// Report is the canonical in-memory threat report. Every input mode (template
// file, JSON, interactive) produces one of these, and it is the single value
// that flows through validate → defang → the wire mapping. Field types are
// chosen for the pipeline's convenience (slices for multi-value fields); the
// list→pipe-string join for evidence and the docker→container rename happen at
// the client boundary, not here.
type Report struct {
	// Type is the CLI-facing report type. It accepts the seven canonical
	// report_type values plus the "docker" alias (mapped to "container" at the
	// client boundary).
	Type string

	ResourceID  string // resource_identifier (required)
	Description string // threat_description (required)

	PackageName        string   // package_name (distinct from ResourceID)
	Registry           string   // registry (NOT "ecosystem" — that's a check/query param)
	Publisher          string   // publisher
	ContactEmail       string   // contact_email
	PayloadDescription string   // payload_description — the ONLY defanged field
	SeverityLevel      string   // severity_level: critical|high|medium|low
	EvidenceRefs       []string // evidence_references — joined to a pipe string at the wire boundary; never defanged
	VersionInfo        string   // version_info — comma-separated string
	FirstSeen          string   // first_seen — ISO 8601
	LastSeen           string   // last_seen — ISO 8601
	OSVAdvisoryURL     string   // osv_advisory_url — never defanged
	Tags               []string // tags
	Contributors       []string // contributors (JSON mode)
	DownloadCount      int      // download_count (JSON mode)
}

// Report types — the canonical seven-value report_type enum. This is broader
// than internal/infer's four check types, which is why submit owns its own
// vocabulary rather than reusing infer.IsSupported. TypeDocker is the CLI alias
// for TypeContainer and is mapped at the client boundary.
const (
	TypePackage    = "package"
	TypeContainer  = "container"
	TypeRepository = "repository"
	TypeURL        = "url"
	TypeDomain     = "domain"
	TypeIP         = "ip"
	TypeWallet     = "wallet"

	TypeDocker = "docker" // CLI alias → container
)

// IsValidType reports whether t is an accepted report_type. It accepts the seven
// canonical values and the "docker" alias.
func IsValidType(t string) bool {
	switch t {
	case TypePackage, TypeContainer, TypeRepository, TypeURL,
		TypeDomain, TypeIP, TypeWallet, TypeDocker:
		return true
	default:
		return false
	}
}
