package report

import (
	"regexp"
	"strings"
)

// Defang token grammar. Each classifier is anchored to a full whitespace-free
// token; the first match wins in the order URL → IPv4 → IPv6 → hostname.
var (
	// tokenRe carves the input into maximal non-space runs so surrounding
	// whitespace and prose are preserved exactly.
	tokenRe = regexp.MustCompile(`\S+`)

	// urlRe matches a scheme://... token; group 1 is the scheme.
	urlRe = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9+.-]*)://(.*)$`)

	// ipv4Re matches four dotted octets with optional /CIDR and :port.
	ipv4Re = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?(:\d+)?$`)

	// ipv6Re matches a bare or bracketed hex:colon token; a separate ≥2-colon
	// guard excludes single-colon host:port and version strings.
	ipv6Re = regexp.MustCompile(`^\[?[0-9a-fA-F:]+\]?$`)

	// hostRe matches a dotted hostname whose final label is all-alpha, length
	// 2–24, so IPs and version strings (final label numeric) are excluded.
	hostRe = regexp.MustCompile(`^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,24}$`)
)

// Defang rewrites IOC tokens in s to the platform convention so live indicators
// can't be clicked or resolved by accident:
//
//	.        → [.]   (inside matched tokens only)
//	https:// → hxxps://,  http:// → hxxp://
//
// It is pattern-scoped and idempotent. Matched token grammar: IPv4 (with
// optional /CIDR and :port), IPv6 (bracketed or bare), scheme://host[/path]
// URLs, and bare hostnames with a plausible public-suffix TLD. Email addresses
// are matched and skipped (abuse@evil.com must not become abuse@evil[.]com), and
// prose and version strings like 1.2.3 are left untouched. Re-running Defang on
// already-defanged text is a no-op.
func Defang(s string) string {
	return tokenRe.ReplaceAllStringFunc(s, defangToken)
}

// Punctuation peeled off a token before classification so IOCs adjacent to
// prose punctuation (evil.com. / (evil.com) / 10.0.0.1,) are still neutralized.
// A trailing ':' and '/' are deliberately NOT peeled — they carry meaning in
// IPv6 (fe80::) and IPv4 :port / URL paths.
const (
	leadTrim  = "([{<\"'`"
	trailTrim = ".,;!?)]}>\"'`"
)

// defangToken peels surrounding punctuation, neutralizes the core indicator,
// and re-attaches the punctuation. A token that is not a recognized indicator
// comes back unchanged.
func defangToken(tok string) string {
	lead := 0
	for lead < len(tok) && strings.IndexByte(leadTrim, tok[lead]) >= 0 {
		lead++
	}
	trail := len(tok)
	for trail > lead && strings.IndexByte(trailTrim, tok[trail-1]) >= 0 {
		trail--
	}
	core := tok[lead:trail]
	if core == "" {
		return tok
	}
	return tok[:lead] + defangCore(core) + tok[trail:]
}

// defangCore neutralizes a single punctuation-stripped indicator. URLs and IPs
// are classified BEFORE the email skip so a credentialed URL
// (http://user:pass@host) is defanged rather than mistaken for an email.
func defangCore(tok string) string {
	switch {
	case urlRe.MatchString(tok):
		return defangURL(tok)
	case ipv4Re.MatchString(tok):
		return defangDots(tok)
	case isIPv6(tok):
		return defangColons(tok)
	case strings.ContainsRune(tok, '@'):
		// A bare email (not a URL/IP) is a citation, not an indicator.
		return tok
	case hostRe.MatchString(tok):
		return defangDots(tok)
	default:
		return tok
	}
}

// isIPv6 reports whether tok is an IPv6 indicator, excluding all-decimal
// colon strings with too few colons — a clock like 12:34:56 is not an IOC.
func isIPv6(tok string) bool {
	if !ipv6Re.MatchString(tok) || strings.Count(tok, ":") < 2 {
		return false
	}
	// Require a compressed run, 3+ colons, or a hex letter to distinguish real
	// IPv6 from a time-of-day (two decimal colons, no "::").
	return strings.Contains(tok, "::") ||
		strings.Count(tok, ":") >= 3 ||
		strings.ContainsAny(tok, "abcdefABCDEF")
}

// defangURL rewrites the scheme (http→hxxp, https→hxxps) and defangs the dots in
// the host portion, leaving any path untouched.
func defangURL(tok string) string {
	m := urlRe.FindStringSubmatch(tok)
	scheme, rest := m[1], m[2]

	host, path := rest, ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		host, path = rest[:i], rest[i:]
	}

	switch strings.ToLower(scheme) {
	case "http":
		scheme = "hxxp"
	case "https":
		scheme = "hxxps"
	}
	return scheme + "://" + defangDots(host) + path
}

// defangDots replaces every dot with "[.]", leaving already-defanged "[.]"
// untouched so the operation is idempotent.
func defangDots(s string) string {
	const sentinel = "\x00"
	s = strings.ReplaceAll(s, "[.]", sentinel)
	s = strings.ReplaceAll(s, ".", "[.]")
	return strings.ReplaceAll(s, sentinel, "[.]")
}

// defangColons replaces every colon with "[:]", leaving already-defanged "[:]"
// untouched so the operation is idempotent.
func defangColons(s string) string {
	const sentinel = "\x00"
	s = strings.ReplaceAll(s, "[:]", sentinel)
	s = strings.ReplaceAll(s, ":", "[:]")
	return strings.ReplaceAll(s, sentinel, "[:]")
}

// DefangPayload returns a copy of r with PayloadDescription defanged. No other
// field is touched — evidence references and the OSV advisory URL are citations
// meant to be followed, so they are never defanged.
func DefangPayload(r Report) Report {
	r.PayloadDescription = Defang(r.PayloadDescription)
	return r
}
