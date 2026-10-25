// Package verdict classifies a check-malicious response as MALICIOUS, REVIEW
// or CLEAN.
package verdict

import (
	"regexp"
	"strings"

	"github.com/fieldse/osm-tools/internal/client"
)

// Status is the verdict for one lookup.
type Status string

// Verdicts.
const (
	Malicious Status = "MALICIOUS"
	Review    Status = "REVIEW"
	Clean     Status = "CLEAN"
)

// exactVersion matches a single pinned version such as 1.2.3, v1.2.3,
// 1.2.3-beta.1, 1.0rc1, 1.0.post1, 5.4.0.Final or the PEP 440 epoch form
// 1!2.0, and rejects ranges, wildcards and tags.
var exactVersion = regexp.MustCompile(`^(\d+!)?[vV]?\d+(\.\d+)*([-+_.]?[0-9A-Za-z][0-9A-Za-z.+_-]*)?$`)

// IsExactVersion reports whether v names one version rather than a range.
func IsExactVersion(v string) bool {
	if !exactVersion.MatchString(v) {
		return false
	}
	for _, part := range strings.Split(v, ".") {
		if part == "x" || part == "X" {
			return false
		}
	}
	return true
}

// Of returns the verdict for r. sentVersion is the version the query sent.
// artifactFallback marks a result found only by the Maven artifactId
// fallback, which can be at most REVIEW.
func Of(r client.CheckResult, sentVersion string, artifactFallback bool) Status {
	s := base(r, sentVersion)
	if artifactFallback && s == Malicious {
		return Review
	}
	return s
}

func base(r client.CheckResult, sentVersion string) Status {
	if r.Malicious {
		if allVersions(r.Details.VersionInfo) || IsExactVersion(sentVersion) {
			return Malicious
		}
		return Review
	}
	if strings.TrimSpace(r.Warning) != "" || hasNonBlank(r.KnownMaliciousVersions) {
		return Review
	}
	return Clean
}

// allVersions reports whether version_info marks every version as malicious.
func allVersions(info string) bool {
	info = strings.TrimSpace(info)
	return info == "" || strings.EqualFold(info, "all")
}

func hasNonBlank(vs []string) bool {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}
