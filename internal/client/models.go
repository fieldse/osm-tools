package client

import "strings"

// CheckResult is the response from GET /check-malicious. Threat metadata lives
// in the nested Details object; top-level fields echo the request.
type CheckResult struct {
	Malicious          bool    `json:"malicious"`
	ReportType         string  `json:"report_type"`
	ResourceIdentifier string  `json:"resource_identifier"`
	Ecosystem          string  `json:"ecosystem"`
	Version            string  `json:"version"` // the version the query sent; null when none was
	OSMURL             string  `json:"osm_url"`
	ThreatCount        int     `json:"threat_count"`
	Message            string  `json:"message"` // present on not-found responses
	Details            Details `json:"details"` // null on not-found and warning responses

	// Warning and KnownMaliciousVersions are set when the package has malicious
	// versions but the queried version is not one of them.
	Warning                string   `json:"warning"`
	KnownMaliciousVersions []string `json:"known_malicious_versions"`
}

// Details holds the threat metadata returned when a resource is malicious.
type Details struct {
	ID            string   `json:"id"`
	ThreatID      string   `json:"threat_id"` // the live API's name for the threat id
	Status        string   `json:"status"`
	SeverityLevel string   `json:"severity_level"`
	Description   string   `json:"description"`
	VersionInfo   string   `json:"version_info"` // "all", blank, or a comma-separated version list
	Tags          []string `json:"tags"`
	FirstSeen     string   `json:"first_seen"`
	LastSeen      string   `json:"last_seen"`
}

// LatestResponse is the GET /query-latest envelope.
type LatestResponse struct {
	Ecosystem string         `json:"ecosystem"`
	Count     int            `json:"count"`
	Threats   []LatestThreat `json:"threats"`
}

// LatestThreat is one entry from the query-latest threats array.
type LatestThreat struct {
	ID                 string   `json:"id"`
	ResourceIdentifier string   `json:"resource_identifier"`
	PackageName        string   `json:"package_name"`
	Status             string   `json:"status"`
	OSMURL             string   `json:"osm_url"`
	VerifiedAt         string   `json:"verified_at"`
	ThreatDescription  string   `json:"threat_description"`
	SeverityLevel      string   `json:"severity_level"`
	Registry           string   `json:"registry"`
	Publisher          string   `json:"publisher"`
	VersionInfo        string   `json:"version_info"`
	CreatedAt          string   `json:"created_at"`
	Tags               []string `json:"tags"`
}

// AffectedVersions returns the malicious versions the response names:
// details.version_info on a hit, or known_malicious_versions on a version-miss
// warning. It is empty when neither is present.
func (r CheckResult) AffectedVersions() string {
	if v := strings.TrimSpace(r.Details.VersionInfo); v != "" {
		return v
	}
	var known []string
	for _, v := range r.KnownMaliciousVersions {
		if v = strings.TrimSpace(v); v != "" {
			known = append(known, v)
		}
	}
	return strings.Join(known, ", ")
}
