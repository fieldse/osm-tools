package client

// CheckResult is the response from GET /check-malicious. Threat metadata lives
// in the nested Details object; top-level fields echo the request.
type CheckResult struct {
	Malicious          bool    `json:"malicious"`
	ReportType         string  `json:"report_type"`
	ResourceIdentifier string  `json:"resource_identifier"`
	Ecosystem          string  `json:"ecosystem"`
	ThreatCount        int     `json:"threat_count"`
	Message            string  `json:"message"` // present on not-found responses
	Details            Details `json:"details"`
}

// Details holds the threat metadata returned when a resource is malicious.
type Details struct {
	ID            string   `json:"id"`
	Status        string   `json:"status"`
	SeverityLevel string   `json:"severity_level"`
	Description   string   `json:"description"`
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
	ID                string   `json:"id"`
	PackageName       string   `json:"package_name"`
	ThreatDescription string   `json:"threat_description"`
	SeverityLevel     string   `json:"severity_level"`
	Registry          string   `json:"registry"`
	Publisher         string   `json:"publisher"`
	VersionInfo       string   `json:"version_info"`
	CreatedAt         string   `json:"created_at"`
	Tags              []string `json:"tags"`
}
