package client

// CheckResult is the response from GET /check-malicious. Field names follow the
// documented schema; verify against a live API response before locking.
type CheckResult struct {
	Malicious     bool     `json:"malicious"`
	SeverityLevel string   `json:"severity_level"`
	Description   string   `json:"description"`
	Tags          []string `json:"tags"`
	FirstSeen     string   `json:"first_seen"`
	LastSeen      string   `json:"last_seen"`
	LastOSMScore  int      `json:"last_osm_score"`
	LastScannedAt string   `json:"last_scanned_at"`
	ScanCount     int      `json:"scan_count"`
	Details       Details  `json:"details"`
}

// Details holds the nested object carrying the threat identifier.
type Details struct {
	ThreatID string `json:"threat_id"`
}

// LatestThreat is one entry from GET /query-latest.
type LatestThreat struct {
	Ecosystem     string   `json:"ecosystem"`
	Package       string   `json:"package"`
	Version       string   `json:"version"`
	SeverityLevel string   `json:"severity_level"`
	Description   string   `json:"description"`
	Tags          []string `json:"tags"`
	FirstSeen     string   `json:"first_seen"`
	ThreatID      string   `json:"threat_id"`
}
