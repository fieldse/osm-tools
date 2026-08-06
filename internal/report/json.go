package report

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/fieldse/osm-tools/internal/osmerr"
)

// acceptedJSONKeys lists the wire field names accepted by ParseJSON, mirroring
// the json tags on client.SubmitRequest. Named in the unknown-key error so a
// typo points the user at the valid vocabulary.
const acceptedJSONKeys = "report_type, resource_identifier, threat_description, " +
	"package_name, registry, publisher, contact_email, payload_description, " +
	"severity_level, evidence_references, version_info, first_seen, last_seen, " +
	"osv_advisory_url, tags, contributors, download_count"

// jsonReport is the internal API-keyed shape ParseJSON decodes into before
// mapping to a Report. evidence_references is deferred to a RawMessage because
// the API accepts it as either a JSON array or a pipe-delimited string.
type jsonReport struct {
	ReportType         string          `json:"report_type"`
	ResourceID         string          `json:"resource_identifier"`
	Description        string          `json:"threat_description"`
	PackageName        string          `json:"package_name"`
	Registry           string          `json:"registry"`
	Publisher          string          `json:"publisher"`
	ContactEmail       string          `json:"contact_email"`
	PayloadDescription string          `json:"payload_description"`
	SeverityLevel      string          `json:"severity_level"`
	EvidenceRefs       json.RawMessage `json:"evidence_references"`
	VersionInfo        string          `json:"version_info"`
	FirstSeen          string          `json:"first_seen"`
	LastSeen           string          `json:"last_seen"`
	OSVAdvisoryURL     string          `json:"osv_advisory_url"`
	Tags               []string        `json:"tags"`
	Contributors       []string        `json:"contributors"`
	DownloadCount      int             `json:"download_count"`
}

// ParseJSON decodes a JSON report object (keyed by API field names) into a
// Report. Unknown/misspelled keys are rejected with a *osmerr.UsageError so a
// typo like "serverity_level" fails loudly instead of silently dropping data.
// It performs light normalization (e.g. evidence_references accepted as either a
// list or a pipe-delimited string) but no validation — that is Validate's job.
func ParseJSON(src []byte) (Report, error) {
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.DisallowUnknownFields()

	var jr jsonReport
	if err := dec.Decode(&jr); err != nil {
		// DisallowUnknownFields reports the offending field in its message;
		// surface it as a UsageError so main maps it to exit code 2.
		if strings.Contains(err.Error(), "unknown field") {
			return Report{}, osmerr.Usagef("%s; accepted: %s", err.Error(), acceptedJSONKeys)
		}
		return Report{}, osmerr.Usagef("invalid JSON report: %s", err.Error())
	}

	refs, err := parseEvidenceRefs(jr.EvidenceRefs)
	if err != nil {
		return Report{}, err
	}

	return Report{
		Type:               jr.ReportType,
		ResourceID:         jr.ResourceID,
		Description:        jr.Description,
		PackageName:        jr.PackageName,
		Registry:           jr.Registry,
		Publisher:          jr.Publisher,
		ContactEmail:       jr.ContactEmail,
		PayloadDescription: jr.PayloadDescription,
		SeverityLevel:      jr.SeverityLevel,
		EvidenceRefs:       refs,
		VersionInfo:        jr.VersionInfo,
		FirstSeen:          jr.FirstSeen,
		LastSeen:           jr.LastSeen,
		OSVAdvisoryURL:     jr.OSVAdvisoryURL,
		Tags:               jr.Tags,
		Contributors:       jr.Contributors,
		DownloadCount:      jr.DownloadCount,
	}, nil
}

// parseEvidenceRefs normalizes evidence_references, which the API accepts as
// either a JSON array of strings or a single pipe-delimited string, into a
// []string. An absent value yields a nil slice.
func parseEvidenceRefs(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	// Try a JSON array first.
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}

	// Fall back to a pipe-delimited string.
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, osmerr.Usagef("evidence_references must be a string array or pipe-delimited string")
	}
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}

	parts := strings.Split(s, "|")
	refs := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			refs = append(refs, p)
		}
	}
	return refs, nil
}
