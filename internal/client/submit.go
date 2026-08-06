package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// SubmitRequest is the POST /submit-threat-report body. Field names are the wire
// contract (verified against docs.opensourcemalware.com). ReportType carries the
// CLI-facing value and is mapped (docker→container) inside SubmitThreat, exactly
// as Check maps its query type. EvidenceReferences is a single pipe-delimited
// string, not an array — the caller joins the report's evidence list before
// building this struct.
type SubmitRequest struct {
	ReportType         string   `json:"report_type"`
	ResourceIdentifier string   `json:"resource_identifier"`
	ThreatDescription  string   `json:"threat_description"`
	PackageName        string   `json:"package_name,omitempty"`
	Registry           string   `json:"registry,omitempty"`
	Publisher          string   `json:"publisher,omitempty"`
	ContactEmail       string   `json:"contact_email,omitempty"`
	PayloadDescription string   `json:"payload_description,omitempty"`
	SeverityLevel      string   `json:"severity_level,omitempty"`
	EvidenceReferences string   `json:"evidence_references,omitempty"` // pipe-delimited
	VersionInfo        string   `json:"version_info,omitempty"`
	FirstSeen          string   `json:"first_seen,omitempty"`
	LastSeen           string   `json:"last_seen,omitempty"`
	OSVAdvisoryURL     string   `json:"osv_advisory_url,omitempty"`
	Tags               []string `json:"tags,omitempty"`
	Contributors       []string `json:"contributors,omitempty"`
	DownloadCount      int      `json:"download_count,omitempty"`
}

// SubmitResult is the 201 response from POST /submit-threat-report.
type SubmitResult struct {
	ThreatID string `json:"threat_id"`
	Status   string `json:"status"` // "pending" on success
	Message  string `json:"message"`
}

// SubmitThreat files a threat report via POST /submit-threat-report. It maps
// ReportType (docker→container) at this boundary, sends under the shared rate
// limiter and the given context, and returns the created threat's id/status. A
// non-2xx response is classified into a *osmerr.APIError (401/403/409/429/5xx)
// just like the GET path.
func (c *Client) SubmitThreat(ctx context.Context, req SubmitRequest) (SubmitResult, error) {
	// Build the body from a copy so the caller's req is not mutated; docker→container
	// happens here, exactly as Check maps its query type.
	body := req
	body.ReportType = reportType(req.ReportType)

	var result SubmitResult
	if err := c.postJSON(ctx, "/submit-threat-report", body, &result); err != nil {
		return SubmitResult{}, err
	}
	return result, nil
}

// postJSON marshals payload, issues a POST, classifies the response, and decodes
// the body into dst. It mirrors getJSON: the Bearer token is never logged.
func (c *Client) postJSON(ctx context.Context, path string, payload, dst any) error {
	u := c.baseURL + path

	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encoding %s request: %w", path, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if c.debug != nil {
		fmt.Fprintf(c.debug, "→ POST %s\n", u)
	}

	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		if c.debug != nil {
			fmt.Fprintf(c.debug, "← error after %s: %v\n", time.Since(start).Round(time.Millisecond), err)
		}
		// Network/transport failure (or a cancelled context). Operational.
		return fmt.Errorf("request to %s: %w", path, err)
	}
	defer resp.Body.Close()

	if c.debug != nil {
		fmt.Fprintf(c.debug, "← %s (%s)\n", resp.Status, time.Since(start).Round(time.Millisecond))
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return classifyError(resp)
	}

	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		return fmt.Errorf("decoding %s response: %w", path, err)
	}
	return nil
}
