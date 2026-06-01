// Package client is the typed HTTP layer for the OSM API. It owns the wire
// response models and returns concrete structs; no interface is defined here
// (consumers define their own at the point of substitution).
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fieldse/osm-tools/internal/osmerr"
)

// Client talks to the OSM API. Construct it with New; it is safe for concurrent
// use as long as the underlying *http.Client is.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
	debug   io.Writer // when non-nil, each request is logged here
}

// SetDebug enables request/response logging to w. The Bearer token is never
// logged. Pass nil to disable.
func (c *Client) SetDebug(w io.Writer) {
	c.debug = w
}

// New builds a Client. baseURL is the API root (no trailing slash required),
// token is the Bearer token, and httpClient supplies the transport — pass a
// rate-limited client from NewRateLimitedClient in production, or an
// httptest-backed one in tests.
func New(baseURL, token string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    httpClient,
	}
}

// Check performs a GET /check-malicious lookup.
func (c *Client) Check(ctx context.Context, q Query) (CheckResult, error) {
	params := url.Values{}
	params.Set("report_type", reportType(q.Type))
	params.Set("resource_identifier", q.Identifier)
	if q.Ecosystem != "" {
		params.Set("ecosystem", q.Ecosystem)
	}
	if q.Version != "" {
		params.Set("version", q.Version)
	}

	var result CheckResult
	if err := c.getJSON(ctx, "/check-malicious", params, &result); err != nil {
		return CheckResult{}, err
	}
	return result, nil
}

// QueryLatest performs a GET /query-latest for one ecosystem, returning the most
// recent verified threats.
func (c *Client) QueryLatest(ctx context.Context, ecosystem string) ([]LatestThreat, error) {
	params := url.Values{}
	params.Set("ecosystem", ecosystem)

	var resp LatestResponse
	if err := c.getJSON(ctx, "/query-latest", params, &resp); err != nil {
		return nil, err
	}
	return resp.Threats, nil
}

// getJSON issues a GET, classifies the response, and decodes the body into dst.
func (c *Client) getJSON(ctx context.Context, path string, params url.Values, dst any) error {
	u := c.baseURL + path
	if encoded := params.Encode(); encoded != "" {
		u += "?" + encoded
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	if c.debug != nil {
		fmt.Fprintf(c.debug, "→ GET %s\n", u)
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

// classifyError reads a non-2xx response and builds an *APIError. The
// RetryAfter header is captured for 429s so callers can honor it.
func classifyError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return &osmerr.APIError{
		StatusCode: resp.StatusCode,
		Body:       strings.TrimSpace(string(body)),
		RetryAfter: resp.Header.Get("Retry-After"),
	}
}
