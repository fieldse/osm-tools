// Package client is the typed HTTP layer for the OSM API. It owns the wire
// response models and returns concrete structs; no interface is defined here
// (consumers define their own at the point of substitution).
package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
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

// Retry policy for per-minute 429s. A daily-quota 429 is never retried.
const (
	maxRetries       = 3
	defaultRetryWait = 2 * time.Second
	maxRetryWait     = 60 * time.Second
	dailyQuotaMarker = "daily quota"
)

// getJSON issues a GET, retrying per-minute 429s, and decodes the body into dst.
func (c *Client) getJSON(ctx context.Context, path string, params url.Values, dst any) error {
	u := c.baseURL + path
	if encoded := params.Encode(); encoded != "" {
		u += "?" + encoded
	}

	for attempt := 0; ; attempt++ {
		err := c.getOnce(ctx, path, u, dst)
		var apiErr *osmerr.APIError
		if attempt == maxRetries || !errors.As(err, &apiErr) || !retryable(apiErr) {
			return err
		}
		wait := retryWait(apiErr.RetryAfter, time.Now())
		if c.debug != nil {
			fmt.Fprintf(c.debug, "  rate limited; retry %d/%d in %s\n", attempt+1, maxRetries, wait)
		}
		if err := sleepCtx(ctx, wait); err != nil {
			return fmt.Errorf("waiting to retry %s: %w", path, err)
		}
	}
}

// getOnce issues one GET, classifies the response, and decodes the body into dst.
func (c *Client) getOnce(ctx context.Context, path, u string, dst any) error {
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

// retryable reports whether e is a per-minute rate limit worth waiting out.
func retryable(e *osmerr.APIError) bool {
	return e.IsRateLimit() && !strings.Contains(strings.ToLower(e.Body), dailyQuotaMarker)
}

// retryWait converts a Retry-After header (seconds or an HTTP date) into a
// wait, falling back to defaultRetryWait and capping at maxRetryWait.
func retryWait(header string, now time.Time) time.Duration {
	header = strings.TrimSpace(header)
	wait := defaultRetryWait
	if secs, err := strconv.Atoi(header); err == nil {
		wait = time.Duration(secs) * time.Second
	} else if at, err := http.ParseTime(header); err == nil {
		wait = at.Sub(now)
	}
	return min(max(wait, 0), maxRetryWait)
}

// sleepCtx waits for d or until ctx ends, returning ctx's error in that case.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
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
