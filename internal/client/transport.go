package client

import (
	"net/http"

	"golang.org/x/time/rate"
)

// DefaultRPM is the free-tier rate limit: 60 requests per minute.
const DefaultRPM = 60

// rateLimitedTransport wraps a base RoundTripper and blocks on a shared limiter
// before each request. Putting throttling in the transport means every request
// — from any command, including concurrent sweep goroutines sharing one limiter
// — is uniformly rate-limited with no call-site discipline. Context cancellation
// propagates into the limiter wait.
type rateLimitedTransport struct {
	base    http.RoundTripper
	limiter *rate.Limiter
}

func (t *rateLimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := t.limiter.Wait(req.Context()); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(req)
}

// NewLimiter returns a token-bucket limiter for the given requests-per-minute,
// with a burst of 1 so requests are evenly paced rather than bursting.
func NewLimiter(rpm int) *rate.Limiter {
	return rate.NewLimiter(rate.Limit(float64(rpm)/60.0), 1)
}

// NewRateLimitedClient builds an *http.Client whose transport is throttled by
// the given limiter. The limiter is injected so it can be shared across a
// command's requests and relaxed in tests.
func NewRateLimitedClient(limiter *rate.Limiter) *http.Client {
	return &http.Client{
		Transport: &rateLimitedTransport{
			base:    http.DefaultTransport,
			limiter: limiter,
		},
	}
}
