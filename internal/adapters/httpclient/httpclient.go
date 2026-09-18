// Package httpclient is the real ports.HTTPClient adapter: a thin wrapper
// around net/http.Client that enforces the ScopeGuard on every request
// before it is sent.
package httpclient

import (
	"fmt"
	"net/http"
	"time"

	"github.com/JonasBorgesLM/security-scanner/internal/core/scope"
	"github.com/JonasBorgesLM/security-scanner/internal/ports"
)

var _ ports.HTTPClient = (*Client)(nil)

// Client is the production ports.HTTPClient. Its only way to send a
// request is Do, and Do always checks the ScopeGuard first — there is no
// other path to the network through this type, so it is structurally
// impossible to bypass scope enforcement while using it.
type Client struct {
	guard      *scope.ScopeGuard
	httpClient *http.Client
}

// New builds a Client. guard must not be nil — it is the whole point of
// this adapter. If httpClient is nil, a plain *http.Client is used.
//
// timeout bounds each individual request: connection, redirects and
// reading the response body, all of it. It is a separate parameter rather
// than something the caller sets on httpClient because forgetting it is
// not a visible mistake — without one, the only limit is the whole run's
// context, so a target that accepts a connection and never answers pins a
// worker until the global deadline fires and takes the entire scan down
// with it. A parameter at least shows up at every call site.
//
// A timeout of zero or less means no per-request limit. That is the
// pre-existing behaviour, kept reachable for tests that need a request to
// outlive a deliberate stall; config.validateEngine rejects a negative
// value, and cmd/scanner supplies a default, so no real scan runs without
// one.
//
// A supplied httpClient is never mutated in place — New works on a shallow
// copy — for three reasons: mutating http.DefaultClient itself would leak a
// redirect policy into any other code in the process that happens to use
// it, mutating a caller-supplied *http.Client shared across multiple
// New calls (each with its own ScopeGuard) would let the later call's
// CheckRedirect silently overwrite the earlier one's, and the same applies
// to the Timeout set below.
func New(guard *scope.ScopeGuard, httpClient *http.Client, timeout time.Duration) *Client {
	if guard == nil {
		panic("httpclient: guard must not be nil")
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	} else {
		clone := *httpClient
		httpClient = &clone
	}

	if timeout > 0 {
		httpClient.Timeout = timeout
	}

	// net/http.Client.Do follows redirects internally, dialing each hop
	// itself without ever calling back through this type's Do — so without
	// this, a 3xx response from an in-scope host to an out-of-scope
	// Location would be followed straight past the guard below. This is
	// what makes every hop of a redirect chain go through the same check
	// the first request does, not just the first hop.
	httpClient.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if err := guard.Check(req.URL.Host); err != nil {
			return fmt.Errorf("httpclient: redirect blocked: %w", err)
		}
		return nil
	}

	return &Client{guard: guard, httpClient: httpClient}
}

// Do enforces the ScopeGuard against req's host before delegating to the
// underlying net/http.Client. A request to a host outside the allowlist
// never reaches the network: Do returns before dialing. Any redirect the
// response chain follows from there is checked again by CheckRedirect,
// set up in New.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if err := c.guard.Check(req.URL.Host); err != nil {
		return nil, fmt.Errorf("httpclient: request blocked: %w", err)
	}
	return c.httpClient.Do(req)
}
