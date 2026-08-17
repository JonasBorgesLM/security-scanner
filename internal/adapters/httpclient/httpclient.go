// Package httpclient is the real ports.HTTPClient adapter: a thin wrapper
// around net/http.Client that enforces the ScopeGuard on every request
// before it is sent.
package httpclient

import (
	"fmt"
	"net/http"

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
// A supplied httpClient is never mutated in place — New works on a shallow
// copy — for two reasons: mutating http.DefaultClient itself would leak a
// redirect policy into any other code in the process that happens to use
// it, and mutating a caller-supplied *http.Client shared across multiple
// New calls (each with its own ScopeGuard) would let the later call's
// CheckRedirect silently overwrite the earlier one's.
func New(guard *scope.ScopeGuard, httpClient *http.Client) *Client {
	if guard == nil {
		panic("httpclient: guard must not be nil")
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	} else {
		clone := *httpClient
		httpClient = &clone
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
