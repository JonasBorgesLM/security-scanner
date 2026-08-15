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
// this adapter. If httpClient is nil, http.DefaultClient is used.
func New(guard *scope.ScopeGuard, httpClient *http.Client) *Client {
	if guard == nil {
		panic("httpclient: guard must not be nil")
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{guard: guard, httpClient: httpClient}
}

// Do enforces the ScopeGuard against req's host before delegating to the
// underlying net/http.Client. A request to a host outside the allowlist
// never reaches the network: Do returns before dialing.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if err := c.guard.Check(req.URL.Host); err != nil {
		return nil, fmt.Errorf("httpclient: request blocked: %w", err)
	}
	return c.httpClient.Do(req)
}
