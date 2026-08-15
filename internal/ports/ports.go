// Package ports declares the interfaces core and checks code depend on, so
// they can be tested against fakes with no real network or disk I/O.
package ports

import "net/http"

// HTTPClient is the sole boundary outbound requests may cross. The real
// adapter (internal/adapters/httpclient) wires the ScopeGuard in as
// middleware around Do; tests substitute a fake with canned responses.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}
