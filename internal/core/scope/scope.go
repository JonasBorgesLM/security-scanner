// Package scope implements the ScopeGuard — the central security boundary
// of the scanner. Every outbound request must be checked against the host
// allowlist before it is sent; this is what keeps the tool from ever
// touching anything but the operator's own lab target.
//
// # What it covers
//
// Every request that leaves through internal/adapters/httpclient, which is
// the only path to the network any component is given — including each hop
// of a redirect chain, which net/http would otherwise follow internally
// without calling back through the adapter.
//
// # What it does NOT cover
//
// Stating this is the point of the section: a control described as
// complete when it is partial is worse than an absent one, because someone
// will rely on it.
//
//   - It matches HOST NAMES, not addresses. It never resolves anything, so
//     an allowed name whose DNS points somewhere else reaches somewhere
//     else. There is no defence here against DNS rebinding, a hosts-file
//     entry, or a name the operator does not control.
//   - It is an exact string comparison. "LOCALHOST:8080" does not match
//     "localhost:8080", and "example.com" does not match "example.com:443"
//     — the port is part of the string or it is not there at all.
//   - It says nothing about what is sent, only where. Non-destructiveness
//     is a separate gate (see model.Endpoint.Destructive), and the rate
//     limiter is another (see internal/core/engine).
//
// The second point always fails CLOSED: a mismatch blocks the request, so
// the failure mode is a scan that cannot reach its own target, not one
// that reaches somebody else's. config.validateScope cross-checks the
// target's own host up front so that particular mistake is caught before
// any request is built; a redirect destination gets no such warning.
//
// The threat model this is built for is the operator's own honest mistake
// — a stale base_url, a copied config, a redirect off the lab host — not
// an adversary who controls the config file or the resolver. Someone who
// controls either has already won, and no allowlist recovers that.
package scope

import (
	"errors"
	"fmt"
)

// ErrOutOfScope is returned when a host is not in the allowlist.
var ErrOutOfScope = errors.New("scope: host not in allowlist")

// ScopeGuard holds the allowlist of hosts the scanner is permitted to
// contact. It is the single point of enforcement — no request may bypass
// it, by design rather than by convention.
type ScopeGuard struct {
	allowed map[string]struct{}
}

// NewScopeGuard builds a ScopeGuard from a list of allowed hosts. Hosts
// must match exactly what appears in a request URL's Host field, including
// the port when the target uses a non-default one (e.g. "localhost:8080"),
// matching scope.allowed_hosts in config.yaml.
func NewScopeGuard(allowedHosts []string) *ScopeGuard {
	allowed := make(map[string]struct{}, len(allowedHosts))
	for _, h := range allowedHosts {
		allowed[h] = struct{}{}
	}
	return &ScopeGuard{allowed: allowed}
}

// Check returns ErrOutOfScope if host is not in the allowlist, nil
// otherwise.
func (g *ScopeGuard) Check(host string) error {
	if _, ok := g.allowed[host]; !ok {
		return fmt.Errorf("%w: %q", ErrOutOfScope, host)
	}
	return nil
}
