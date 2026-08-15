// Package scope implements the ScopeGuard — the central security boundary
// of the scanner. Every outbound request must be checked against the host
// allowlist before it is sent; this is what keeps the tool from ever
// touching anything but the operator's own lab target.
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
