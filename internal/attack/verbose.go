package attack

import (
	"context"
	"fmt"

	"github.com/JonasBorgesLM/security-scanner/internal/checks"
	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

func init() {
	Register(verboseConfirmer{})
}

// verboseConfirmer reproduces a verbose-error finding by resending the
// malformed request and a benign one to the same URL, and confirming the
// leak appears with the first and not the second.
//
// Sending both is what makes this a reproduction rather than a rerun: scan
// ruled the leak out of the endpoint's baseline, and doing the equivalent
// here — malformed leaks, benign does not — proves the malformed input is
// the cause now, without needing scan's stored baseline.
type verboseConfirmer struct{}

var _ Confirmer = verboseConfirmer{}

func (verboseConfirmer) CheckName() string { return "verbose-errors" }

func (verboseConfirmer) Confirm(ctx context.Context, f model.Finding, clients model.Clients) (model.Finding, error) {
	malformed, err := get(ctx, clients.Default, f.Request.Method, f.Request.URL)
	if err != nil {
		return f, fmt.Errorf("replaying the malformed request: %w", err)
	}
	name, leaks := checks.LooksLikeErrorLeak(string(malformed.body))
	if !leaks {
		f.Evidence.StatusCode = malformed.status
		f.Evidence.ResponseSnippet = "did not reproduce: the malformed request no longer returns internal detail — the endpoint may have been fixed since the scan"
		return f, nil
	}

	// A benign value at the same parameter. If it leaks too, the detail is
	// not something the malformed input caused, and this is not a finding
	// worth confirming.
	// Same parameter, a benign value, via the same replacement scan
	// captured. If a leak shows here too it is not the malformed input's
	// doing, and confirming would be wrong.
	if benign, err := withInjectedValue(f.Request.URL, f.Request.InjectedParam, f.Request.Payload, "1"); err == nil {
		if clean, err := get(ctx, clients.Default, f.Request.Method, benign); err == nil {
			if _, alsoLeaks := checks.LooksLikeErrorLeak(string(clean.body)); alsoLeaks {
				f.Evidence.ResponseSnippet = "did not reproduce: the endpoint returns the same internal detail for a benign value, so the malformed input is not the cause"
				return f, nil
			}
		}
	}

	f.Confirmed = true
	f.Evidence.StatusCode = malformed.status
	f.Evidence.ResponseSnippet = fmt.Sprintf(
		"reproduced: malformed input still produces %s that a benign value does not: %s",
		name, snippetOf(malformed.body, 200))
	return f, nil
}
