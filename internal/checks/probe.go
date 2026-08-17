package checks

import (
	"context"
	"fmt"
	"io"
	"net/url"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
	"github.com/JonasBorgesLM/security-scanner/internal/ports"
)

// maxProbeBodyBytes caps how much of any single active-check probe response
// is read into memory. Shared by every active check so the ceiling is one
// number, not one per check.
const maxProbeBodyBytes = 1 << 20 // 1 MiB

// sendProbe issues one active-check request with target's parameter set to
// value (every other injectable parameter set to its inert filler, via
// buildProbeRequest) and reads the response back into a probeResult. It is
// the one request path every active check shares: sqli-boolean and
// xss-reflected send byte-for-byte identical probes, differing only in the
// value they inject and how they interpret the body — so the sending itself
// lives here once rather than being copied per check.
//
// check names the calling check purely for error messages ("checks: sqli:
// probing q", "checks: xss: probing q"), so a failure points at which check
// and which parameter without the caller having to wrap it.
func sendProbe(
	ctx context.Context,
	client ports.HTTPClient,
	check string,
	ep model.Endpoint,
	origin *url.URL,
	all []model.Parameter,
	target model.Parameter,
	value string,
) (*probeResult, error) {
	req, err := buildProbeRequest(ctx, ep, origin, all, target, value)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("checks: %s: probing %s: %w", check, target.Name, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("checks: %s: reading response for %s: %w", check, target.Name, err)
	}

	return &probeResult{url: req.URL.String(), status: resp.StatusCode, body: body}, nil
}
