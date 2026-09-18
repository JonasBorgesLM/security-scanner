package checks

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"

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

// perParameterResult is the outcome of sweeping one check across an
// endpoint's injectable parameters.
type perParameterResult struct {
	findings []model.Finding
	// untested names the parameters no probe could be completed against —
	// a refused connection, broken auth, a URL that would not build. They
	// are the difference between "this route is clean" and "this much of
	// the route is clean".
	untested []string
	lastErr  error
}

// runPerParameter applies test to every parameter and keeps account of the
// ones it could not reach.
//
// It exists because both active checks were making the same bookkeeping
// mistake in the same place: each collected a lastErr per parameter and
// then threw it away whenever at least one other parameter had worked, so
// an endpoint where three parameters tested fine and a fourth refused every
// probe was reported as examined and clean. The shape is shared; more to
// the point, the correctness property is — a new active check should not
// have to rediscover that an untested parameter has to be admitted.
func runPerParameter(params []model.Parameter, test func(model.Parameter) (*model.Finding, error)) perParameterResult {
	var res perParameterResult
	for _, p := range params {
		f, err := test(p)
		if err != nil {
			res.untested = append(res.untested, p.Name)
			res.lastErr = err
			continue
		}
		if f != nil {
			res.findings = append(res.findings, *f)
		}
	}
	return res
}

// outcome turns the sweep into what a Check must return.
//
// Three cases, and the middle one is the reason this function exists:
// nothing testable is a plain skip, everything testable is a plain result,
// and a partial sweep is BOTH — findings to report and an admission to
// make. model.Skippedf wraps the cause with %w so a caller can still reach
// it with errors.Is.
func (r perParameterResult) outcome(ep model.Endpoint, params []model.Parameter) ([]model.Finding, error) {
	switch {
	case len(r.untested) == len(params):
		return nil, model.Skippedf("could not test any parameter of %s %s: %w",
			ep.Method, ep.Path, r.lastErr)
	case len(r.untested) > 0:
		return r.findings, model.Skippedf("%d of %d parameter(s) of %s %s could not be tested (%s); the rest were: %w",
			len(r.untested), len(params), ep.Method, ep.Path, strings.Join(r.untested, ", "), r.lastErr)
	default:
		return r.findings, nil
	}
}
