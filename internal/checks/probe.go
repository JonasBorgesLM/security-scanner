package checks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/JonasBorgesLM/warden/internal/core/model"
	"github.com/JonasBorgesLM/warden/internal/ports"
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

// probeFillerFor returns the benign value to send for a parameter whose
// own value matters this round — the target of a noise measurement or a
// baseline fetch, not a bystander parameter merely being held inert.
//
// It prefers p.Sample — a real value the OpenAPI spec itself supplied —
// over fallback, the check's own generic default. Measured against a real
// API: a strictly-typed parameter (an enum array, a uuid path segment)
// rejects a purely generic filler exactly as it rejects an injection
// payload, so the check never gets past validation to test anything and
// ErrNotExercised fires on a parameter that was never actually exercised
// by anything but a bad guess. A schema-derived value clears that gate
// when the spec provides one; when it does not, the generic fallback is
// still what runs, unchanged from before.
func probeFillerFor(p model.Parameter, fallback string) string {
	if p.Sample != "" {
		return p.Sample
	}
	return fallback
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
func (r perParameterResult) outcome(ep model.Endpoint, params []model.Parameter, heldBack int) ([]model.Finding, error) {
	gate := ""
	if heldBack > 0 {
		gate = fmt.Sprintf("; a further %d body parameter(s) were not probed at all because engine.test_creates is not set", heldBack)
	}

	switch {
	case len(params) == 0 && heldBack > 0:
		return nil, heldBackByCreates(ep, heldBack)
	case len(r.untested) == len(params):
		return nil, model.Skippedf("could not test any parameter of %s %s%s: %w",
			ep.Method, ep.Path, gate, r.lastErr)
	case len(r.untested) > 0:
		return r.findings, model.Skippedf("%d of %d parameter(s) of %s %s could not be tested (%s)%s; the rest were: %w",
			len(r.untested), len(params), ep.Method, ep.Path, strings.Join(r.untested, ", "), gate, r.lastErr)
	case heldBack > 0:
		// Everything reachable was reached, but not everything was
		// reachable. Findings stand; the gap is admitted alongside them.
		return r.findings, heldBackByCreates(ep, heldBack)
	default:
		return r.findings, nil
	}
}

// ErrNotExercised marks a parameter whose probes never reached the code
// path being tested, so nothing can be concluded about it — least of all
// that it is clean.
//
// Two shapes reach it, and the live run against a real API produced both:
//
//   - The target rejected the benign filler too. A parameter declared as an
//     enum, an integer or a uuid answers 400 to "1" exactly as it answers
//     400 to "' OR '1'='1", so the noise floor gets measured over error
//     pages and the two payloads are then compared as error pages. The
//     difference is zero and the route reads as clean.
//   - No probe could be sent at all.
//
// The distinction that matters, and the reason this is not simply "4xx
// means skip": a benign value that succeeds while the payload is rejected
// is the opposite result — that is input validation working, and the
// parameter WAS exercised.
var ErrNotExercised = errors.New("checks: parameter was never exercised")

// rejected reports whether a response status means the request never
// reached the behaviour under test. 4xx is the target refusing the request;
// 5xx means it broke before answering. Neither is a response to compare.
func rejected(status int) bool { return status >= 400 }

// notExercisedf builds an ErrNotExercised-wrapping explanation. Callers
// hand it to runPerParameter, which records the parameter as untested — so
// it reaches the coverage block as an admission rather than vanishing.
func notExercisedf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrNotExercised}, args...)...)
}
