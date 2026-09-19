package checks

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

func init() {
	RegisterCheck(&dangerousMethods{})
}

// traceMarker is sent as a header the target has no reason to know about.
// Finding it in the response body is what separates "TRACE is enabled" from
// "the server answered 200 with something else in it".
const traceMarker = "X-Scanner-Trace-Probe"

// traceSnippetLimit bounds how much of the echo reaches evidence.
const traceSnippetLimit = 200

// dangerousMethods reports a target that still answers TRACE.
//
// # The severity is low, deliberately
//
// The traditional grading for this is medium, on the strength of
// Cross-Site Tracing: a script reads the echoed response and recovers
// HttpOnly cookies. That attack is dead. Browsers have refused to issue
// TRACE from XHR and fetch since around 2010, so there is no path by which
// a page can make one happen.
//
// What survives is information disclosure. TRACE echoes the request back
// including whatever headers a proxy chain added on the way in, which is
// useful for reconnaissance and is why compliance checklists still ask for
// it off. That is a low finding, and reporting it as medium would be
// repeating a severity scanners carry out of habit — the opposite of what
// this project is for.
//
// # Why it asks anonymously
//
// TRACE echoes the request headers. Sent as the authenticated identity, the
// target would hand back the Authorization header, and the evidence would
// carry a live credential into a findings.json that gets committed. Asking
// without credentials answers the same question and has nothing to leak.
//
// # Why it is active rather than reading OPTIONS
//
// An Allow header is the server describing itself, and not every server
// sends one. A 200 with the request echoed back is the behaviour itself.
// TRACE is safe and idempotent (RFC 9110), so proving it costs one harmless
// request — one per endpoint, since a proxy may permit TRACE on some paths
// and not others, and the check cannot know which without asking.
type dangerousMethods struct{}

var _ model.Check = (*dangerousMethods)(nil)

func (c *dangerousMethods) Metadata() model.CheckMetadata {
	return model.CheckMetadata{
		Name:          "dangerous-http-methods",
		OWASPCategory: "A05:2021-Security Misconfiguration",
		Severity:      "low",
		Kind:          model.KindActive,
	}
}

func (c *dangerousMethods) Run(ctx context.Context, t model.Target, clients model.Clients) ([]model.Finding, error) {
	if t.Baseline == nil {
		return nil, model.Skippedf("no baseline response for %s %s, so the target's origin is unknown: %v",
			t.Endpoint.Method, t.Endpoint.Path, t.BaselineErr)
	}
	base, err := url.Parse(t.Baseline.URL)
	if err != nil {
		return nil, model.Skippedf("baseline URL %q is not parseable: %v", t.Baseline.URL, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodTrace, base.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("checks: dangerous-http-methods: building TRACE for %s: %w", base, err)
	}
	req.Header.Set(traceMarker, "1")

	resp, err := clients.Anonymous.Do(req)
	if err != nil {
		return nil, fmt.Errorf("checks: dangerous-http-methods: %s: %w", base, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("checks: dangerous-http-methods: reading TRACE response for %s: %w", base, err)
	}

	switch {
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		// Refused, which is the answer everyone wants. 405 and 501 are the
		// usual forms; anything else non-2xx still means TRACE did not run.
		return nil, nil

	case !strings.Contains(string(body), traceMarker):
		// A 200 without the echo is not TRACE working — a catch-all route
		// or a proxy answering on its behalf. Saying so beats reporting a
		// finding that would not reproduce.
		return nil, model.Skippedf(
			"%s answered %d to TRACE but did not echo the request back, so whether TRACE is handled here is undetermined",
			base, resp.StatusCode)

	default:
		return []model.Finding{{
			ID: "TRACE",
			Request: model.CapturedRequest{
				Method:  http.MethodTrace,
				URL:     base.String(),
				Headers: map[string]string{traceMarker: "1"},
			},
			Evidence: model.Evidence{
				StatusCode: resp.StatusCode,
				ResponseSnippet: fmt.Sprintf(
					"TRACE is answered here and echoes the request back, including any header a proxy added on the way in — "+
						"useful for reconnaissance. The classic Cross-Site Tracing attack is not reachable: browsers have "+
						"refused to issue TRACE from script for well over a decade. Echo: %s",
					snippetOfN(body, traceSnippetLimit)),
			},
		}}, nil
	}
}
