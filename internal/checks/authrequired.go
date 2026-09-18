package checks

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

func init() {
	RegisterCheck(&authRequired{})
}

// authSnippetLimit bounds how much of an unauthenticated response lands in
// evidence. The body of a route that answered without credentials is the
// proof, and a short excerpt of it is enough to recognise.
const authSnippetLimit = 200

// authRequired asks the one question an authorization control exists to
// answer: is a route the spec calls protected actually protected?
//
// For every endpoint whose OpenAPI security declares credentials, it sends
// the request with none and reads the status back. The spec is the oracle —
// it says this route requires auth, and the target either agrees or does
// not. No second user, no session to correlate, no heuristic.
//
// # Why this check concludes where the injection checks cannot
//
// sqli-boolean and xss-reflected ask whether a payload reaches somewhere it
// should not, so a target that validates its input refuses the payload and
// the question goes unanswered (see ErrNotExercised). This check's oracle is
// the STATUS CODE, and validation cannot interfere with it: a 400 is still
// not a 401. Against a well-built API — which is most of them — it is the
// one check here that still reaches a verdict.
//
// # What it sends, and what it refuses to send
//
// The endpoint's own method, path parameters filled with an inert value,
// and NO BODY, ever. That last part is deliberate. An unauthenticated POST
// that a target actually accepts would create something, and a check whose
// job is to find a missing control must not rely on exercising it. Without
// a body such a route answers 400 at validation instead, which this check
// reports as inconclusive rather than clean.
//
// The residue: a route that is unprotected AND accepts an empty body will
// be created against. That request is also the finding, so the trade is a
// created resource in exchange for a critical discovery — acceptable in the
// operator's own lab, and the reason the destructive gate still keeps
// DELETE/PUT/PATCH out of here entirely.
type authRequired struct{}

var _ model.Check = (*authRequired)(nil)

func (c *authRequired) Metadata() model.CheckMetadata {
	return model.CheckMetadata{
		Name:          "auth-required",
		OWASPCategory: "A01:2021-Broken Access Control",
		Severity:      "critical",
		Kind:          model.KindActive,
		// Only endpoints the spec declares as protected. A public route
		// answering without credentials is the route working as designed.
		RequiresAuth: true,
	}
}

func (c *authRequired) Run(ctx context.Context, t model.Target, clients model.Clients) ([]model.Finding, error) {
	if t.Baseline == nil {
		return nil, model.Skippedf("no baseline response for %s %s, so the target's origin is unknown: %v",
			t.Endpoint.Method, t.Endpoint.Path, t.BaselineErr)
	}
	base, err := url.Parse(t.Baseline.URL)
	if err != nil {
		return nil, model.Skippedf("baseline URL %q is not parseable: %v", t.Baseline.URL, err)
	}
	origin := &url.URL{Scheme: base.Scheme, Host: base.Host}

	// Every declared parameter gets the inert filler: the goal is a request
	// the target will route, not one it will act on.
	params := t.Endpoint.Parameters
	req, err := buildProbeRequest(ctx, t.Endpoint, origin, params, model.Parameter{}, "")
	if err != nil {
		return nil, model.Skippedf("could not build an unauthenticated request for %s %s: %v",
			t.Endpoint.Method, t.Endpoint.Path, err)
	}

	// Anonymous, not Default. This is the one place in the codebase where
	// reaching for it is the point rather than a mistake.
	resp, err := clients.Anonymous.Do(req)
	if err != nil {
		return nil, fmt.Errorf("checks: auth-required: %s %s: %w", t.Endpoint.Method, t.Endpoint.Path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("checks: auth-required: reading response for %s %s: %w",
			t.Endpoint.Method, t.Endpoint.Path, err)
	}

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return []model.Finding{{
			ID: "unauthenticated",
			Request: model.CapturedRequest{
				Method: t.Endpoint.Method,
				URL:    req.URL.String(),
			},
			Evidence: model.Evidence{
				StatusCode: resp.StatusCode,
				ResponseSnippet: fmt.Sprintf(
					"the spec declares this route as requiring authentication, but it answered %d to a request carrying no credentials; response: %s",
					resp.StatusCode, snippetOfN(body, authSnippetLimit)),
			},
		}}, nil

	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		// The control is there and it held. Nothing to report, and this is
		// a verdict — not a gap.
		return nil, nil

	default:
		// Anything else leaves the question open, and saying so beats
		// guessing in either direction. A 400 is suggestive — validation
		// normally runs after authentication, so reaching it without
		// credentials hints the control did not run — but "suggestive" is
		// not the standard this project reports on.
		return nil, model.Skippedf(
			"%s %s answered %d to an unauthenticated request, which is neither an acceptance nor a rejection; "+
				"a control that ran would have answered 401 or 403, so this may mean the request never reached it",
			t.Endpoint.Method, t.Endpoint.Path, resp.StatusCode)
	}
}
