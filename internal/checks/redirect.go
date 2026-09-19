package checks

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
	"github.com/JonasBorgesLM/security-scanner/internal/ports"
)

func init() {
	RegisterCheck(&openRedirect{})
}

// redirectHost is the foreign host the check tries to send the target to.
// A route that puts it in a Location header will redirect a victim to any
// host, which is the whole of the vulnerability.
const redirectHost = "scanner-redirect.example"

// redirectProbe is the value planted in a candidate parameter.
const redirectProbe = "https://" + redirectHost + "/"

// redirectParamNames are the parameter names worth trying. Open redirect
// lives on parameters that name a destination, and guessing beyond these
// would mean planting a URL in fields that are not one and reading noise.
var redirectParamNames = map[string]bool{
	"redirect": true, "redirect_uri": true, "redirecturl": true, "redirect_url": true,
	"url": true, "next": true, "return": true, "return_url": true, "returnto": true,
	"return_to": true, "dest": true, "destination": true, "continue": true,
	"callback": true, "target": true, "goto": true, "forward": true,
}

// openRedirect reports a parameter that will send a browser to an
// arbitrary external host.
//
// # It must not follow the redirect
//
// The finding IS the target trying to bounce us off-scope, and the
// ScopeGuard exists precisely to stop the scanner following such a bounce.
// So the check reads the Location off the 3xx directly rather than chasing
// it. That works because net/http returns the 3xx response ALONGSIDE the
// CheckRedirect error, and the anonymous client passes both through — the
// authenticated client would swallow the response on error, which is one
// reason this check uses the anonymous one. The other is that an open
// redirect is an unauthenticated abuse: it does not need a session.
type openRedirect struct{}

var _ model.Check = (*openRedirect)(nil)

func (c *openRedirect) Metadata() model.CheckMetadata {
	return model.CheckMetadata{
		Name:          "open-redirect",
		OWASPCategory: "A01:2021-Broken Access Control",
		Severity:      "medium",
		Kind:          model.KindActive,
		AppliesTo: func(ep model.Endpoint) bool {
			return len(redirectCandidates(ep)) > 0
		},
	}
}

// redirectCandidates are the query and path parameters whose names suggest
// a redirect destination.
func redirectCandidates(ep model.Endpoint) []model.Parameter {
	var out []model.Parameter
	for _, p := range ep.Parameters {
		if (p.In == "query" || p.In == "path") && redirectParamNames[strings.ToLower(p.Name)] {
			out = append(out, p)
		}
	}
	return out
}

func (c *openRedirect) Run(ctx context.Context, t model.Target, clients model.Clients) ([]model.Finding, error) {
	candidates := redirectCandidates(t.Endpoint)
	if len(candidates) == 0 {
		return nil, nil
	}
	if t.Baseline == nil {
		return nil, model.Skippedf("no baseline response for %s %s, so the target's origin is unknown: %v",
			t.Endpoint.Method, t.Endpoint.Path, t.BaselineErr)
	}
	base, err := url.Parse(t.Baseline.URL)
	if err != nil {
		return nil, model.Skippedf("baseline URL %q is not parseable: %v", t.Baseline.URL, err)
	}
	origin := &url.URL{Scheme: base.Scheme, Host: base.Host}

	res := runPerParameter(candidates, func(p model.Parameter) (*model.Finding, error) {
		return c.testParameter(ctx, clients.Anonymous, t.Endpoint, origin, candidates, p)
	})
	return res.outcome(t.Endpoint, candidates, 0)
}

func (c *openRedirect) testParameter(
	ctx context.Context,
	client ports.HTTPClient,
	ep model.Endpoint,
	origin *url.URL,
	all []model.Parameter,
	target model.Parameter,
) (*model.Finding, error) {
	req, err := buildProbeRequest(ctx, ep, origin, all, target, redirectProbe)
	if err != nil {
		return nil, err
	}

	// Do returns the 3xx together with the CheckRedirect error when a
	// redirect is blocked; that response is exactly what proves the point,
	// so a non-nil error with a usable response is not a failure here.
	resp, doErr := client.Do(req)
	if resp == nil {
		return nil, doErr
	}
	defer resp.Body.Close()

	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return nil, nil
	}
	location := resp.Header.Get("Location")
	if !pointsAt(location, redirectHost) {
		return nil, nil
	}

	return &model.Finding{
		ID: target.Name,
		Request: model.CapturedRequest{
			Method:        ep.Method,
			URL:           req.URL.String(),
			InjectedParam: target.Name,
			Payload:       redirectProbe,
		},
		Evidence: model.Evidence{
			StatusCode: resp.StatusCode,
			ResponseSnippet: fmt.Sprintf(
				"%q accepted an external URL and the response redirected to %q — a link to this route can send a victim anywhere, which is what makes it useful for phishing",
				target.Name, location),
		},
	}, nil
}

// pointsAt reports whether a Location header sends the browser to host.
// Parsed rather than matched as a substring: "https://target/?next=//host"
// contains the host without redirecting to it, and only the parsed target
// authority is the real destination.
func pointsAt(location, host string) bool {
	u, err := url.Parse(strings.TrimSpace(location))
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Hostname(), host)
}
