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
	RegisterCheck(&missingHeaders{})
}

// securityHeader is one header the check looks for, with the reason it
// matters — the reason ends up in the report, where "add this header" is
// far less useful than "without it, this is what an attacker can do".
type securityHeader struct {
	name string
	why  string
	// httpsOnly marks headers that are meaningless over plain HTTP, so a
	// lab running on http:// does not collect noise findings.
	httpsOnly bool
}

// securityHeaders is deliberately short. Every entry has to be defensible
// on an API — headers aimed at HTML rendering (X-XSS-Protection, and
// X-Frame-Options for JSON endpoints) produce noise a reader learns to
// ignore, and a check people ignore is worse than no check.
var securityHeaders = []securityHeader{
	{
		name: "Strict-Transport-Security",
		why:  "clients may be downgraded to plaintext HTTP by a network attacker, exposing tokens in transit",
		// Sending HSTS over plain HTTP is a no-op; browsers ignore it.
		httpsOnly: true,
	},
	{
		name: "X-Content-Type-Options",
		why:  "browsers may MIME-sniff a JSON response into something executable",
	},
	{
		name: "Content-Security-Policy",
		why:  "any reflected content has no policy limiting where scripts and data may come from",
	},
	{
		name: "Referrer-Policy",
		why:  "full URLs — including path parameters such as identifiers or tokens — leak to third-party sites in the Referer header",
	},
}

// missingHeaders reports security headers absent from a route's baseline
// response.
//
// It is passive: everything it needs is in the response the engine already
// collected, so it costs no request of its own.
type missingHeaders struct{}

var _ model.Check = (*missingHeaders)(nil)

func (c *missingHeaders) Metadata() model.CheckMetadata {
	return model.CheckMetadata{
		Name:          "missing-headers",
		OWASPCategory: "A05:2021-Security Misconfiguration",
		Severity:      "low",
		Kind:          model.KindPassive,
	}
}

func (c *missingHeaders) Run(_ context.Context, t model.Target, _ ports.HTTPClient) ([]model.Finding, error) {
	if t.Baseline == nil {
		// No response means nothing was examined. Saying so is the whole
		// point of ErrSkipped: reporting the route as clean here would be a
		// lie the report has no way to walk back.
		return nil, model.Skippedf("no baseline response for %s %s: %v", t.Endpoint.Method, t.Endpoint.Path, t.BaselineErr)
	}

	https := isHTTPS(t.Baseline.URL)

	var findings []model.Finding
	for _, h := range securityHeaders {
		if h.httpsOnly && !https {
			continue
		}
		if t.Baseline.Headers.Get(h.name) != "" {
			continue
		}

		findings = append(findings, model.Finding{
			// Discriminator only: the engine namespaces it with the check
			// name and endpoint to build the final ID.
			ID: h.name,
			Request: model.CapturedRequest{
				Method: t.Baseline.ProbedMethod,
				URL:    t.Baseline.URL,
			},
			Evidence: model.Evidence{
				ResponseSnippet: fmt.Sprintf("response has no %s header; %s", h.name, h.why),
				StatusCode:      t.Baseline.StatusCode,
				// ResponseTime deliberately left zero: this finding has
				// nothing to do with timing, and recording wall-clock here
				// would make two identical scans produce different files.
			},
		})
	}
	return findings, nil
}

// isHTTPS reports whether the baseline was fetched over TLS. Headers that
// only take effect over TLS are not worth reporting against a plaintext lab
// — that would be noise, and a check people learn to ignore is worse than
// no check.
func isHTTPS(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Scheme, "https")
}
