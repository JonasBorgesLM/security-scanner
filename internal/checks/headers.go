package checks

import (
	"context"
	"fmt"

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
}

// securityHeaders is the set this check reports on. The order is fixed so
// the findings for one endpoint always come out the same way.
var securityHeaders = []securityHeader{
	{
		name: "Content-Security-Policy",
		why:  "any reflected content has no policy limiting where scripts and data may be loaded from",
	},
	{
		name: "Strict-Transport-Security",
		why:  "clients are not told to stay on TLS, so a network attacker can downgrade them to plaintext and read tokens in transit",
	},
	{
		name: "X-Frame-Options",
		why:  "a response rendered in a browser can be framed by a third-party site for clickjacking",
	},
	{
		name: "X-Content-Type-Options",
		why:  "browsers may MIME-sniff a response into something executable instead of trusting its declared type",
	},
}

// missingHeaders reports security headers absent from a route's baseline
// response.
//
// It is passive: everything it needs is in the response the engine already
// collected during the initial pass, so it costs no request of its own —
// and the engine hands it a client that refuses to send one.
type missingHeaders struct{}

var _ model.Check = (*missingHeaders)(nil)

func (c *missingHeaders) Metadata() model.CheckMetadata {
	return model.CheckMetadata{
		Name:          "missing-headers",
		OWASPCategory: "A05:2021-Security Misconfiguration",
		Severity:      "medium",
		Kind:          model.KindPassive,
	}
}

func (c *missingHeaders) Run(_ context.Context, t model.Target, _ ports.HTTPClient) ([]model.Finding, error) {
	if t.Baseline == nil {
		// Nothing was examined, so there is nothing to conclude. Returning
		// no findings here would read as "this route is clean" — a lie the
		// report has no way to walk back.
		return nil, model.Skippedf("no baseline response for %s %s: %v",
			t.Endpoint.Method, t.Endpoint.Path, t.BaselineErr)
	}

	var findings []model.Finding
	for _, h := range securityHeaders {
		// Headers.Get canonicalises its argument, so a server answering in
		// lower case still counts as present.
		if t.Baseline.Headers.Get(h.name) != "" {
			continue
		}

		findings = append(findings, model.Finding{
			// Discriminator only: the engine namespaces this with the check
			// name and endpoint to build the final, stable ID.
			ID: h.name,
			Request: model.CapturedRequest{
				Method: t.Baseline.ProbedMethod,
				URL:    t.Baseline.URL,
			},
			Evidence: model.Evidence{
				ResponseSnippet: fmt.Sprintf("response has no %s header; %s", h.name, h.why),
				StatusCode:      t.Baseline.StatusCode,
				// ResponseTime deliberately left zero: this finding has
				// nothing to do with timing, and wall-clock here would make
				// two identical scans produce different files.
			},
		})
	}
	return findings, nil
}
