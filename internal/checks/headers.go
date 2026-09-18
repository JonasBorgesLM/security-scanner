package checks

import (
	"context"
	"fmt"
	"mime"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

func init() {
	RegisterCheck(&missingHeaders{})
}

// securityHeader is one header the check looks for, with the reason it
// matters — the reason ends up in the report, where "add this header" is
// far less useful than "without it, this is what an attacker can do".
//
// Two headers matter differently depending on what the response actually
// is, so each carries a second reason and a lower severity for the case
// where the response is data rather than a document. The header is still
// reported: OWASP's REST guidance recommends all four on API responses, and
// a check that stayed silent would make "no CSP finding" mean either "it is
// set" or "we decided not to look" — the same ambiguity the coverage block
// exists to prevent, one level down.
type securityHeader struct {
	name string
	why  string
	// dataWhy and dataSeverity apply when the response is not a document a
	// browser renders. Empty means the header matters the same either way.
	dataWhy      string
	dataSeverity string
}

// securityHeaders is the set this check reports on. The order is fixed so
// the findings for one endpoint always come out the same way.
var securityHeaders = []securityHeader{
	{
		name: "Content-Security-Policy",
		why:  "any reflected content has no policy limiting where scripts and data may be loaded from",
		dataWhy: "this response is data, not a document, so there is nothing here for a policy to restrict today — " +
			"it is defence in depth for the day something interprets the response as markup anyway",
		dataSeverity: "low",
	},
	{
		name: "Strict-Transport-Security",
		why:  "clients are not told to stay on TLS, so a network attacker can downgrade them to plaintext and read tokens in transit",
	},
	{
		name: "X-Frame-Options",
		why:  "a response rendered in a browser can be framed by a third-party site for clickjacking",
		dataWhy: "this response is data, not a document, so there is nothing framed for a user to click — " +
			"worth setting anyway, but not the clickjacking exposure it is on a page",
		dataSeverity: "low",
	},
	{
		// Deliberately not downgraded for data responses. Sniffing a JSON
		// body into HTML is the exact attack this header prevents, so on an
		// API it matters at least as much as on a page.
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

func (c *missingHeaders) Run(_ context.Context, t model.Target, _ model.Clients) ([]model.Finding, error) {
	if t.Baseline == nil {
		// Nothing was examined, so there is nothing to conclude. Returning
		// no findings here would read as "this route is clean" — a lie the
		// report has no way to walk back.
		return nil, model.Skippedf("no baseline response for %s %s: %v",
			t.Endpoint.Method, t.Endpoint.Path, t.BaselineErr)
	}

	isData := !rendersAsDocument(t.Baseline.Headers.Get("Content-Type"))

	var findings []model.Finding
	for _, h := range securityHeaders {
		// Headers.Get canonicalises its argument, so a server answering in
		// lower case still counts as present.
		if t.Baseline.Headers.Get(h.name) != "" {
			continue
		}

		why, severity := h.why, ""
		if isData && h.dataWhy != "" {
			why, severity = h.dataWhy, h.dataSeverity
		}

		findings = append(findings, model.Finding{
			// Discriminator only: the engine namespaces this with the check
			// name and endpoint to build the final, stable ID.
			ID: h.name,
			// Left empty for the document case, where the engine fills in
			// the check's own severity.
			Severity: severity,
			Request: model.CapturedRequest{
				Method: t.Baseline.ProbedMethod,
				URL:    t.Baseline.URL,
			},
			Evidence: model.Evidence{
				ResponseSnippet: fmt.Sprintf("response has no %s header; %s", h.name, why),
				StatusCode:      t.Baseline.StatusCode,
				// ResponseTime deliberately left zero: this finding has
				// nothing to do with timing, and wall-clock here would make
				// two identical scans produce different files.
			},
		})
	}
	return findings, nil
}

// rendersAsDocument reports whether a browser would render this response as
// something a user sees and interacts with, which is what makes a missing
// framing or script policy an exposure rather than a hardening gap.
//
// Anything unrecognised — including a response with no Content-Type at all —
// counts as a document. Refusing to downgrade what cannot be classified is
// the safe direction: being wrong that way over-reports a low-severity
// finding, and being wrong the other way quietly demotes a real one.
func rendersAsDocument(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return true
	}
	switch mediaType {
	case "application/json", "application/problem+json", "text/plain",
		"application/octet-stream", "text/csv", "application/pdf":
		return false
	}
	return true
}
