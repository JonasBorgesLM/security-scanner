package attack

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"strings"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
	"github.com/JonasBorgesLM/security-scanner/internal/ports"
)

func init() {
	Register(xssConfirmer{})
}

// xssSnippetLimit bounds how much response text lands in Evidence.
const xssSnippetLimit = 200

// xssConfirmer confirms a reflected-XSS finding by replaying the injection
// point with a fresh, unique marker and checking that it comes back
// unescaped. A fresh marker rather than scan's original payload matters
// twice over: it rules out a cached response answering for us, and it
// distinguishes "reflected as literal text" from "reflected but
// HTML-escaped" — only the former is exploitable, and scan's own marker
// might not have said which happened.
type xssConfirmer struct{}

var _ Confirmer = xssConfirmer{}

func (xssConfirmer) CheckName() string { return "xss-reflected" }

func (xssConfirmer) Confirm(ctx context.Context, f model.Finding, client ports.HTTPClient) (model.Finding, error) {
	marker, err := freshMarker()
	if err != nil {
		return f, fmt.Errorf("generating a fresh marker: %w", err)
	}
	payload := fmt.Sprintf("<xsscanary-%s>", marker)

	testURL, err := withInjectedValue(f.Request.URL, f.Request.InjectedParam, f.Request.Payload, payload)
	if err != nil {
		return f, fmt.Errorf("reconstructing the injection: %w", err)
	}

	res, err := get(ctx, client, f.Request.Method, testURL)
	if err != nil {
		return f, fmt.Errorf("replaying with a fresh marker: %w", err)
	}
	body := string(res.body)

	switch {
	case strings.Contains(body, payload):
		f.Confirmed = true
		f.Evidence.StatusCode = res.status
		f.Evidence.ResponseSnippet = "marker reflected unescaped: " + snippetAround(body, payload)
		f.Request.URL = testURL
		f.Request.Payload = payload
	case strings.Contains(body, html.EscapeString(payload)):
		f.Evidence.ResponseSnippet = "marker was reflected, but HTML-escaped — not exploitable as raw markup"
	default:
		f.Evidence.ResponseSnippet = "marker did not reproduce in the response"
	}
	return f, nil
}

func freshMarker() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// snippetAround returns the text immediately surrounding marker within
// body, so evidence shows the reflection in context instead of just
// asserting it happened.
func snippetAround(body, marker string) string {
	const radius = 60

	i := strings.Index(body, marker)
	if i < 0 {
		return snippetOf([]byte(body), xssSnippetLimit)
	}
	start := max(0, i-radius)
	end := min(len(body), i+len(marker)+radius)
	return snippetOf([]byte(body[start:end]), xssSnippetLimit)
}
