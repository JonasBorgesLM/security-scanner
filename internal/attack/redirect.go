package attack

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/JonasBorgesLM/warden/internal/core/model"
)

func init() {
	Register(redirectConfirmer{})
}

// redirectConfirmer reproduces an open-redirect finding by resending the
// request and reading the Location off the 3xx — without following it,
// which is the ScopeGuard's job and the point of the finding.
//
// It uses the anonymous client for the same two reasons the check did: the
// authenticated client swallows the response when Do returns the
// CheckRedirect error, and an open redirect is an unauthenticated abuse.
type redirectConfirmer struct{}

var _ Confirmer = redirectConfirmer{}

func (redirectConfirmer) CheckName() string { return "open-redirect" }

func (redirectConfirmer) Confirm(ctx context.Context, f model.Finding, clients model.Clients) (model.Finding, error) {
	req, err := http.NewRequestWithContext(ctx, f.Request.Method, f.Request.URL, nil)
	if err != nil {
		return f, err
	}

	// Do hands back the 3xx together with the CheckRedirect error, so a
	// non-nil error with a response is the expected, useful case.
	resp, _ := clients.Anonymous.Do(req)
	if resp == nil {
		return f, fmt.Errorf("no response replaying %s", f.Request.URL)
	}
	defer resp.Body.Close()

	location := resp.Header.Get("Location")
	host := redirectTargetHost(f.Request.Payload)

	if resp.StatusCode < 300 || resp.StatusCode >= 400 || !locationPointsAt(location, host) {
		f.Evidence.StatusCode = resp.StatusCode
		f.Evidence.ResponseSnippet = fmt.Sprintf(
			"did not reproduce: replaying it answered %d with Location %q, which no longer sends a browser to the external host",
			resp.StatusCode, location)
		return f, nil
	}

	f.Confirmed = true
	f.Evidence.StatusCode = resp.StatusCode
	f.Evidence.ResponseSnippet = fmt.Sprintf(
		"reproduced: the response redirects to %q, an external host supplied through the request", location)
	return f, nil
}

// redirectTargetHost recovers the host the probe tried to reach, so the
// confirmer checks the Location against the same host the finding is about
// rather than a hard-coded constant that could drift from the check's.
func redirectTargetHost(payload string) string {
	u, err := url.Parse(payload)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func locationPointsAt(location, host string) bool {
	if host == "" {
		return false
	}
	u, err := url.Parse(strings.TrimSpace(location))
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Hostname(), host)
}
