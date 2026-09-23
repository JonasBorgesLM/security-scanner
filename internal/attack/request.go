package attack

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/JonasBorgesLM/warden/internal/ports"
)

// maxProbeBodyBytes caps how much of any single PoC response is read.
const maxProbeBodyBytes = 1 << 20 // 1 MiB

// withInjectedValue rewrites rawURL so injectedParam carries newValue
// instead of oldValue, working from nothing but what CapturedRequest
// already stores — it does not need to know the endpoint's parameter list,
// since scan already resolved that once and captured the result.
//
// It handles both shapes a Finding's injection point can take: a query
// parameter (found and replaced through net/url, which re-escapes
// correctly) and a path parameter (found by locating oldValue in the
// path's DECODED form — u.Path, not the raw URL string — since url.URL
// keeps the escaped form only in RawPath and re-derives it from Path on
// String(); matching against the escaped form here would silently never
// find anything).
func withInjectedValue(rawURL, injectedParam, oldValue, newValue string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parse %q: %w", rawURL, err)
	}

	if q := u.Query(); injectedParam != "" && q.Has(injectedParam) {
		q.Set(injectedParam, newValue)
		u.RawQuery = q.Encode()
		return u.String(), nil
	}

	if !strings.Contains(u.Path, oldValue) {
		return "", fmt.Errorf("%q not found as a query parameter or in the path of %q", injectedParam, rawURL)
	}
	u.Path = strings.Replace(u.Path, oldValue, newValue, 1)
	// Clear RawPath: it would otherwise still hold the escaping of the OLD
	// path, and url.URL prefers RawPath over re-escaping Path whenever the
	// two are consistent with each other, which after this edit they are
	// not.
	u.RawPath = ""
	return u.String(), nil
}

// probeResult is one HTTP response boiled down to what a Confirmer needs.
type probeResult struct {
	status int
	body   []byte
}

// get sends a body-less request to rawURL with method and reads the
// response.
//
// It keeps the endpoint's own method — a finding on a POST route is
// replayed as POST — because a Confirmer's job is to reproduce what scan
// saw, and a server routing strictly by method would answer 405 to
// anything else. What it never does is carry a body: every Confirmer here
// only needs to read data back (extract a database name, look for a
// reflected marker), and resubmitting an endpoint's own payload is
// squarely the attack territory this project does not go into.
//
// The name is historical — it predates the method parameter — and is kept
// because "body-less read-back request" is still what every caller wants
// from it.
func get(ctx context.Context, client ports.HTTPClient, method, rawURL string) (*probeResult, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", rawURL, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("reading response from %s: %w", rawURL, err)
	}
	return &probeResult{status: resp.StatusCode, body: body}, nil
}

// snippetOf renders a short, single-line excerpt of a response body for
// evidence — collapsing whitespace so a formatted body doesn't blow up the
// line count of a reviewed confirmed.json.
func snippetOf(body []byte, limit int) string {
	s := strings.Join(strings.Fields(string(body)), " ")
	if s == "" {
		return "<empty body>"
	}
	r := []rune(s)
	if len(r) > limit {
		return string(r[:limit]) + "…"
	}
	return s
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
