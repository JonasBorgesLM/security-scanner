package checks

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JonasBorgesLM/security-scanner/internal/adapters/httpclient"
	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
	"github.com/JonasBorgesLM/security-scanner/internal/core/scope"
)

// scopedClient builds the real ScopeGuard-enforcing client allowing only
// srv's host — so an off-scope Location is blocked exactly as in a real run,
// which is the behaviour this check reads.
func scopedClient(t *testing.T, srv *httptest.Server) model.Clients {
	t.Helper()
	host := strings.TrimPrefix(srv.URL, "http://")
	guard := scope.NewScopeGuard([]string{host})
	c := httpclient.New(guard, nil, 5*time.Second) // a per-request bound, as the composition root always sets
	return model.Clients{Default: c, Anonymous: c}
}

func redirectTarget(srv *httptest.Server, param string) model.Target {
	return model.Target{
		Endpoint: model.Endpoint{Method: http.MethodGet, Path: "/go", Parameters: []model.Parameter{queryParam(param)}},
		Baseline: &model.Response{URL: srv.URL + "/go", StatusCode: 200, ProbedMethod: http.MethodGet},
	}
}

// TestOpenRedirect_ExternalLocationIsAFinding is the case, and it exercises
// the delicate part: the target returns a 302 to an off-scope host, the
// ScopeGuard blocks the follow and Do returns an error alongside the 302,
// and the check reads the Location off that response rather than treating
// the error as a failure.
func TestOpenRedirect_ExternalLocationIsAFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if dest := r.URL.Query().Get("next"); dest != "" {
			w.Header().Set("Location", dest)
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	findings, err := (&openRedirect{}).Run(t.Context(), redirectTarget(srv, "next"), scopedClient(t, srv))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Evidence.ResponseSnippet, redirectHost) {
		t.Errorf("evidence = %q, want the external host it redirected to", findings[0].Evidence.ResponseSnippet)
	}
}

// TestOpenRedirect_InternalRedirectIsClean is the control: a route that
// only ever redirects within itself is not vulnerable, even though it does
// redirect.
func TestOpenRedirect_InternalRedirectIsClean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/go" {
			w.Header().Set("Location", "/home") // internal, ignores the param
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	findings, err := (&openRedirect{}).Run(t.Context(), redirectTarget(srv, "next"), scopedClient(t, srv))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings for an internal redirect, want 0", len(findings))
	}
}

// TestOpenRedirect_OnlyRedirectishParameters keeps it from planting a URL
// in fields that are not a destination.
func TestOpenRedirect_OnlyRedirectishParameters(t *testing.T) {
	applies := (&openRedirect{}).Metadata().AppliesTo
	if applies(model.Endpoint{Parameters: []model.Parameter{queryParam("q")}}) {
		t.Error("AppliesTo = true for a plain query parameter")
	}
	if !applies(model.Endpoint{Parameters: []model.Parameter{queryParam("redirect_uri")}}) {
		t.Error("AppliesTo = false for redirect_uri")
	}
}

// TestPointsAt_ParsesRatherThanMatches guards against a substring false
// positive: a Location that merely contains the host in a query parameter
// does not redirect to it.
func TestPointsAt_ParsesRatherThanMatches(t *testing.T) {
	if !pointsAt("https://scanner-redirect.example/x", "scanner-redirect.example") {
		t.Error("pointsAt = false for a genuine redirect to the host")
	}
	if pointsAt("https://target.internal/?next=scanner-redirect.example", "scanner-redirect.example") {
		t.Error("pointsAt = true for a host that only appears in a query parameter")
	}
}

// TestOpenRedirect_NoCandidatesIsCleanNotSkip: an endpoint with no
// redirect-ish parameter has nothing to test and no gap to admit.
func TestOpenRedirect_NoCandidatesIsCleanNotSkip(t *testing.T) {
	target := model.Target{
		Endpoint: model.Endpoint{Method: http.MethodGet, Path: "/x", Parameters: []model.Parameter{queryParam("q")}},
		Baseline: &model.Response{URL: "http://lab.test/x", StatusCode: 200, ProbedMethod: http.MethodGet},
	}
	findings, err := (&openRedirect{}).Run(t.Context(), target, model.Clients{Anonymous: http.DefaultClient})
	if err != nil && !errors.Is(err, model.ErrSkipped) {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}
