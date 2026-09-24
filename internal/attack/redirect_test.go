package attack

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/warden/internal/adapters/httpclient"
	"github.com/JonasBorgesLM/warden/internal/core/model"
	"github.com/JonasBorgesLM/warden/internal/core/scope"
)

func redirectScoped(t *testing.T, srv *httptest.Server) model.Clients {
	t.Helper()
	guard := scope.NewScopeGuard([]string{strings.TrimPrefix(srv.URL, "http://")})
	c := httpclient.New(guard, nil, 0)
	return model.Clients{Default: c, Anonymous: c}
}

func redirectFinding(url string) model.Finding {
	return model.Finding{
		CheckName: "open-redirect",
		Endpoint:  model.Endpoint{Method: http.MethodGet, Path: "/go"},
		Request:   model.CapturedRequest{Method: http.MethodGet, URL: url, InjectedParam: "next", Payload: "https://evil.example/"},
	}
}

// TestRedirectConfirmer_ReadsTheBlockedLocation reproduces without
// following: the target 302s off-scope, the ScopeGuard blocks the follow,
// and the confirmer reads the Location off the response returned alongside
// the error.
func TestRedirectConfirmer_ReadsTheBlockedLocation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", r.URL.Query().Get("next"))
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(srv.Close)

	got, err := redirectConfirmer{}.Confirm(t.Context(),
		redirectFinding(srv.URL+"/go?next=https://evil.example/"), redirectScoped(t, srv))
	if err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	if !got.Confirmed {
		t.Error("Confirmed = false, want the external redirect reproduced")
	}
	if !strings.Contains(got.Evidence.ResponseSnippet, "evil.example") {
		t.Errorf("evidence = %q, want the external host", got.Evidence.ResponseSnippet)
	}
}

// TestRedirectConfirmer_InternalRedirectDoesNotConfirm is the control.
func TestRedirectConfirmer_InternalRedirectDoesNotConfirm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/go" {
			w.Header().Set("Location", "/home")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	got, err := redirectConfirmer{}.Confirm(t.Context(),
		redirectFinding(srv.URL+"/go?next=https://evil.example/"), redirectScoped(t, srv))
	if err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	if got.Confirmed {
		t.Error("Confirmed = true for an internal redirect")
	}
}
