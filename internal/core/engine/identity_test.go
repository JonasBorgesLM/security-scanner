package engine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/JonasBorgesLM/warden/internal/core/auth"
	"github.com/JonasBorgesLM/warden/internal/core/model"
)

// TestRun_AnonymousIdentityCarriesNoCredentials is the capability
// auth-required and idor were both waiting on.
//
// The Authenticator injects the token into every request that passes
// through it, so a check handed one client had no way to ask "what does
// this route do for someone who is not logged in?". The engine now hands
// over two identities, and this proves they really are two: the same check,
// the same route, one request with the token and one without.
func TestRun_AnonymousIdentityCarriesNoCredentials(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"token": "tok-identity"})
	})
	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.URL.Query().Get("as")] = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	authenticated, err := auth.New(srv.URL, auth.Config{
		LoginEndpoint: "/login",
		TokenPath:     "token",
		TokenPrefix:   "Bearer ",
		Credentials:   auth.Credentials{Username: "u", Password: "p"},
	}, http.DefaultClient)
	if err != nil {
		t.Fatalf("auth.New() error = %v", err)
	}

	send := func(ctx context.Context, c interface {
		Do(*http.Request) (*http.Response, error)
	}, as string) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/probe?as="+as, nil)
		if err != nil {
			t.Errorf("NewRequestWithContext() error = %v", err)
			return
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Errorf("Do(%s) error = %v", as, err)
			return
		}
		resp.Body.Close()
	}

	check := &stubCheck{
		meta: model.CheckMetadata{Name: "identity", Kind: model.KindActive},
		run: func(ctx context.Context, _ model.Target, c model.Clients) ([]model.Finding, error) {
			send(ctx, c.Default, "default")
			send(ctx, c.Anonymous, "anonymous")
			return nil, nil
		},
	}

	e, err := New(Config{BaseURL: srv.URL, MaxConcurrency: 1, RequestsPerSecond: 1000}, authenticated, http.DefaultClient, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := e.Run(t.Context(), e.BuildJobs(targetsFor(endpoints(1)), []model.Check{check})); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if got, want := seen["default"], "Bearer tok-identity"; got != want {
		t.Errorf("Default sent Authorization %q, want %q", got, want)
	}
	if got := seen["anonymous"]; got != "" {
		t.Errorf("Anonymous sent Authorization %q, want none — the whole point is that it carries no credentials", got)
	}
}

// TestNew_BothIdentitiesShareOneRateLimiter guards the property that keeps
// "gentle by design" true once a check has two clients to choose from.
//
// A second identity must not buy a second request budget: what the rate
// limit protects is the target's experience, and the target does not care
// which credentials a request carried. Two limiters at requests_per_second
// each would quietly double the load the operator configured.
func TestNew_BothIdentitiesShareOneRateLimiter(t *testing.T) {
	e, err := New(Config{BaseURL: testBaseURL, MaxConcurrency: 1, RequestsPerSecond: 10}, &fakeClient{}, &fakeClient{}, nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	def, ok := e.clients.Default.(*rateLimitedClient)
	if !ok {
		t.Fatalf("Default is %T, want it wrapped in the rate limiter", e.clients.Default)
	}
	anon, ok := e.clients.Anonymous.(*rateLimitedClient)
	if !ok {
		t.Fatalf("Anonymous is %T, want it wrapped in the rate limiter", e.clients.Anonymous)
	}
	if def.limiter != anon.limiter {
		t.Error("the two identities hold different limiters; a second identity must not buy a second request budget")
	}
}
