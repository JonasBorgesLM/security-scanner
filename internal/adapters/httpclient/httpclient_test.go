package httpclient

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/JonasBorgesLM/security-scanner/internal/core/scope"
)

func newCountingServer(t *testing.T) (srv *httptest.Server, hits *int32) {
	t.Helper()
	hits = new(int32)
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, hits
}

// (a) A host in the allowlist passes through untouched.
func TestClient_Do_AllowedHostReachesServer(t *testing.T) {
	srv, hits := newCountingServer(t)

	guard := scope.NewScopeGuard([]string{srv.Listener.Addr().String()})
	client := New(guard, nil)

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v, want nil for an allowed host", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := atomic.LoadInt32(hits); got != 1 {
		t.Errorf("server received %d requests, want 1", got)
	}
}

// (b) A host outside the allowlist is blocked, and — crucially — the
// request never reaches the network at all.
func TestClient_Do_BlockedHostNeverReachesServer(t *testing.T) {
	srv, hits := newCountingServer(t)

	// Deliberately does not include srv's host: everything is out of scope.
	guard := scope.NewScopeGuard([]string{"only-this-host-is-allowed.invalid:9999"})
	client := New(guard, nil)

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	resp, err := client.Do(req)
	if resp != nil {
		resp.Body.Close()
		t.Errorf("Do() response = %v, want nil when blocked", resp)
	}
	if err == nil {
		t.Fatal("Do() error = nil, want an error for an out-of-scope host")
	}
	if !errors.Is(err, scope.ErrOutOfScope) {
		t.Errorf("Do() error = %v, want errors.Is(err, scope.ErrOutOfScope)", err)
	}
	if got := atomic.LoadInt32(hits); got != 0 {
		t.Errorf("server received %d requests, want 0 — an out-of-scope request must never touch the network", got)
	}
}

func TestNew_NilHTTPClientFallsBackToDefault(t *testing.T) {
	guard := scope.NewScopeGuard([]string{"localhost:8080"})

	if got := New(guard, nil).httpClient; got != http.DefaultClient {
		t.Errorf("httpClient = %p, want http.DefaultClient (%p)", got, http.DefaultClient)
	}
}

func TestNew_KeepsSuppliedHTTPClient(t *testing.T) {
	guard := scope.NewScopeGuard([]string{"localhost:8080"})
	custom := &http.Client{}

	if got := New(guard, custom).httpClient; got != custom {
		t.Errorf("httpClient = %p, want the supplied client (%p)", got, custom)
	}
}

func TestNew_PanicsOnNilGuard(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("New(nil, ...) did not panic; a ScopeGuard is mandatory")
		}
	}()
	New(nil, nil)
}
