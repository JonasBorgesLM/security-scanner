package httpclient

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

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

func TestNew_NilHTTPClientGetsAWorkingClient(t *testing.T) {
	guard := scope.NewScopeGuard([]string{"localhost:8080"})

	got := New(guard, nil).httpClient
	if got == nil {
		t.Fatal("httpClient = nil, want a usable *http.Client")
	}
	// Must not be http.DefaultClient itself: New sets CheckRedirect on
	// whatever it returns, and mutating the shared global would leak a
	// redirect policy into any other code in the process using it.
	if got == http.DefaultClient {
		t.Error("httpClient == http.DefaultClient, want New to build its own client rather than mutate the shared global")
	}
}

// New must not mutate the *http.Client a caller supplies, nor share it
// between instances: two Clients built from the same custom *http.Client
// but different guards must not stomp on each other's CheckRedirect.
func TestNew_DoesNotMutateOrShareSuppliedHTTPClient(t *testing.T) {
	custom := &http.Client{Timeout: 7 * time.Second}

	guardA := scope.NewScopeGuard([]string{"a.invalid"})
	a := New(guardA, custom)
	guardB := scope.NewScopeGuard([]string{"b.invalid"})
	b := New(guardB, custom)

	if custom.CheckRedirect != nil {
		t.Error("the caller's original *http.Client was mutated (CheckRedirect set on it directly)")
	}
	if a.httpClient == custom || b.httpClient == custom {
		t.Error("New reused the caller's *http.Client instead of cloning it")
	}
	if a.httpClient == b.httpClient {
		t.Error("two New calls sharing a supplied *http.Client ended up sharing the clone too")
	}
	if a.httpClient.Timeout != 7*time.Second || b.httpClient.Timeout != 7*time.Second {
		t.Error("cloning the supplied *http.Client lost a field the caller set (Timeout)")
	}
}

// The bug this guards against: net/http.Client.Do follows redirects
// internally without ever calling back through Client.Do, so only checking
// the first request's host would let a 3xx from an in-scope host silently
// carry the scanner to an out-of-scope one.
func TestClient_Do_RedirectToOutOfScopeHostIsBlocked(t *testing.T) {
	outOfScope, outOfScopeHits := newCountingServer(t)

	inScope := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, outOfScope.URL+"/steal", http.StatusFound)
	}))
	t.Cleanup(inScope.Close)

	guard := scope.NewScopeGuard([]string{inScope.Listener.Addr().String()})
	client := New(guard, nil)

	req, err := http.NewRequest(http.MethodGet, inScope.URL+"/start", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	resp, err := client.Do(req)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("Do() error = nil, want the redirect to an out-of-scope host to be blocked")
	}
	if !errors.Is(err, scope.ErrOutOfScope) {
		t.Errorf("Do() error = %v, want errors.Is(err, scope.ErrOutOfScope)", err)
	}
	if got := atomic.LoadInt32(outOfScopeHits); got != 0 {
		t.Errorf("out-of-scope server received %d requests, want 0 — a redirect must never let a request past the guard", got)
	}
}

// A redirect that stays within the allowlist (e.g. a trailing-slash
// normalisation on the same host) must still work — the fix is scoped to
// blocking out-of-scope hops, not to breaking redirects altogether.
func TestClient_Do_RedirectWithinScopeIsFollowed(t *testing.T) {
	final, finalHits := newCountingServer(t)

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/done", http.StatusFound)
	}))
	t.Cleanup(redirector.Close)

	guard := scope.NewScopeGuard([]string{
		redirector.Listener.Addr().String(),
		final.Listener.Addr().String(),
	})
	client := New(guard, nil)

	req, err := http.NewRequest(http.MethodGet, redirector.URL+"/start", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v, want the in-scope redirect to be followed", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d (the final in-scope response)", resp.StatusCode, http.StatusOK)
	}
	if got := atomic.LoadInt32(finalHits); got != 1 {
		t.Errorf("final server received %d requests, want 1", got)
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
