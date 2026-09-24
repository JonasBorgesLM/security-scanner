package httpclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JonasBorgesLM/warden/internal/core/scope"
)

// NewScopeGuardFor builds a guard that allows exactly srv's host.
func NewScopeGuardFor(t *testing.T, srv *httptest.Server) *scope.ScopeGuard {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parsing test server URL: %v", err)
	}
	return scope.NewScopeGuard([]string{u.Host})
}

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
	client := New(guard, nil, 0)

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
	client := New(guard, nil, 0)

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

	got := New(guard, nil, 0).httpClient
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
	a := New(guardA, custom, 0)
	guardB := scope.NewScopeGuard([]string{"b.invalid"})
	b := New(guardB, custom, 0)

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
	client := New(guard, nil, 0)

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
	client := New(guard, nil, 0)

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
	New(nil, nil, 0)
}

// ------------------------------------------------------------ per-request timeout

// newStallingServer serves a handler that answers only after stall — or as
// soon as the client gives up, whichever comes first. Watching the request
// context matters: without it a handler still sleeping when the client has
// already timed out would hold srv.Close() for the rest of the stall.
func newStallingServer(t *testing.T, stall time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(stall):
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestClient_Do_WithoutTimeout_WaitsOutAStalledServer is the negative
// control for the test below: with no per-request bound the stall is simply
// absorbed and the request succeeds. It is what makes the next test's
// failure attributable to the timeout rather than to the server.
func TestClient_Do_WithoutTimeout_WaitsOutAStalledServer(t *testing.T) {
	srv := newStallingServer(t, 200*time.Millisecond)
	client := New(NewScopeGuardFor(t, srv), nil, 0)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do() with no timeout error = %v, want the stalled request to be absorbed", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Do() status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestClient_Do_TimeoutFiresWithoutSpendingTheRunDeadline is the point of
// the per-request bound, and the second assertion is the one that matters.
// Before this existed the only limit was the run's own context, so a route
// that accepted a connection and never answered held its worker until the
// global deadline — and the whole scan was then discarded as incomplete.
// A request that gives up on its own must leave that deadline untouched.
func TestClient_Do_TimeoutFiresWithoutSpendingTheRunDeadline(t *testing.T) {
	srv := newStallingServer(t, 10*time.Second)
	client := New(NewScopeGuardFor(t, srv), nil, 50*time.Millisecond)

	// Stands in for the scan's global deadline: generous, and it must still
	// be generous once the request below has given up.
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)

	if err == nil {
		resp.Body.Close()
		t.Fatal("Do() = nil error, want the per-request timeout to fire")
	}
	if elapsed > 5*time.Second {
		t.Errorf("Do() took %v, want it to give up near the 50ms timeout rather than wait out the server", elapsed)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		t.Errorf("run context error = %v, want nil — a single stalled request must not spend the whole run's deadline", ctxErr)
	}
}

// TestNew_DoesNotMutateSuppliedClientTimeout guards the same sharing rule
// New already keeps for CheckRedirect: the timeout goes on New's own copy,
// never on the *http.Client the caller handed over and may still be using.
func TestNew_DoesNotMutateSuppliedClientTimeout(t *testing.T) {
	custom := &http.Client{}
	guard := scope.NewScopeGuard([]string{"example.com"})

	c := New(guard, custom, 250*time.Millisecond)

	if custom.Timeout != 0 {
		t.Errorf("supplied client Timeout = %v, want 0 — New must not write through to the caller's client", custom.Timeout)
	}
	if c.httpClient.Timeout != 250*time.Millisecond {
		t.Errorf("Client timeout = %v, want 250ms", c.httpClient.Timeout)
	}
}

// TestNew_NonPositiveTimeoutLeavesNoLimit documents the escape hatch the
// tests above rely on, so a later reader does not "fix" it into a default.
func TestNew_NonPositiveTimeoutLeavesNoLimit(t *testing.T) {
	guard := scope.NewScopeGuard([]string{"example.com"})

	for _, d := range []time.Duration{0, -time.Second} {
		if got := New(guard, nil, d).httpClient.Timeout; got != 0 {
			t.Errorf("New(..., %v) timeout = %v, want 0 (no limit)", d, got)
		}
	}
}
