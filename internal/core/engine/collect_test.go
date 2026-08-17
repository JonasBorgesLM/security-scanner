package engine

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
	"github.com/JonasBorgesLM/security-scanner/internal/ports"
)

// ---------------------------------------------------------------- collection

// recordingClient answers every request and remembers what it was asked for.
type recordingClient struct {
	mu       sync.Mutex
	requests []string
	status   int
	headers  http.Header
	body     string
	err      error
}

var _ ports.HTTPClient = (*recordingClient)(nil)

func (c *recordingClient) Do(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.requests = append(c.requests, req.Method+" "+req.URL.String())
	c.mu.Unlock()

	if c.err != nil {
		return nil, c.err
	}
	status := c.status
	if status == 0 {
		status = http.StatusOK
	}
	headers := c.headers
	if headers == nil {
		headers = http.Header{}
	}
	return &http.Response{
		StatusCode: status,
		Header:     headers,
		Body:       io.NopCloser(strings.NewReader(c.body)),
		Request:    req,
	}, nil
}

func (c *recordingClient) seen() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.requests)
}

func newCollectEngine(t *testing.T, client ports.HTTPClient, testDestructive bool) *Engine {
	t.Helper()
	e, err := New(Config{
		BaseURL:           "http://lab.invalid",
		MaxConcurrency:    4,
		RequestsPerSecond: 100000,
		TestDestructive:   testDestructive,
	}, client)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return e
}

func TestCollect_CapturesOneBaselinePerEndpoint(t *testing.T) {
	client := &recordingClient{
		status:  http.StatusOK,
		headers: http.Header{"X-Frame-Options": []string{"DENY"}},
		body:    `{"ok":true}`,
	}
	e := newCollectEngine(t, client, false)

	eps := []model.Endpoint{
		{Method: "GET", Path: "/items"},
		{Method: "POST", Path: "/items"},
	}

	targets, _ := e.Collect(t.Context(), eps)

	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2", len(targets))
	}
	if got := len(client.seen()); got != 2 {
		t.Errorf("client saw %d requests, want exactly one baseline per endpoint", got)
	}
	for _, target := range targets {
		if target.BaselineErr != nil {
			t.Fatalf("%s: BaselineErr = %v", target.Endpoint.Path, target.BaselineErr)
		}
		if target.Baseline == nil {
			t.Fatalf("%s: Baseline is nil", target.Endpoint.Path)
		}
		if target.Baseline.StatusCode != http.StatusOK {
			t.Errorf("StatusCode = %d, want 200", target.Baseline.StatusCode)
		}
		if got := target.Baseline.Headers.Get("X-Frame-Options"); got != "DENY" {
			t.Errorf("headers not captured: X-Frame-Options = %q", got)
		}
		if string(target.Baseline.Body) != `{"ok":true}` {
			t.Errorf("Body = %q, want the response body", target.Baseline.Body)
		}
	}
}

func TestCollect_SubstitutesPathParameters(t *testing.T) {
	client := &recordingClient{}
	e := newCollectEngine(t, client, false)

	_, _ = e.Collect(t.Context(), []model.Endpoint{
		{Method: "GET", Path: "/items/{id}"},
		{Method: "GET", Path: "/users/{userId}/posts/{postId}"},
	})

	want := []string{
		"GET http://lab.invalid/items/1",
		"GET http://lab.invalid/users/1/posts/1",
	}
	got := client.seen()
	slices.Sort(got)
	slices.Sort(want)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("requests = %v, want %v — path templates must be filled in", got, want)
	}
}

func TestCollect_NeverTouchesDestructiveEndpointsByDefault(t *testing.T) {
	client := &recordingClient{}
	e := newCollectEngine(t, client, false)

	targets, _ := e.Collect(t.Context(), []model.Endpoint{
		{Method: "GET", Path: "/items"},
		{Method: "DELETE", Path: "/items/{id}", Destructive: true},
		{Method: "PUT", Path: "/items/{id}", Destructive: true},
	})

	if len(targets) != 1 {
		t.Errorf("got %d targets, want 1 — destructive endpoints must not be collected", len(targets))
	}
	for _, r := range client.seen() {
		if strings.HasPrefix(r, "DELETE") || strings.HasPrefix(r, "PUT") {
			t.Errorf("a baseline %s was sent — there is no harmless baseline DELETE", r)
		}
	}
}

func TestCollect_IncludesDestructiveWhenOptedIn(t *testing.T) {
	client := &recordingClient{}
	e := newCollectEngine(t, client, true)

	targets, _ := e.Collect(t.Context(), []model.Endpoint{
		{Method: "GET", Path: "/items"},
		{Method: "DELETE", Path: "/items/{id}", Destructive: true},
	})

	if len(targets) != 2 {
		t.Errorf("got %d targets, want 2 with test_destructive enabled", len(targets))
	}
}

func TestCollect_FailureBecomesBaselineErrNotAMissingTarget(t *testing.T) {
	boom := errors.New("connection refused")
	e := newCollectEngine(t, &recordingClient{err: boom}, false)

	targets, _ := e.Collect(t.Context(), endpoints(3))

	if len(targets) != 3 {
		t.Fatalf("got %d targets, want 3 — a failed collection still yields a target", len(targets))
	}
	for _, target := range targets {
		if target.Baseline != nil {
			t.Errorf("%s: Baseline is non-nil despite the failure", target.Endpoint.Path)
		}
		if !errors.Is(target.BaselineErr, boom) {
			t.Errorf("%s: BaselineErr = %v, want it to wrap the transport error", target.Endpoint.Path, target.BaselineErr)
		}
	}
}

func TestCollect_PreservesEndpointOrder(t *testing.T) {
	e := newCollectEngine(t, &recordingClient{}, false)

	eps := []model.Endpoint{
		{Method: "GET", Path: "/zzz"},
		{Method: "GET", Path: "/aaa"},
		{Method: "GET", Path: "/mmm"},
	}

	for range 10 {
		targets, _ := e.Collect(t.Context(), eps)
		if len(targets) != 3 {
			t.Fatalf("got %d targets, want 3", len(targets))
		}
		for i, ep := range eps {
			if targets[i].Endpoint.Path != ep.Path {
				t.Fatalf("targets[%d] = %s, want %s", i, targets[i].Endpoint.Path, ep.Path)
			}
		}
	}
}

func TestCollect_RespectsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	client := &recordingClient{}
	e := newCollectEngine(t, client, false)

	targets, _ := e.Collect(ctx, endpoints(20))

	if len(targets) != 0 {
		t.Errorf("got %d targets, want 0 for an already-cancelled context", len(targets))
	}
	if got := len(client.seen()); got != 0 {
		t.Errorf("client saw %d requests, want 0", got)
	}
}

func TestCollect_NoEndpoints(t *testing.T) {
	e := newCollectEngine(t, &recordingClient{}, false)
	if got, _ := e.Collect(t.Context(), nil); len(got) != 0 {
		t.Errorf("got %d targets, want 0", len(got))
	}
}

// ------------------------------------------------------- passive check wiring

// A passive check must work from the collected baseline. The engine hands
// it a client that refuses, so the rule holds by construction.
func TestRun_PassiveCheckIsDeniedTheNetwork(t *testing.T) {
	client := &recordingClient{}
	e := newCollectEngine(t, client, false)

	var attemptErr error
	passive := &stubCheck{
		meta: model.CheckMetadata{Name: "nosy-passive", Kind: model.KindPassive},
		run: func(ctx context.Context, target model.Target, c ports.HTTPClient) ([]model.Finding, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://lab.invalid/sneaky", nil)
			if err != nil {
				return nil, err
			}
			_, attemptErr = c.Do(req)
			return nil, nil
		},
	}

	targets, _ := e.Collect(t.Context(), endpoints(1))
	before := len(client.seen())

	if _, err := e.Run(t.Context(), e.BuildJobs(targets, []model.Check{passive})); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !errors.Is(attemptErr, ErrPassiveCheckRequest) {
		t.Errorf("passive check's Do() error = %v, want ErrPassiveCheckRequest", attemptErr)
	}
	if got := len(client.seen()); got != before {
		t.Errorf("client saw %d extra requests, want 0 — the passive check reached the network", got-before)
	}
}

// An active check gets the real (rate-limited) client and can reach out.
func TestRun_ActiveCheckKeepsTheNetwork(t *testing.T) {
	client := &recordingClient{}
	e := newCollectEngine(t, client, false)

	active := &stubCheck{
		meta: model.CheckMetadata{Name: "prober", Kind: model.KindActive},
		run: func(ctx context.Context, target model.Target, c ports.HTTPClient) ([]model.Finding, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://lab.invalid/probe", nil)
			if err != nil {
				return nil, err
			}
			resp, err := c.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			return nil, nil
		},
	}

	targets, _ := e.Collect(t.Context(), endpoints(1))
	before := len(client.seen())

	results, err := e.Run(t.Context(), e.BuildJobs(targets, []model.Check{active}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if results[0].Err != nil {
		t.Errorf("Result.Err = %v, want nil", results[0].Err)
	}
	if got := len(client.seen()) - before; got != 1 {
		t.Errorf("client saw %d extra requests, want 1", got)
	}
}

// The point of collecting once: many checks on one endpoint still cost a
// single request, and each of them sees the same response.
func TestRun_ManyPassiveChecksShareOneCollectedResponse(t *testing.T) {
	client := &recordingClient{
		status:  http.StatusOK,
		headers: http.Header{"Server": []string{"lab/1.0"}},
		body:    "hello",
	}
	e := newCollectEngine(t, client, false)

	var mu sync.Mutex
	seenBodies := map[string]int{}

	makeCheck := func(name string) model.Check {
		return &stubCheck{
			meta: model.CheckMetadata{Name: name, Kind: model.KindPassive},
			run: func(ctx context.Context, target model.Target, c ports.HTTPClient) ([]model.Finding, error) {
				if target.Baseline == nil {
					return nil, errors.New("no baseline")
				}
				mu.Lock()
				seenBodies[string(target.Baseline.Body)]++
				mu.Unlock()
				if target.Baseline.Headers.Get("Server") != "lab/1.0" {
					return nil, errors.New("headers missing from baseline")
				}
				return []model.Finding{{ID: name}}, nil
			},
		}
	}
	checks := []model.Check{makeCheck("a"), makeCheck("b"), makeCheck("c"), makeCheck("d")}

	eps := endpoints(3)
	targets, _ := e.Collect(t.Context(), eps)

	if got := len(client.seen()); got != len(eps) {
		t.Fatalf("collection made %d requests, want %d (one per endpoint)", got, len(eps))
	}

	results, err := e.Run(t.Context(), e.BuildJobs(targets, checks))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if len(results) != len(eps)*len(checks) {
		t.Errorf("got %d results, want %d", len(results), len(eps)*len(checks))
	}
	for _, r := range results {
		if r.Err != nil {
			t.Errorf("%s on %s: Err = %v", r.CheckName, r.Endpoint.Path, r.Err)
		}
	}
	// Still only the collection requests: 12 checks, 3 requests.
	if got := len(client.seen()); got != len(eps) {
		t.Errorf("client saw %d requests after running %d checks, want %d", got, len(results), len(eps))
	}

	mu.Lock()
	defer mu.Unlock()
	if seenBodies["hello"] != len(eps)*len(checks) {
		t.Errorf("checks saw the shared body %d times, want %d", seenBodies["hello"], len(eps)*len(checks))
	}
}

func TestRun_CheckSeesBaselineError(t *testing.T) {
	boom := errors.New("connection refused")
	e := newCollectEngine(t, &recordingClient{err: boom}, false)

	var sawErr bool
	check := &stubCheck{
		meta: model.CheckMetadata{Name: "careful", Kind: model.KindPassive},
		run: func(ctx context.Context, target model.Target, c ports.HTTPClient) ([]model.Finding, error) {
			if target.Baseline == nil && target.BaselineErr != nil {
				sawErr = true
				// Cannot conclude anything: report nothing rather than guess.
				return nil, nil
			}
			return []model.Finding{{ID: "should not happen"}}, nil
		},
	}

	targets, _ := e.Collect(t.Context(), endpoints(1))
	results, err := e.Run(t.Context(), e.BuildJobs(targets, []model.Check{check}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if !sawErr {
		t.Error("the check did not observe BaselineErr")
	}
	if len(results) != 1 || len(results[0].Findings) != 0 {
		t.Errorf("results = %+v, want one result with no findings", results)
	}
}

func TestDeniedClient_NamesTheAttemptedRequest(t *testing.T) {
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://lab.invalid/x", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	_, gotErr := deniedClient{}.Do(req)
	if !errors.Is(gotErr, ErrPassiveCheckRequest) {
		t.Fatalf("Do() error = %v, want ErrPassiveCheckRequest", gotErr)
	}
	if !strings.Contains(gotErr.Error(), "POST") || !strings.Contains(gotErr.Error(), "/x") {
		t.Errorf("error = %q, want it to name the attempted request", gotErr)
	}
}

// errReader fails part-way through the body, simulating a connection that
// drops mid-response.
type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// brokenBodyClient answers with a response whose body cannot be read.
type brokenBodyClient struct{ err error }

var _ ports.HTTPClient = (*brokenBodyClient)(nil)

func (c *brokenBodyClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(errReader{err: c.err}),
		Request:    req,
	}, nil
}

func TestCollect_UnreadableBodyBecomesBaselineErr(t *testing.T) {
	boom := errors.New("unexpected EOF")
	e := newCollectEngine(t, &brokenBodyClient{err: boom}, false)

	targets, _ := e.Collect(t.Context(), endpoints(1))

	if len(targets) != 1 {
		t.Fatalf("got %d targets, want 1", len(targets))
	}
	if targets[0].Baseline != nil {
		t.Error("Baseline is non-nil despite an unreadable body")
	}
	if !errors.Is(targets[0].BaselineErr, boom) {
		t.Errorf("BaselineErr = %v, want it to wrap the read error", targets[0].BaselineErr)
	}
}

// The collection phase must never send a request that changes state. An
// endpoint declared POST is probed with GET instead, and the substitution
// is recorded so a check is not misled about what produced the response.
func TestCollect_ProbesUnsafeMethodsWithGet(t *testing.T) {
	client := &recordingClient{}
	e := newCollectEngine(t, client, true)

	targets, err := e.Collect(t.Context(), []model.Endpoint{
		{Method: "GET", Path: "/a"},
		{Method: "HEAD", Path: "/b"},
		{Method: "OPTIONS", Path: "/c"},
		{Method: "POST", Path: "/d"},
		{Method: "PUT", Path: "/e", Destructive: true},
		{Method: "PATCH", Path: "/f", Destructive: true},
		{Method: "DELETE", Path: "/g", Destructive: true},
	})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	for _, r := range client.seen() {
		method, _, _ := strings.Cut(r, " ")
		if !safeMethods[method] {
			t.Errorf("collection sent %s — only safe methods may be used to build a baseline", r)
		}
	}

	wantProbe := map[string]string{
		"/a": "GET", "/b": "HEAD", "/c": "OPTIONS",
		"/d": "GET", "/e": "GET", "/f": "GET", "/g": "GET",
	}
	for _, target := range targets {
		want := wantProbe[target.Endpoint.Path]
		if target.Baseline == nil {
			t.Fatalf("%s: Baseline is nil", target.Endpoint.Path)
		}
		if got := target.Baseline.ProbedMethod; got != want {
			t.Errorf("%s (declared %s): ProbedMethod = %q, want %q",
				target.Endpoint.Path, target.Endpoint.Method, got, want)
		}
	}
}

func TestCollect_RecordsProbedURL(t *testing.T) {
	e := newCollectEngine(t, &recordingClient{}, false)

	targets, err := e.Collect(t.Context(), []model.Endpoint{{Method: "GET", Path: "/items/{id}"}})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if got := targets[0].Baseline.URL; got != "http://lab.invalid/items/1" {
		t.Errorf("Baseline.URL = %q, want the absolute probed URL", got)
	}
}

// The baseline must not alias anything the rest of the process can mutate,
// because every check on the endpoint reads the same map concurrently.
func TestCollect_ClonesResponseHeaders(t *testing.T) {
	shared := http.Header{"X-Original": []string{"yes"}}
	client := &recordingClient{headers: shared}
	e := newCollectEngine(t, client, false)

	targets, err := e.Collect(t.Context(), endpoints(1))
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	shared.Set("X-Original", "tampered")
	shared.Set("X-Added-Later", "surprise")

	if got := targets[0].Baseline.Headers.Get("X-Original"); got != "yes" {
		t.Errorf("baseline header = %q, want %q — the header map was not cloned", got, "yes")
	}
	if got := targets[0].Baseline.Headers.Get("X-Added-Later"); got != "" {
		t.Errorf("baseline picked up %q added after collection — the map is still aliased", got)
	}
}

func TestCollect_UnjoinableBaseURLBecomesBaselineErr(t *testing.T) {
	e, err := New(Config{
		BaseURL:           "http://lab.invalid/\x7f\x00",
		MaxConcurrency:    2,
		RequestsPerSecond: 100000,
	}, &recordingClient{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	targets, _ := e.Collect(t.Context(), endpoints(1))

	if len(targets) != 1 {
		t.Fatalf("got %d targets, want 1", len(targets))
	}
	if targets[0].BaselineErr == nil {
		t.Error("BaselineErr = nil, want an error for a base URL that cannot be joined")
	}
}
