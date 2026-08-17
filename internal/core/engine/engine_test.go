package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
	"github.com/JonasBorgesLM/security-scanner/internal/ports"
)

// fakeClient records when each request was let through, so tests can assert
// on pacing without any real network.
type fakeClient struct {
	mu    sync.Mutex
	times []time.Time

	// delay simulates a slow target.
	delay time.Duration
	// err, when set, is returned instead of a response.
	err error
}

var _ ports.HTTPClient = (*fakeClient)(nil)

func (c *fakeClient) Do(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.times = append(c.times, time.Now())
	c.mu.Unlock()

	if c.delay > 0 {
		select {
		case <-time.After(c.delay):
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
	if c.err != nil {
		return nil, c.err
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("ok")),
		Request:    req,
	}, nil
}

func (c *fakeClient) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.times)
}

func (c *fakeClient) elapsed() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.times) < 2 {
		return 0
	}
	return c.times[len(c.times)-1].Sub(c.times[0])
}

// stubCheck is a model.Check driven entirely by the test.
type stubCheck struct {
	meta model.CheckMetadata
	run  func(ctx context.Context, t model.Target, c ports.HTTPClient) ([]model.Finding, error)
}

var _ model.Check = (*stubCheck)(nil)

func (s *stubCheck) Metadata() model.CheckMetadata { return s.meta }

func (s *stubCheck) Run(ctx context.Context, t model.Target, c ports.HTTPClient) ([]model.Finding, error) {
	return s.run(ctx, t, c)
}

// oneRequestCheck issues exactly one request per job — the simplest way to
// make request count equal job count.
func oneRequestCheck(name string) *stubCheck {
	return &stubCheck{
		meta: model.CheckMetadata{Name: name, Kind: model.KindActive},
		run: func(ctx context.Context, t model.Target, c ports.HTTPClient) ([]model.Finding, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://lab.invalid"+t.Endpoint.Path, nil)
			if err != nil {
				return nil, err
			}
			resp, err := c.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
			return nil, nil
		},
	}
}

// testBaseURL is never dialled: the fake client answers before anything
// leaves the process.
const testBaseURL = "http://lab.invalid"

// newEngine builds an Engine with settings fast enough not to slow tests
// down, varying only the destructive opt-in.
func newEngine(t *testing.T, testDestructive bool) *Engine {
	t.Helper()
	e, err := New(Config{
		BaseURL:           testBaseURL,
		MaxConcurrency:    4,
		RequestsPerSecond: 100000,
		TestDestructive:   testDestructive,
	}, &fakeClient{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return e
}

// targetsFor wraps endpoints as targets without a baseline, for tests that
// only exercise job construction.
func targetsFor(eps []model.Endpoint) []model.Target {
	targets := make([]model.Target, len(eps))
	for i, ep := range eps {
		targets[i] = model.Target{Endpoint: ep}
	}
	return targets
}

func endpoints(n int) []model.Endpoint {
	eps := make([]model.Endpoint, n)
	for i := range n {
		eps[i] = model.Endpoint{Method: http.MethodGet, Path: fmt.Sprintf("/r%02d", i)}
	}
	return eps
}

func jobsFor(eps []model.Endpoint, c model.Check) []Job {
	jobs := make([]Job, len(eps))
	for i, ep := range eps {
		jobs[i] = Job{Target: model.Target{Endpoint: ep}, Check: c}
	}
	return jobs
}

// ---------------------------------------------------------------- rate limit

func TestRun_RespectsRateLimit(t *testing.T) {
	const (
		jobs  = 10
		rps   = 50.0
		burst = 1
	)

	client := &fakeClient{}
	e, err := New(Config{BaseURL: testBaseURL, MaxConcurrency: 8, RequestsPerSecond: rps, Burst: burst}, client)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	start := time.Now()
	results, err := e.Run(t.Context(), jobsFor(endpoints(jobs), oneRequestCheck("paced")))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	total := time.Since(start)

	if len(results) != jobs {
		t.Fatalf("got %d results, want %d", len(results), jobs)
	}
	if got := client.count(); got != jobs {
		t.Fatalf("client saw %d requests, want %d", got, jobs)
	}

	// With a burst of 1, the first request goes immediately and the
	// remaining jobs-1 are spaced 1/rps apart. Allow slack for scheduling
	// jitter, but a pool that ignored the limiter would finish in ~0ms.
	wantMin := time.Duration(float64(jobs-burst) / rps * float64(time.Second))
	if total < time.Duration(float64(wantMin)*0.85) {
		t.Errorf("run took %v, want at least ~%v — %d workers appear to have outrun the %.0f req/s limit",
			total, wantMin, 8, rps)
	}

	// Independently of wall-clock slack, the observed rate across the
	// requests themselves must not exceed the configured ceiling.
	if spread := client.elapsed(); spread > 0 {
		observed := float64(jobs-1) / spread.Seconds()
		if observed > rps*1.35 {
			t.Errorf("observed %.1f req/s across %v, want <= ~%.0f req/s", observed, spread, rps)
		}
	}
}

func TestRun_RateLimitAppliesAcrossWorkers(t *testing.T) {
	// A per-worker limiter would let concurrency multiply the rate. One
	// shared limiter must hold the total down no matter the pool size.
	const (
		jobs = 12
		rps  = 40.0
	)

	client := &fakeClient{}
	e, err := New(Config{BaseURL: testBaseURL, MaxConcurrency: jobs, RequestsPerSecond: rps, Burst: 1}, client)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	start := time.Now()
	if _, err := e.Run(t.Context(), jobsFor(endpoints(jobs), oneRequestCheck("paced"))); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	total := time.Since(start)

	wantMin := time.Duration(float64(jobs-1) / rps * float64(time.Second))
	if total < time.Duration(float64(wantMin)*0.85) {
		t.Errorf("run with %d workers took %v, want at least ~%v — the limiter is not shared", jobs, total, wantMin)
	}
}

func TestRun_BurstAllowsAnInitialBatch(t *testing.T) {
	const (
		jobs  = 5
		rps   = 2.0 // slow enough that only the burst can land quickly
		burst = 5
	)

	client := &fakeClient{}
	e, err := New(Config{BaseURL: testBaseURL, MaxConcurrency: jobs, RequestsPerSecond: rps, Burst: burst}, client)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	start := time.Now()
	if _, err := e.Run(t.Context(), jobsFor(endpoints(jobs), oneRequestCheck("bursty"))); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// All five fit in the burst, so nothing should have waited on the
	// 2 req/s sustained rate (which would have taken ~2s).
	if total := time.Since(start); total > 500*time.Millisecond {
		t.Errorf("run took %v, want it to complete within the burst allowance", total)
	}
	if got := client.count(); got != jobs {
		t.Errorf("client saw %d requests, want %d", got, jobs)
	}
}

// ---------------------------------------------------------------- shutdown

func TestRun_CancellationStopsThePool(t *testing.T) {
	const jobs = 200

	var started atomic.Int32
	release := make(chan struct{})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	check := &stubCheck{
		meta: model.CheckMetadata{Name: "slow", Kind: model.KindActive},
		run: func(ctx context.Context, t model.Target, c ports.HTTPClient) ([]model.Finding, error) {
			// Cancel once the pool is demonstrably busy.
			if started.Add(1) == 4 {
				close(release)
			}
			<-release
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(10 * time.Millisecond):
				return nil, nil
			}
		},
	}

	e, err := New(Config{BaseURL: testBaseURL, MaxConcurrency: 4, RequestsPerSecond: 1000}, &fakeClient{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	go func() {
		<-release
		cancel()
	}()

	done := make(chan struct{})
	var results []Result
	var runErr error
	go func() {
		results, runErr = e.Run(ctx, jobsFor(endpoints(jobs), check))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not return after cancellation — the pool did not shut down")
	}

	if !errors.Is(runErr, context.Canceled) {
		t.Errorf("Run() error = %v, want context.Canceled", runErr)
	}
	if n := int(started.Load()); n >= jobs {
		t.Errorf("%d of %d jobs started — cancellation should have stopped new work", n, jobs)
	}
	if len(results) >= jobs {
		t.Errorf("got %d results, want fewer than the %d jobs submitted", len(results), jobs)
	}
	// Whatever did run must still be reported rather than thrown away.
	if len(results) == 0 {
		t.Error("got 0 results, want the jobs that already ran to be returned")
	}
}

func TestRun_InFlightJobFinishesBeforeShutdown(t *testing.T) {
	// "Graceful" means a worker is never abandoned mid-job: the job it holds
	// runs to completion and its result comes back with the rest.
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var completed atomic.Int32
	entered := make(chan struct{})
	var once sync.Once

	check := &stubCheck{
		meta: model.CheckMetadata{Name: "finisher", Kind: model.KindPassive},
		run: func(ctx context.Context, t model.Target, c ports.HTTPClient) ([]model.Finding, error) {
			once.Do(func() { close(entered) })
			// Deliberately ignores ctx: the worker must still wait for it.
			time.Sleep(50 * time.Millisecond)
			completed.Add(1)
			return []model.Finding{{ID: "f-" + t.Endpoint.Path, CheckName: "finisher"}}, nil
		},
	}

	e, err := New(Config{BaseURL: testBaseURL, MaxConcurrency: 1, RequestsPerSecond: 1000}, &fakeClient{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	go func() {
		<-entered
		cancel()
	}()

	results, runErr := e.Run(ctx, jobsFor(endpoints(50), check))

	if !errors.Is(runErr, context.Canceled) {
		t.Errorf("Run() error = %v, want context.Canceled", runErr)
	}
	if completed.Load() == 0 {
		t.Fatal("the in-flight job did not complete — the worker was abandoned")
	}
	if len(results) != int(completed.Load()) {
		t.Errorf("got %d results for %d completed jobs — a finished job's result was dropped",
			len(results), completed.Load())
	}
	for _, r := range results {
		if len(r.Findings) != 1 {
			t.Errorf("result for %s has %d findings, want 1", r.Endpoint.Path, len(r.Findings))
		}
	}
}

func TestRun_TimeoutStopsThePool(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	check := &stubCheck{
		meta: model.CheckMetadata{Name: "slow", Kind: model.KindActive},
		run: func(ctx context.Context, t model.Target, c ports.HTTPClient) ([]model.Finding, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(20 * time.Millisecond):
				return nil, nil
			}
		},
	}

	start := time.Now()
	e, err := New(Config{BaseURL: testBaseURL, MaxConcurrency: 2, RequestsPerSecond: 1000}, &fakeClient{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, runErr := e.Run(ctx, jobsFor(endpoints(500), check))

	if !errors.Is(runErr, context.DeadlineExceeded) {
		t.Errorf("Run() error = %v, want context.DeadlineExceeded", runErr)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Run() took %v after a 100ms deadline — shutdown is not prompt", elapsed)
	}
}

func TestRun_CancelledBeforeStartRunsNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	var started atomic.Int32
	check := &stubCheck{
		meta: model.CheckMetadata{Name: "never", Kind: model.KindActive},
		run: func(ctx context.Context, t model.Target, c ports.HTTPClient) ([]model.Finding, error) {
			started.Add(1)
			return nil, nil
		},
	}

	e, err := New(Config{BaseURL: testBaseURL, MaxConcurrency: 4, RequestsPerSecond: 1000}, &fakeClient{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	results, runErr := e.Run(ctx, jobsFor(endpoints(10), check))

	if !errors.Is(runErr, context.Canceled) {
		t.Errorf("Run() error = %v, want context.Canceled", runErr)
	}
	if n := started.Load(); n != 0 {
		t.Errorf("%d jobs started, want 0 for an already-cancelled context", n)
	}
	if len(results) != 0 {
		t.Errorf("got %d results, want 0", len(results))
	}
}

func TestRun_LeavesNoGoroutinesBehind(t *testing.T) {
	e, err := New(Config{BaseURL: testBaseURL, MaxConcurrency: 8, RequestsPerSecond: 10000}, &fakeClient{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	settle := func() int {
		for range 20 {
			runtime.Gosched()
			time.Sleep(10 * time.Millisecond)
		}
		return runtime.NumGoroutine()
	}

	before := settle()

	ctx, cancel := context.WithCancel(t.Context())
	if _, err := e.Run(t.Context(), jobsFor(endpoints(50), oneRequestCheck("quick"))); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	// And again, this time cancelled part-way.
	go func() {
		time.Sleep(5 * time.Millisecond)
		cancel()
	}()
	e.Run(ctx, jobsFor(endpoints(200), oneRequestCheck("quick")))

	if after := settle(); after > before+2 {
		t.Errorf("goroutines went from %d to %d — the pool leaked workers", before, after)
	}
}

// ---------------------------------------------------------------- pool bounds

func TestRun_NeverExceedsMaxConcurrency(t *testing.T) {
	const maxConcurrency = 3

	var inFlight, peak atomic.Int32
	check := &stubCheck{
		meta: model.CheckMetadata{Name: "counter", Kind: model.KindActive},
		run: func(ctx context.Context, t model.Target, c ports.HTTPClient) ([]model.Finding, error) {
			n := inFlight.Add(1)
			for {
				old := peak.Load()
				if n <= old || peak.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
			inFlight.Add(-1)
			return nil, nil
		},
	}

	e, err := New(Config{BaseURL: testBaseURL, MaxConcurrency: maxConcurrency, RequestsPerSecond: 100000}, &fakeClient{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if _, err := e.Run(t.Context(), jobsFor(endpoints(60), check)); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if got := peak.Load(); got > maxConcurrency {
		t.Errorf("peak concurrency = %d, want at most %d", got, maxConcurrency)
	}
	if got := peak.Load(); got < 2 {
		t.Errorf("peak concurrency = %d — the pool does not appear to run jobs in parallel at all", got)
	}
}

func TestRun_MoreWorkersThanJobsIsHarmless(t *testing.T) {
	client := &fakeClient{}
	e, err := New(Config{BaseURL: testBaseURL, MaxConcurrency: 32, RequestsPerSecond: 10000}, client)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	results, err := e.Run(t.Context(), jobsFor(endpoints(3), oneRequestCheck("few")))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(results) != 3 {
		t.Errorf("got %d results, want 3", len(results))
	}
}

func TestRun_NoJobs(t *testing.T) {
	e, err := New(Config{BaseURL: testBaseURL, MaxConcurrency: 4, RequestsPerSecond: 10}, &fakeClient{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	results, err := e.Run(t.Context(), nil)
	if err != nil {
		t.Errorf("Run() error = %v, want nil", err)
	}
	if len(results) != 0 {
		t.Errorf("got %d results, want 0", len(results))
	}
}

// ---------------------------------------------------------------- results

func TestRun_ResultOrderIsDeterministic(t *testing.T) {
	// Workers finish in arbitrary order; the output must not.
	eps := []model.Endpoint{
		{Method: "GET", Path: "/c"},
		{Method: "POST", Path: "/a"},
		{Method: "GET", Path: "/a"},
		{Method: "GET", Path: "/b"},
	}
	// Deliberately out of name order, to prove BuildJobs imposes one.
	checks := []model.Check{oneRequestCheck("zeta"), oneRequestCheck("alpha")}

	e := newEngine(t, false)
	jobs := e.BuildJobs(targetsFor(eps), checks)

	// Endpoints keep the order they were discovered in; checks are paired
	// alphabetically within each endpoint.
	want := []string{
		"GET /c alpha", "GET /c zeta",
		"POST /a alpha", "POST /a zeta",
		"GET /a alpha", "GET /a zeta",
		"GET /b alpha", "GET /b zeta",
	}

	var first []string
	for run := range 15 {
		results, err := e.Run(t.Context(), jobs)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}

		got := make([]string, len(results))
		for i, r := range results {
			got[i] = r.Endpoint.Method + " " + r.Endpoint.Path + " " + r.CheckName
		}

		if run == 0 {
			first = got
			if strings.Join(got, "|") != strings.Join(want, "|") {
				t.Fatalf("order = %v, want %v", got, want)
			}
			continue
		}
		// Workers finish in arbitrary order; the output must not.
		if strings.Join(got, "|") != strings.Join(first, "|") {
			t.Fatalf("run %d order = %v, differs from first run %v", run, got, first)
		}
	}
}

func TestRun_CheckErrorIsReportedNotFatal(t *testing.T) {
	boom := errors.New("check exploded")
	failing := &stubCheck{
		meta: model.CheckMetadata{Name: "failing", Kind: model.KindActive},
		run: func(ctx context.Context, t model.Target, c ports.HTTPClient) ([]model.Finding, error) {
			if t.Endpoint.Path == "/r01" {
				return nil, boom
			}
			return []model.Finding{{ID: "ok"}}, nil
		},
	}

	e, err := New(Config{BaseURL: testBaseURL, MaxConcurrency: 4, RequestsPerSecond: 10000}, &fakeClient{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	results, err := e.Run(t.Context(), jobsFor(endpoints(4), failing))
	if err != nil {
		t.Fatalf("Run() error = %v, want nil — one check failing must not fail the run", err)
	}
	if len(results) != 4 {
		t.Fatalf("got %d results, want 4", len(results))
	}

	var failed, ok int
	for _, r := range results {
		if r.Err != nil {
			failed++
			if !errors.Is(r.Err, boom) {
				t.Errorf("Err = %v, want it to wrap the check's error", r.Err)
			}
			if !strings.Contains(r.Err.Error(), "failing") {
				t.Errorf("Err = %q, want it to name the check", r.Err)
			}
			continue
		}
		ok++
	}
	if failed != 1 || ok != 3 {
		t.Errorf("got %d failed / %d ok, want 1 / 3", failed, ok)
	}
}

func TestRun_PanickingCheckBecomesAnError(t *testing.T) {
	panicky := &stubCheck{
		meta: model.CheckMetadata{Name: "panicky", Kind: model.KindActive},
		run: func(ctx context.Context, t model.Target, c ports.HTTPClient) ([]model.Finding, error) {
			if t.Endpoint.Path == "/r00" {
				panic("nil map write or similar")
			}
			return []model.Finding{{ID: "ok"}}, nil
		},
	}

	e, err := New(Config{BaseURL: testBaseURL, MaxConcurrency: 2, RequestsPerSecond: 10000}, &fakeClient{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	results, err := e.Run(t.Context(), jobsFor(endpoints(3), panicky))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3 — a panicking check must not lose the whole scan", len(results))
	}

	var panicked int
	for _, r := range results {
		if r.Err != nil && strings.Contains(r.Err.Error(), "panicked") {
			panicked++
			if len(r.Findings) != 0 {
				t.Errorf("panicked result carries %d findings, want 0", len(r.Findings))
			}
		}
	}
	if panicked != 1 {
		t.Errorf("got %d panic results, want 1", panicked)
	}
}

func TestRun_FindingsAreReturned(t *testing.T) {
	check := &stubCheck{
		meta: model.CheckMetadata{Name: "finder", Kind: model.KindPassive},
		run: func(ctx context.Context, t model.Target, c ports.HTTPClient) ([]model.Finding, error) {
			return []model.Finding{
				{ID: "f-" + t.Endpoint.Path, CheckName: "finder", Severity: "low"},
			}, nil
		},
	}

	e, err := New(Config{BaseURL: testBaseURL, MaxConcurrency: 4, RequestsPerSecond: 10000}, &fakeClient{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	results, err := e.Run(t.Context(), jobsFor(endpoints(5), check))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	total := 0
	for _, r := range results {
		total += len(r.Findings)
	}
	if total != 5 {
		t.Errorf("collected %d findings, want 5", total)
	}
}

// A passive check that makes no request must not consume rate budget: the
// limiter gates requests, not jobs.
func TestRun_PassiveChecksSpendNoRateBudget(t *testing.T) {
	client := &fakeClient{}
	passive := &stubCheck{
		meta: model.CheckMetadata{Name: "passive", Kind: model.KindPassive},
		run: func(ctx context.Context, t model.Target, c ports.HTTPClient) ([]model.Finding, error) {
			return nil, nil
		},
	}

	// 1 req/s would make even two requests take a second.
	e, err := New(Config{BaseURL: testBaseURL, MaxConcurrency: 4, RequestsPerSecond: 1, Burst: 1}, client)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	start := time.Now()
	results, err := e.Run(t.Context(), jobsFor(endpoints(20), passive))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if total := time.Since(start); total > 500*time.Millisecond {
		t.Errorf("20 passive jobs took %v at 1 req/s — they are being charged for requests they never made", total)
	}
	if len(results) != 20 {
		t.Errorf("got %d results, want 20", len(results))
	}
	if got := client.count(); got != 0 {
		t.Errorf("client saw %d requests, want 0", got)
	}
}

// ---------------------------------------------------------------- construction

func TestNew_RejectsInvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		cfg    Config
		client ports.HTTPClient
	}{
		{"empty base URL", Config{MaxConcurrency: 1, RequestsPerSecond: 10}, &fakeClient{}},
		{"zero concurrency", Config{BaseURL: testBaseURL, MaxConcurrency: 0, RequestsPerSecond: 10}, &fakeClient{}},
		{"negative concurrency", Config{BaseURL: testBaseURL, MaxConcurrency: -1, RequestsPerSecond: 10}, &fakeClient{}},
		{"zero rate", Config{BaseURL: testBaseURL, MaxConcurrency: 1, RequestsPerSecond: 0}, &fakeClient{}},
		{"negative rate", Config{BaseURL: testBaseURL, MaxConcurrency: 1, RequestsPerSecond: -5}, &fakeClient{}},
		{"nil client", Config{BaseURL: testBaseURL, MaxConcurrency: 1, RequestsPerSecond: 10}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.cfg, tt.client); err == nil {
				t.Error("New() error = nil, want an error")
			}
		})
	}
}

func TestNew_DefaultsBurstToOne(t *testing.T) {
	e, err := New(Config{BaseURL: testBaseURL, MaxConcurrency: 1, RequestsPerSecond: 10}, &fakeClient{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if got := e.cfg.Burst; got != 1 {
		t.Errorf("Burst = %d, want 1", got)
	}
}

// ---------------------------------------------------------------- BuildJobs

func TestBuildJobs_SkipsDestructiveByDefault(t *testing.T) {
	eps := []model.Endpoint{
		{Method: "GET", Path: "/items"},
		{Method: "DELETE", Path: "/items/{id}", Destructive: true},
		{Method: "PUT", Path: "/items/{id}", Destructive: true},
	}
	checks := []model.Check{oneRequestCheck("c1")}

	jobs := newEngine(t, false).BuildJobs(targetsFor(eps), checks)
	if len(jobs) != 1 {
		t.Fatalf("got %d jobs, want 1 — destructive endpoints must be skipped without opt-in", len(jobs))
	}
	if jobs[0].Target.Endpoint.Method != "GET" {
		t.Errorf("job endpoint = %s, want the non-destructive GET", jobs[0].Target.Endpoint.Method)
	}
}

func TestBuildJobs_IncludesDestructiveWhenOptedIn(t *testing.T) {
	eps := []model.Endpoint{
		{Method: "GET", Path: "/items"},
		{Method: "DELETE", Path: "/items/{id}", Destructive: true},
	}
	checks := []model.Check{oneRequestCheck("c1")}

	if got := len(newEngine(t, true).BuildJobs(targetsFor(eps), checks)); got != 2 {
		t.Errorf("got %d jobs, want 2 with test_destructive enabled", got)
	}
}

func TestBuildJobs_HonoursAppliesTo(t *testing.T) {
	onlyPost := &stubCheck{
		meta: model.CheckMetadata{
			Name:      "post-only",
			AppliesTo: func(ep model.Endpoint) bool { return ep.Method == "POST" },
		},
		run: func(context.Context, model.Target, ports.HTTPClient) ([]model.Finding, error) {
			return nil, nil
		},
	}
	everything := oneRequestCheck("all")

	eps := []model.Endpoint{
		{Method: "GET", Path: "/a"},
		{Method: "POST", Path: "/a"},
	}

	jobs := newEngine(t, false).BuildJobs(targetsFor(eps), []model.Check{onlyPost, everything})

	// GET gets only "all"; POST gets both.
	if len(jobs) != 3 {
		t.Fatalf("got %d jobs, want 3", len(jobs))
	}
	for _, j := range jobs {
		if j.Check.Metadata().Name == "post-only" && j.Target.Endpoint.Method != "POST" {
			t.Errorf("post-only check paired with %s", j.Target.Endpoint.Method)
		}
	}
}

func TestBuildJobs_OrderIsDeterministic(t *testing.T) {
	eps := endpoints(3)
	// Deliberately out of name order.
	checks := []model.Check{oneRequestCheck("zulu"), oneRequestCheck("alpha"), oneRequestCheck("mike")}

	e := newEngine(t, false)
	want := e.BuildJobs(targetsFor(eps), checks)
	for run := range 10 {
		got := e.BuildJobs(targetsFor(eps), checks)
		if len(got) != len(want) {
			t.Fatalf("run %d: got %d jobs, want %d", run, len(got), len(want))
		}
		for i := range got {
			if got[i].Check.Metadata().Name != want[i].Check.Metadata().Name ||
				got[i].Target.Endpoint.Path != want[i].Target.Endpoint.Path {
				t.Fatalf("run %d differs at index %d", run, i)
			}
		}
	}

	// Checks are paired in name order regardless of input order.
	for i, name := range []string{"alpha", "mike", "zulu"} {
		if got := want[i].Check.Metadata().Name; got != name {
			t.Errorf("job %d check = %q, want %q", i, got, name)
		}
	}
}

func TestBuildJobs_DoesNotMutateCallerSlice(t *testing.T) {
	checks := []model.Check{oneRequestCheck("zulu"), oneRequestCheck("alpha")}

	newEngine(t, false).BuildJobs(targetsFor(endpoints(1)), checks)

	if got := checks[0].Metadata().Name; got != "zulu" {
		t.Errorf("caller's slice was reordered: checks[0] = %q, want zulu", got)
	}
}

func TestBuildJobs_EmptyInputs(t *testing.T) {
	if got := newEngine(t, false).BuildJobs(nil, []model.Check{oneRequestCheck("c")}); len(got) != 0 {
		t.Errorf("got %d jobs for no endpoints, want 0", len(got))
	}
	if got := newEngine(t, false).BuildJobs(targetsFor(endpoints(3)), nil); len(got) != 0 {
		t.Errorf("got %d jobs for no checks, want 0", len(got))
	}
}

// ---------------------------------------------------------- rate-limited client

func TestRateLimitedClient_PropagatesInnerError(t *testing.T) {
	boom := errors.New("transport failed")
	c := newRateLimitedClient(&fakeClient{err: boom}, 1000, 1)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://lab.invalid/x", nil)
	if _, err := c.Do(req); !errors.Is(err, boom) {
		t.Errorf("Do() error = %v, want it to wrap the inner error", err)
	}
}

func TestRateLimitedClient_CancelledContextAbortsTheWait(t *testing.T) {
	// 1 req/s with burst 1: the second request must wait ~1s, and a
	// cancelled context has to cut that short instead of pinning a worker.
	inner := &fakeClient{}
	c := newRateLimitedClient(inner, 1, 1)

	first, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://lab.invalid/x", nil)
	if _, err := c.Do(first); err != nil {
		t.Fatalf("first Do() error = %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	second, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://lab.invalid/x", nil)
	start := time.Now()
	_, err := c.Do(second)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("Do() error = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("Do() blocked for %v after cancellation, want it to return promptly", elapsed)
	}
	if got := inner.count(); got != 1 {
		t.Errorf("inner client saw %d requests, want 1 — the cancelled one must not be sent", got)
	}
}

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

	targets := e.Collect(t.Context(), eps)

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

	e.Collect(t.Context(), []model.Endpoint{
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

	targets := e.Collect(t.Context(), []model.Endpoint{
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

	targets := e.Collect(t.Context(), []model.Endpoint{
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

	targets := e.Collect(t.Context(), endpoints(3))

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
		targets := e.Collect(t.Context(), eps)
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

	targets := e.Collect(ctx, endpoints(20))

	if len(targets) != 0 {
		t.Errorf("got %d targets, want 0 for an already-cancelled context", len(targets))
	}
	if got := len(client.seen()); got != 0 {
		t.Errorf("client saw %d requests, want 0", got)
	}
}

func TestCollect_NoEndpoints(t *testing.T) {
	e := newCollectEngine(t, &recordingClient{}, false)
	if got := e.Collect(t.Context(), nil); len(got) != 0 {
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

	targets := e.Collect(t.Context(), endpoints(1))
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

	targets := e.Collect(t.Context(), endpoints(1))
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
	targets := e.Collect(t.Context(), eps)

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

	targets := e.Collect(t.Context(), endpoints(1))
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

	targets := e.Collect(t.Context(), endpoints(1))

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

func TestCollect_UnbuildableRequestBecomesBaselineErr(t *testing.T) {
	client := &recordingClient{}
	// A method with a space in it is not a valid HTTP method, so building
	// the request fails before anything is sent.
	e, err := New(Config{
		BaseURL:           testBaseURL,
		MaxConcurrency:    2,
		RequestsPerSecond: 100000,
	}, client)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	targets := e.Collect(t.Context(), []model.Endpoint{{Method: "BAD METHOD", Path: "/x"}})

	if len(targets) != 1 {
		t.Fatalf("got %d targets, want 1", len(targets))
	}
	if targets[0].BaselineErr == nil {
		t.Error("BaselineErr = nil, want an error for an unbuildable request")
	}
	if got := len(client.seen()); got != 0 {
		t.Errorf("client saw %d requests, want 0 — nothing should be sent", got)
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

	targets := e.Collect(t.Context(), endpoints(1))

	if len(targets) != 1 {
		t.Fatalf("got %d targets, want 1", len(targets))
	}
	if targets[0].BaselineErr == nil {
		t.Error("BaselineErr = nil, want an error for a base URL that cannot be joined")
	}
}
