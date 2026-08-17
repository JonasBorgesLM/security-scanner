package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
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
