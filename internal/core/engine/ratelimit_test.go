package engine

import (
	"net/http"
	"testing"
	"time"
)

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

func TestNewRateLimitedClient_PacesRequests(t *testing.T) {
	client := &fakeClient{}
	rl := NewRateLimitedClient(client, 20, 1)

	start := time.Now()
	for range 3 {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://lab.invalid/x", nil)
		if _, err := rl.Do(req); err != nil {
			t.Fatalf("Do() error = %v", err)
		}
	}
	// 3 requests at 20/s with burst 1: at least ~2/20s of waiting.
	if elapsed := time.Since(start); elapsed < 80*time.Millisecond {
		t.Errorf("3 requests at 20 req/s took %v, want it paced", elapsed)
	}
	if got := client.count(); got != 3 {
		t.Errorf("client saw %d requests, want 3", got)
	}
}

func TestNewRateLimitedClient_DefaultsBurstToOne(t *testing.T) {
	// Burst 0 must not panic or produce an unlimited limiter; it should
	// behave the same as New's own default of 1.
	client := &fakeClient{}
	rl := NewRateLimitedClient(client, 1000, 0)

	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://lab.invalid/x", nil)
	if _, err := rl.Do(req); err != nil {
		t.Fatalf("Do() error = %v", err)
	}
}
