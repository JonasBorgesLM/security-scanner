// Package engine orchestrates check execution: a bounded worker pool draws
// jobs from a channel, every outbound request passes through a shared rate
// limiter, and the whole run is bounded by a context so a global timeout or
// Ctrl+C stops it cleanly.
//
// Being gentle to the target is a design goal, not a nicety — the lab being
// scanned is the operator's own, and a scanner that self-DoSes it is
// useless. The pool bounds how much work happens at once; the rate limiter
// bounds how fast requests actually leave.
package engine

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"

	"golang.org/x/time/rate"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
	"github.com/JonasBorgesLM/security-scanner/internal/ports"
)

// Config mirrors the engine: section of config.yaml.
type Config struct {
	// MaxConcurrency is the worker pool size: how many checks may be in
	// flight at once. Must be greater than zero.
	MaxConcurrency int
	// RequestsPerSecond caps the sustained outbound request rate across all
	// workers combined. Must be greater than zero.
	RequestsPerSecond float64
	// Burst is how many requests may be spent at once before the sustained
	// rate applies. Defaults to 1, i.e. strictly paced.
	Burst int
	// TestDestructive opts in to running checks against DELETE/PUT/PATCH
	// endpoints. Off by default; see BuildJobs.
	TestDestructive bool
}

// Job is one check to run against one endpoint — the unit the worker pool
// consumes.
type Job struct {
	Endpoint model.Endpoint
	Check    model.Check
}

// Result is the outcome of a single Job. Err being non-nil means the check
// could not complete; it is never itself evidence of a vulnerability.
type Result struct {
	Endpoint  model.Endpoint
	CheckName string
	Findings  []model.Finding
	Err       error
}

// Engine runs Jobs through a bounded, rate-limited worker pool.
type Engine struct {
	cfg    Config
	client ports.HTTPClient
}

// New builds an Engine.
//
// client must be the ScopeGuard-enforcing client (see
// internal/adapters/httpclient), normally already wrapped by the
// Authenticator. New wraps it once more in the rate limiter and hands that
// wrapper to every check, so no check can outrun the configured rate even
// by accident — a check cannot reach the network any other way.
//
// One consequence worth knowing: the Authenticator sits below the limiter,
// so its login and re-auth requests are not themselves rate limited. That
// is deliberate — logins are rare and already collapsed into a single
// in-flight attempt by the Authenticator — but it does mean the ceiling is
// requests_per_second plus the occasional login.
func New(cfg Config, client ports.HTTPClient) (*Engine, error) {
	if cfg.MaxConcurrency <= 0 {
		return nil, fmt.Errorf("engine: MaxConcurrency must be greater than 0, got %d", cfg.MaxConcurrency)
	}
	if cfg.RequestsPerSecond <= 0 {
		return nil, fmt.Errorf("engine: RequestsPerSecond must be greater than 0, got %v", cfg.RequestsPerSecond)
	}
	if client == nil {
		return nil, errors.New("engine: client must not be nil")
	}
	if cfg.Burst < 1 {
		cfg.Burst = 1
	}

	return &Engine{
		cfg:    cfg,
		client: newRateLimitedClient(client, cfg.RequestsPerSecond, cfg.Burst),
	}, nil
}

// Run executes every job across the worker pool and returns the results in
// a deterministic order, regardless of which worker finished first.
//
// Cancelling ctx shuts the pool down gracefully: no further job is handed
// out, workers finish what they are holding and exit, and the results
// gathered so far are still returned alongside ctx.Err(). Checks receive
// ctx too, so an in-flight HTTP request unwinds instead of pinning
// shutdown behind a hung connection.
func (e *Engine) Run(ctx context.Context, jobs []Job) ([]Result, error) {
	if len(jobs) == 0 {
		return nil, ctx.Err()
	}

	workers := min(e.cfg.MaxConcurrency, len(jobs))

	// jobCh is unbuffered so a cancelled run cannot leave work queued that
	// a worker would still pick up. resCh is buffered for every job, so a
	// worker never blocks publishing a result and can always exit.
	jobCh := make(chan Job)
	resCh := make(chan Result, len(jobs))

	// runJob recovers panics itself, so nothing here can escape into
	// WaitGroup.Go, which requires its function not to panic.
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for job := range jobCh {
				resCh <- e.runJob(ctx, job)
			}
		})
	}

feed:
	for _, job := range jobs {
		// Checked before the select so that, once cancelled, no further job
		// is dispatched — select alone would pick a ready send branch at
		// random even with ctx.Done() also ready.
		if ctx.Err() != nil {
			break
		}
		select {
		case jobCh <- job:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobCh)

	wg.Wait()
	close(resCh)

	results := make([]Result, 0, len(jobs))
	for r := range resCh {
		results = append(results, r)
	}
	sortResults(results)

	return results, ctx.Err()
}

// runJob executes one check, converting a panic into an ordinary error. A
// single misbehaving check must not discard the findings of an entire scan
// that may have been running for minutes; reporting it as a failed Result
// keeps it visible instead of hiding it.
func (e *Engine) runJob(ctx context.Context, job Job) (res Result) {
	name := job.Check.Metadata().Name
	res = Result{Endpoint: job.Endpoint, CheckName: name}

	defer func() {
		if r := recover(); r != nil {
			res.Findings = nil
			res.Err = fmt.Errorf("engine: check %q panicked on %s %s: %v",
				name, job.Endpoint.Method, job.Endpoint.Path, r)
		}
	}()

	findings, err := job.Check.Run(ctx, job.Endpoint, e.client)
	if err != nil {
		res.Err = fmt.Errorf("engine: check %q on %s %s: %w",
			name, job.Endpoint.Method, job.Endpoint.Path, err)
		return res
	}
	res.Findings = findings
	return res
}

// sortResults imposes a stable order on results that completed in
// nondeterministic worker order, so the same scan of the same target
// produces the same file twice.
func sortResults(results []Result) {
	slices.SortStableFunc(results, func(a, b Result) int {
		if c := strings.Compare(a.Endpoint.Path, b.Endpoint.Path); c != 0 {
			return c
		}
		if c := strings.Compare(a.Endpoint.Method, b.Endpoint.Method); c != 0 {
			return c
		}
		return strings.Compare(a.CheckName, b.CheckName)
	})
}

// BuildJobs pairs each endpoint with every check that applies to it.
//
// It is where the non-destructive default is enforced: an endpoint marked
// Destructive (DELETE/PUT/PATCH) produces no jobs at all unless
// testDestructive is set. Checks are paired in name order so the resulting
// job list — and therefore the scan's output — does not depend on the
// order the registry happened to hand them over in.
func BuildJobs(endpoints []model.Endpoint, checks []model.Check, testDestructive bool) []Job {
	ordered := slices.Clone(checks)
	slices.SortStableFunc(ordered, func(a, b model.Check) int {
		return strings.Compare(a.Metadata().Name, b.Metadata().Name)
	})

	var jobs []Job
	for _, ep := range endpoints {
		if ep.Destructive && !testDestructive {
			continue
		}
		for _, c := range ordered {
			applies := c.Metadata().AppliesTo
			if applies != nil && !applies(ep) {
				continue
			}
			jobs = append(jobs, Job{Endpoint: ep, Check: c})
		}
	}
	return jobs
}

// rateLimitedClient paces every outbound request. It is a ports.HTTPClient
// decorator rather than a gate around each job on purpose: a passive check
// that inspects an already-fetched response spends no requests and so must
// spend no rate budget either, while an active check that issues several
// requests is charged for each one.
type rateLimitedClient struct {
	inner   ports.HTTPClient
	limiter *rate.Limiter
}

var _ ports.HTTPClient = (*rateLimitedClient)(nil)

func newRateLimitedClient(inner ports.HTTPClient, requestsPerSecond float64, burst int) *rateLimitedClient {
	return &rateLimitedClient{
		inner:   inner,
		limiter: rate.NewLimiter(rate.Limit(requestsPerSecond), burst),
	}
}

// Do blocks until the rate limiter allows the request, then delegates. A
// cancelled context aborts the wait instead of holding a worker hostage.
func (c *rateLimitedClient) Do(req *http.Request) (*http.Response, error) {
	if err := c.limiter.Wait(req.Context()); err != nil {
		return nil, fmt.Errorf("engine: waiting for rate limiter: %w", err)
	}
	return c.inner.Do(req)
}
