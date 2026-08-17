// Package engine orchestrates check execution: a baseline response is
// collected once per endpoint, a bounded worker pool runs the applicable
// checks against it, every outbound request passes through a shared rate
// limiter, and the whole run is bounded by a context so a global timeout or
// Ctrl+C stops it cleanly.
//
// Being gentle to the target is a design goal, not a nicety — the lab being
// scanned is the operator's own, and a scanner that self-DoSes it is
// useless. The pool bounds how much work happens at once; the rate limiter
// bounds how fast requests actually leave; the shared baseline means N
// checks on one endpoint cost one request, not N.
package engine

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/time/rate"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
	"github.com/JonasBorgesLM/security-scanner/internal/ports"
)

// maxBodyBytes caps how much of any single response is held in memory.
// Baselines are kept for the whole run, so an unbounded read would scale
// with the size of the spec rather than with anything the operator chose.
const maxBodyBytes = 2 << 20 // 2 MiB

// ErrPassiveCheckRequest is returned to a passive check that tries to send
// a request. Passive checks are defined by working from the baseline the
// engine already collected; one that reaches for the network is a bug in
// the check, and failing loudly beats silently spending rate budget.
var ErrPassiveCheckRequest = errors.New("engine: a passive check must not send requests — use Target.Baseline")

// pathParam matches an OpenAPI path template segment such as {id}.
var pathParam = regexp.MustCompile(`\{[^/{}]+\}`)

// safeMethods are the methods RFC 9110 defines as safe: they are not
// expected to change state on the target.
var safeMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
}

// Config mirrors the engine: section of config.yaml, plus the target's base
// URL that baseline collection needs.
type Config struct {
	// BaseURL is the target's base URL; endpoint paths resolve against it.
	BaseURL string
	// MaxConcurrency is the worker pool size. Must be greater than zero.
	MaxConcurrency int
	// RequestsPerSecond caps the sustained outbound request rate across all
	// workers combined. Must be greater than zero.
	RequestsPerSecond float64
	// Burst is how many requests may be spent at once before the sustained
	// rate applies. Defaults to 1, i.e. strictly paced.
	Burst int
	// TestDestructive opts in to touching DELETE/PUT/PATCH endpoints at all,
	// baseline collection included. Off by default.
	TestDestructive bool
}

// Job is one check to run against one target — the unit the worker pool
// consumes.
type Job struct {
	Target model.Target
	Check  model.Check
}

// Result is the outcome of a single Job.
type Result struct {
	Endpoint  model.Endpoint
	CheckName string
	Findings  []model.Finding
	// Skipped means the check declined to conclude — no baseline, failed
	// auth, whatever SkipReason says. It is not a failure and never a
	// finding, but it must reach the report: a route shown as clean when it
	// was never examined is worse than one openly marked unexamined.
	Skipped    bool
	SkipReason string
	// Err means the check could not complete. It is never itself evidence
	// of a vulnerability.
	Err error
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
	if cfg.BaseURL == "" {
		return nil, errors.New("engine: BaseURL must not be empty")
	}
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

// Collect fetches one baseline response per endpoint, in parallel across
// the pool and paced by the rate limiter.
//
// This is the initial collection the rest of the design leans on: passive
// checks read these responses instead of issuing requests of their own, and
// active checks diff against them instead of against hardcoded
// expectations. Doing it once per endpoint rather than once per check keeps
// the request count proportional to the size of the spec rather than to the
// spec times the number of enabled checks.
//
// Collection only ever sends a safe method. An endpoint declared as POST,
// PUT, PATCH or DELETE is probed with GET instead, and the substitution is
// recorded in Response.ProbedMethod. A phase named "collect" must not
// create or destroy anything on the target — the headers and server
// fingerprint that passive checks look at are properties of the route, not
// of the verb used to reach it.
//
// Destructive endpoints are skipped entirely without the opt-in, so they
// cost no request at all.
//
// A failed collection still yields a Target, carrying BaselineErr instead of
// a response. Targets come back in the order their endpoints were given.
// A cancelled context yields the targets gathered so far plus ctx.Err(), so
// a caller cannot mistake a truncated collection for a complete one.
func (e *Engine) Collect(ctx context.Context, endpoints []model.Endpoint) ([]model.Target, error) {
	eligible := make([]model.Endpoint, 0, len(endpoints))
	for _, ep := range endpoints {
		if ep.Destructive && !e.cfg.TestDestructive {
			continue
		}
		eligible = append(eligible, ep)
	}

	targets := runPool(ctx, e.cfg.MaxConcurrency, eligible, e.collectOne)
	if len(targets) < len(eligible) {
		return targets, cmp.Or(ctx.Err(), errIncomplete)
	}
	return targets, nil
}

// errIncomplete is the fallback when work was left undone but the context
// itself reports no error — it should not happen, and saying so beats
// returning nil and implying the run was complete.
var errIncomplete = errors.New("engine: run did not process every item")

func (e *Engine) collectOne(ctx context.Context, ep model.Endpoint) model.Target {
	target := model.Target{Endpoint: ep}

	method := baselineMethod(ep.Method)

	req, err := e.baselineRequest(ctx, ep, method)
	if err != nil {
		target.BaselineErr = err
		return target
	}
	probedURL := req.URL.String()

	resp, err := e.client.Do(req)
	if err != nil {
		target.BaselineErr = fmt.Errorf("engine: baseline %s %s: %w", method, ep.Path, err)
		return target
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		target.BaselineErr = fmt.Errorf("engine: reading baseline %s %s: %w", method, ep.Path, err)
		return target
	}

	target.Baseline = &model.Response{
		URL:        probedURL,
		StatusCode: resp.StatusCode,
		// Cloned so the baseline does not alias the map net/http still
		// holds, and so every check reads a map nothing else can touch.
		Headers:      resp.Header.Clone(),
		Body:         body,
		ProbedMethod: method,
	}
	return target
}

// baselineMethod returns the method to probe an endpoint with: its own when
// that is safe, GET otherwise.
func baselineMethod(method string) string {
	if safeMethods[method] {
		return method
	}
	return http.MethodGet
}

// baselineRequest builds the untouched request for an endpoint. Path
// template parameters are filled with a harmless placeholder: the goal is a
// representative response, and a 404, 405 or 400 is still a perfectly good
// baseline for, say, a missing-security-header check.
func (e *Engine) baselineRequest(ctx context.Context, ep model.Endpoint, method string) (*http.Request, error) {
	target, err := url.JoinPath(e.cfg.BaseURL, pathParam.ReplaceAllString(ep.Path, "1"))
	if err != nil {
		return nil, fmt.Errorf("engine: building baseline URL for %s: %w", ep.Path, err)
	}

	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return nil, fmt.Errorf("engine: building baseline request for %s %s: %w", method, ep.Path, err)
	}
	return req, nil
}

// BuildJobs pairs each target with every check that applies to it.
//
// It re-applies the non-destructive gate rather than trusting the caller to
// have filtered already: skipping destructive endpoints is a safety
// invariant, and one enforced in a single place is one refactor away from
// being enforced nowhere.
//
// Checks are paired in name order so the resulting job list — and therefore
// the scan's output — does not depend on the order the registry happened to
// hand them over in. (Enabled already sorts; the engine does not know that,
// and sorting a handful of checks costs nothing.)
func (e *Engine) BuildJobs(targets []model.Target, checks []model.Check) []Job {
	ordered := slices.Clone(checks)
	slices.SortStableFunc(ordered, func(a, b model.Check) int {
		return strings.Compare(a.Metadata().Name, b.Metadata().Name)
	})

	var jobs []Job
	for _, t := range targets {
		if t.Endpoint.Destructive && !e.cfg.TestDestructive {
			continue
		}
		for _, c := range ordered {
			if !applies(c.Metadata(), t.Endpoint) {
				continue
			}
			jobs = append(jobs, Job{Target: t, Check: c})
		}
	}
	return jobs
}

// applies decides whether a check is meaningful for an endpoint.
func applies(meta model.CheckMetadata, ep model.Endpoint) bool {
	// A check that needs a session (IDOR and friends) has nothing to say
	// about a route that takes no credentials in the first place.
	if meta.RequiresAuth && !ep.RequiresAuth {
		return false
	}
	if meta.AppliesTo != nil && !meta.AppliesTo(ep) {
		return false
	}
	return true
}

// Run executes every job across the worker pool, returning results in job
// order so identical input produces identical output.
//
// Cancelling ctx shuts the pool down gracefully: no further job is handed
// out, workers finish what they are holding and exit, and the results
// gathered so far are still returned alongside ctx.Err(). Checks receive
// ctx too, so an in-flight HTTP request unwinds instead of pinning shutdown
// behind a hung connection.
//
// The error reports incomplete work, not mere cancellation: a run whose
// last job finished before the context was cancelled processed everything
// it was given and returns nil.
func (e *Engine) Run(ctx context.Context, jobs []Job) ([]Result, error) {
	results := runPool(ctx, e.cfg.MaxConcurrency, jobs, e.runJob)
	if len(results) < len(jobs) {
		return results, cmp.Or(ctx.Err(), errIncomplete)
	}
	return results, nil
}

// runJob executes one check and normalises its outcome.
//
// It recovers panics itself, rather than leaning on the pool's guard, so a
// panicking check still produces a Result naming it. The pool's guard is
// the last resort that keeps the process alive; this is the one that keeps
// the failure attributable.
func (e *Engine) runJob(ctx context.Context, job Job) (res Result) {
	meta := job.Check.Metadata()
	ep := job.Target.Endpoint
	res = Result{Endpoint: ep, CheckName: meta.Name}

	defer func() {
		if r := recover(); r != nil {
			res.Findings = nil
			res.Skipped, res.SkipReason = false, ""
			res.Err = fmt.Errorf("engine: check %q panicked on %s %s: %v",
				meta.Name, ep.Method, ep.Path, r)
		}
	}()

	// A passive check is handed a client that refuses every request, so
	// "passive checks don't hit the network" holds by construction rather
	// than by trusting each check to behave.
	client := e.client
	if meta.Kind == model.KindPassive {
		client = deniedClient{checkName: meta.Name}
	}

	findings, err := job.Check.Run(ctx, job.Target, client)
	switch {
	case errors.Is(err, model.ErrSkipped):
		res.Skipped = true
		res.SkipReason = err.Error()
		return res
	case err != nil:
		res.Err = fmt.Errorf("engine: check %q on %s %s: %w",
			meta.Name, ep.Method, ep.Path, err)
		return res
	}

	res.Findings = enrich(findings, meta, ep)
	return res
}

// enrich fills in the parts of a Finding the engine already knows, so that
// every check does not have to repeat metadata it has already declared —
// and cannot forget to. Endpoint in particular is what the attack stage
// needs to reproduce a finding, so leaving it to each check would make one
// omission enough to break the pipeline.
//
// A check may set Finding.ID to distinguish several findings it produced
// for one endpoint; whatever it sets is namespaced rather than trusted to
// be globally unique.
func enrich(findings []model.Finding, meta model.CheckMetadata, ep model.Endpoint) []model.Finding {
	for i := range findings {
		f := &findings[i]
		f.CheckName = meta.Name
		f.Endpoint = ep
		if f.Severity == "" {
			f.Severity = meta.Severity
		}
		if f.OWASPCategory == "" {
			f.OWASPCategory = meta.OWASPCategory
		}
		f.ID = findingID(meta.Name, ep, f.ID, i)
	}
	return findings
}

// findingID builds a stable identifier. It has to survive re-running the
// same scan unchanged, because findings.json is committed and diffed by
// hand — so it is derived only from things that do not vary between runs.
func findingID(checkName string, ep model.Endpoint, discriminator string, index int) string {
	if discriminator == "" {
		discriminator = strconv.Itoa(index)
	}
	return fmt.Sprintf("%s:%s:%s:%s", checkName, ep.Method, ep.Path, discriminator)
}

// runPool spreads items across at most workers goroutines and returns the
// results of those that completed, in input order.
//
// Preserving input order is what makes output deterministic without a sort:
// workers finish in whatever order they finish, but each writes only to its
// own slot. Cancelling ctx stops dispatch; whatever a worker already picked
// up runs to completion and is included, while undispatched items simply do
// not appear.
func runPool[T, R any](ctx context.Context, workers int, items []T, fn func(context.Context, T) R) []R {
	if len(items) == 0 {
		return nil
	}
	workers = min(workers, len(items))

	// Each goroutine writes only its own indices, and wg.Wait establishes
	// the happens-before edge for reading them back below.
	results := make([]R, len(items))
	completed := make([]bool, len(items))

	type indexed struct {
		i    int
		item T
	}
	// Unbuffered, so a cancelled run cannot leave work queued that a worker
	// would still pick up.
	ch := make(chan indexed)

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range ch {
				results[it.i], completed[it.i] = guard(ctx, it.item, fn)
			}
		}()
	}

feed:
	for i, item := range items {
		// Checked before the select so that, once cancelled, no further item
		// is dispatched — select alone would pick a ready send branch at
		// random even with ctx.Done() also ready.
		if ctx.Err() != nil {
			break
		}
		select {
		case ch <- indexed{i: i, item: item}:
		case <-ctx.Done():
			break feed
		}
	}
	close(ch)
	wg.Wait()

	out := make([]R, 0, len(items))
	for i := range items {
		if completed[i] {
			out = append(out, results[i])
		}
	}
	return out
}

// guard runs fn and turns a panic into a dropped item rather than a dead
// process. A single misbehaving check — or a bug in collection — must not
// discard the work of a scan that may have been running for minutes. A
// panic in a bare pool goroutine would otherwise take the whole process
// down, so recovering here is what makes the pool safe.
//
// The item is reported as not-completed, which is exactly how an
// undispatched item is treated: it simply does not appear in the results,
// and Run/Collect report the run as incomplete.
func guard[T, R any](ctx context.Context, item T, fn func(context.Context, T) R) (res R, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			var zero R
			res, ok = zero, false
		}
	}()
	return fn(ctx, item), true
}

// deniedClient is the ports.HTTPClient handed to passive checks.
type deniedClient struct{ checkName string }

var _ ports.HTTPClient = deniedClient{}

func (d deniedClient) Do(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("%w (check %q attempted %s %s)",
		ErrPassiveCheckRequest, d.checkName, req.Method, req.URL)
}

// rateLimitedClient paces every outbound request. It is a ports.HTTPClient
// decorator rather than a gate around each job on purpose: the thing being
// limited is a request, and one job may issue none or several.
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

// NewRateLimitedClient wraps inner with the same pacing New applies
// internally, exported for pipeline stages that need "gentle by design"
// without needing a full Engine — the attack command, which walks a
// findings list sequentially rather than through a worker pool, is exactly
// that case. Burst below 1 is treated as 1, matching New.
func NewRateLimitedClient(inner ports.HTTPClient, requestsPerSecond float64, burst int) ports.HTTPClient {
	if burst < 1 {
		burst = 1
	}
	return newRateLimitedClient(inner, requestsPerSecond, burst)
}

// Do blocks until the rate limiter allows the request, then delegates. A
// cancelled context aborts the wait instead of holding a worker hostage.
func (c *rateLimitedClient) Do(req *http.Request) (*http.Response, error) {
	if err := c.limiter.Wait(req.Context()); err != nil {
		return nil, fmt.Errorf("engine: waiting for rate limiter: %w", err)
	}
	return c.inner.Do(req)
}
