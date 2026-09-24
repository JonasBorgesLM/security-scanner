package engine

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/warden/internal/core/model"
)

// ------------------------------------------------------------------ skipping

func TestRun_SkippedCheckIsNeitherFindingNorFailure(t *testing.T) {
	skipper := &stubCheck{
		meta: model.CheckMetadata{Name: "cautious", Kind: model.KindPassive},
		run: func(ctx context.Context, target model.Target, c model.Clients) ([]model.Finding, error) {
			return nil, model.Skippedf("no baseline for %s", target.Endpoint.Path)
		},
	}

	e := newEngine(t, false)
	results, err := e.Run(t.Context(), e.BuildJobs(targetsFor(endpoints(2)), []model.Check{skipper}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}

	for _, r := range results {
		if !r.Skipped {
			t.Errorf("%s: Skipped = false, want true", r.Endpoint.Path)
		}
		if r.Err != nil {
			t.Errorf("%s: Err = %v, want nil — a skip is not a failure", r.Endpoint.Path, r.Err)
		}
		if len(r.Findings) != 0 {
			t.Errorf("%s: got %d findings, want 0 — this check returned none, and a skip must never invent one", r.Endpoint.Path, len(r.Findings))
		}
		if !strings.Contains(r.SkipReason, "no baseline") {
			t.Errorf("%s: SkipReason = %q, want the check's explanation", r.Endpoint.Path, r.SkipReason)
		}
	}
}

func TestRun_OrdinaryErrorIsNotASkip(t *testing.T) {
	failing := &stubCheck{
		meta: model.CheckMetadata{Name: "broken", Kind: model.KindPassive},
		run: func(context.Context, model.Target, model.Clients) ([]model.Finding, error) {
			return nil, errors.New("something went wrong")
		},
	}

	e := newEngine(t, false)
	results, err := e.Run(t.Context(), e.BuildJobs(targetsFor(endpoints(1)), []model.Check{failing}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if results[0].Skipped {
		t.Error("Skipped = true for a plain error — only ErrSkipped means skipped")
	}
	if results[0].Err == nil {
		t.Error("Err = nil, want the check's failure")
	}
}

// ----------------------------------------------------------------- enrichment

func enrichingCheck(name string, n int) *stubCheck {
	return &stubCheck{
		meta: model.CheckMetadata{
			Name:          name,
			Kind:          model.KindPassive,
			Severity:      "high",
			OWASPCategory: "A05:2021-Security Misconfiguration",
		},
		run: func(ctx context.Context, target model.Target, c model.Clients) ([]model.Finding, error) {
			out := make([]model.Finding, n)
			return out, nil
		},
	}
}

func TestRun_EngineStampsFindingsFromMetadata(t *testing.T) {
	ep := model.Endpoint{Method: "GET", Path: "/items", RequiresAuth: true}

	e := newEngine(t, false)
	results, err := e.Run(t.Context(), e.BuildJobs(
		[]model.Target{{Endpoint: ep}},
		[]model.Check{enrichingCheck("stamped", 1)},
	))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	f := results[0].Findings[0]
	if f.CheckName != "stamped" {
		t.Errorf("CheckName = %q, want stamped", f.CheckName)
	}
	if f.Severity != "high" {
		t.Errorf("Severity = %q, want high — taken from the check's metadata", f.Severity)
	}
	if f.OWASPCategory == "" {
		t.Error("OWASPCategory is empty, want it copied from the metadata")
	}
	// Endpoint is what the attack stage needs to reproduce the finding;
	// leaving it to each check would make one omission break the pipeline.
	if f.Endpoint.Path != "/items" || f.Endpoint.Method != "GET" {
		t.Errorf("Endpoint = %+v, want the endpoint the check ran against", f.Endpoint)
	}
	if !f.Endpoint.RequiresAuth {
		t.Error("Endpoint.RequiresAuth was not carried over")
	}
}

func TestRun_CheckMaySetItsOwnSeverity(t *testing.T) {
	override := &stubCheck{
		meta: model.CheckMetadata{Name: "graded", Kind: model.KindPassive, Severity: "low"},
		run: func(context.Context, model.Target, model.Clients) ([]model.Finding, error) {
			return []model.Finding{{Severity: "critical"}, {}}, nil
		},
	}

	e := newEngine(t, false)
	results, err := e.Run(t.Context(), e.BuildJobs(targetsFor(endpoints(1)), []model.Check{override}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if got := results[0].Findings[0].Severity; got != "critical" {
		t.Errorf("Severity = %q, want the check's own value to win", got)
	}
	if got := results[0].Findings[1].Severity; got != "low" {
		t.Errorf("Severity = %q, want the metadata default when the check sets none", got)
	}
}

func TestRun_FindingIDsAreUniqueAndDeterministic(t *testing.T) {
	e := newEngine(t, false)
	jobs := e.BuildJobs(targetsFor(endpoints(3)), []model.Check{enrichingCheck("multi", 2)})

	var first []string
	for run := range 10 {
		results, err := e.Run(t.Context(), jobs)
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}

		var ids []string
		for _, r := range results {
			for _, f := range r.Findings {
				ids = append(ids, f.ID)
			}
		}

		seen := map[string]bool{}
		for _, id := range ids {
			if seen[id] {
				t.Fatalf("duplicate finding ID %q — IDs must identify a finding uniquely", id)
			}
			seen[id] = true
			if id == "" {
				t.Fatal("empty finding ID")
			}
		}

		if run == 0 {
			first = ids
			continue
		}
		if strings.Join(ids, "|") != strings.Join(first, "|") {
			t.Fatalf("run %d IDs = %v, differ from first run %v — findings.json would churn between identical scans", run, ids, first)
		}
	}
}

func TestFindingID_UsesTheChecksDiscriminatorWhenGiven(t *testing.T) {
	ep := model.Endpoint{Method: "GET", Path: "/items"}

	withName := findingID("missing-headers", ep, "Content-Security-Policy", 0)
	if !strings.Contains(withName, "Content-Security-Policy") {
		t.Errorf("ID = %q, want the check's discriminator preserved", withName)
	}
	if !strings.Contains(withName, "missing-headers") || !strings.Contains(withName, "/items") {
		t.Errorf("ID = %q, want it namespaced by check and endpoint", withName)
	}

	// Two checks producing the same discriminator on the same endpoint must
	// still not collide.
	other := findingID("other-check", ep, "Content-Security-Policy", 0)
	if withName == other {
		t.Error("IDs from different checks collided")
	}
}

// ------------------------------------------------------------ RequiresAuth

func TestBuildJobs_SkipsAuthOnlyChecksOnPublicEndpoints(t *testing.T) {
	authOnly := &stubCheck{
		meta: model.CheckMetadata{Name: "idor-ish", Kind: model.KindActive, RequiresAuth: true},
		run: func(context.Context, model.Target, model.Clients) ([]model.Finding, error) {
			return nil, nil
		},
	}
	anyRoute := oneRequestCheck("anywhere")

	targets := []model.Target{
		{Endpoint: model.Endpoint{Method: "GET", Path: "/public"}},
		{Endpoint: model.Endpoint{Method: "GET", Path: "/private", RequiresAuth: true}},
	}

	jobs := newEngine(t, false).BuildJobs(targets, []model.Check{authOnly, anyRoute})

	// /public gets only the unrestricted check; /private gets both.
	if len(jobs) != 3 {
		t.Fatalf("got %d jobs, want 3", len(jobs))
	}
	for _, j := range jobs {
		if j.Check.Metadata().RequiresAuth && !j.Target.Endpoint.RequiresAuth {
			t.Errorf("auth-only check paired with public endpoint %s", j.Target.Endpoint.Path)
		}
	}
}

// ------------------------------------------------------------- pool guard

// panickingCollector blows up on the second endpoint.
type panickingCollector struct{}

func (c *panickingCollector) Do(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Path, "/r01") {
		panic("collector exploded")
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       http.NoBody,
		Request:    req,
	}, nil
}

// A panic outside a check — in collection, say — must not kill the process.
// The pool's guard drops the item and the phase reports itself incomplete.
func TestCollect_PanicDoesNotKillTheRun(t *testing.T) {
	e := newCollectEngine(t, &panickingCollector{}, false)

	targets, err := e.Collect(t.Context(), endpoints(3))

	if err == nil {
		t.Error("Collect() error = nil, want the run reported as incomplete")
	}
	if len(targets) != 2 {
		t.Errorf("got %d targets, want 2 — the panicking one dropped, the others kept", len(targets))
	}
}

// TestRun_SkipCarriesTheFindingsTheCheckDidProduce pins that a skip and a
// finding are not alternatives.
//
// A check that examined three parameters and could not reach a fourth has
// something to report and something to admit. Keeping only one of them is
// wrong in one direction or the other: drop the findings and a real
// vulnerability goes unreported, drop the skip and a partly-examined route
// reads as a whole one — which is the failure the coverage block exists to
// end.
func TestRun_SkipCarriesTheFindingsTheCheckDidProduce(t *testing.T) {
	partial := &stubCheck{
		meta: model.CheckMetadata{Name: "partial", Kind: model.KindPassive, Severity: "high"},
		run: func(ctx context.Context, target model.Target, c model.Clients) ([]model.Finding, error) {
			return []model.Finding{{ID: "reachable"}},
				model.Skippedf("1 of 2 parameter(s) of %s could not be tested", target.Endpoint.Path)
		},
	}

	e := newEngine(t, false)
	results, err := e.Run(t.Context(), e.BuildJobs(targetsFor(endpoints(1)), []model.Check{partial}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	r := results[0]

	if !r.Skipped {
		t.Error("Skipped = false, want the admission to survive alongside the finding")
	}
	if !strings.Contains(r.SkipReason, "could not be tested") {
		t.Errorf("SkipReason = %q, want the check's explanation", r.SkipReason)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("got %d findings, want the 1 the check produced to survive the skip", len(r.Findings))
	}
	// Still enriched: a finding reported alongside a skip is a finding like
	// any other, and must not reach the report missing its metadata.
	if got := r.Findings[0]; got.CheckName != "partial" || got.Severity != "high" || got.ID == "reachable" {
		t.Errorf("finding = %+v, want it enriched with check name, severity and a namespaced ID", got)
	}
	if r.Err != nil {
		t.Errorf("Err = %v, want nil — a partial sweep is not a failure", r.Err)
	}
}
