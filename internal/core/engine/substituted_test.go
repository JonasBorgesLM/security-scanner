package engine

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/warden/internal/core/model"
)

// countingCheck records whether it was invoked, which is the point of every
// test below: the question is not what a check concluded but whether it was
// allowed to conclude anything at all.
type countingCheck struct {
	meta model.CheckMetadata
	runs int
}

var _ model.Check = (*countingCheck)(nil)

func (c *countingCheck) Metadata() model.CheckMetadata { return c.meta }

func (c *countingCheck) Run(context.Context, model.Target, model.Clients) ([]model.Finding, error) {
	c.runs++
	return []model.Finding{{ID: "found"}}, nil
}

func postTarget(probedMethod string) model.Target {
	return model.Target{
		Endpoint: model.Endpoint{Method: http.MethodPost, Path: "/items"},
		Baseline: &model.Response{
			URL:          testBaseURL + "/items",
			StatusCode:   http.StatusMethodNotAllowed,
			ProbedMethod: probedMethod,
			Headers:      http.Header{},
		},
	}
}

// TestRun_PassiveCheckIsNotRunOnASubstitutedBaseline is the defect.
//
// Collection substitutes a safe method for anything unsafe, so a POST
// route's baseline is whatever the server answers to GET — on a server that
// routes strictly by method, its 405 handler. A passive check judging that
// reports the wrong response under the route's name, and does it once per
// passive check per route: one error page arrives as a stack of duplicate
// findings wearing other routes' names.
func TestRun_PassiveCheckIsNotRunOnASubstitutedBaseline(t *testing.T) {
	check := &countingCheck{meta: model.CheckMetadata{Name: "headers", Kind: model.KindPassive}}

	results := newEngine(t, false).runJob(t.Context(), Job{Target: postTarget(http.MethodGet), Check: check})

	if check.runs != 0 {
		t.Errorf("check ran %d time(s), want 0 — it was never shown this route's response", check.runs)
	}
	if !results.Skipped {
		t.Error("Skipped = false, want the gap admitted")
	}
	if len(results.Findings) != 0 {
		t.Errorf("got %d findings, want 0", len(results.Findings))
	}
	for _, want := range []string{"POST", "GET", "never seen"} {
		if !strings.Contains(results.SkipReason, want) {
			t.Errorf("SkipReason = %q, want it to mention %q", results.SkipReason, want)
		}
	}
}

// TestRun_PassiveCheckStillRunsOnItsOwnMethod is the control that keeps the
// rule from silencing the 14-out-of-22 routes it has no business touching.
func TestRun_PassiveCheckStillRunsOnItsOwnMethod(t *testing.T) {
	check := &countingCheck{meta: model.CheckMetadata{Name: "headers", Kind: model.KindPassive}}
	target := model.Target{
		Endpoint: model.Endpoint{Method: http.MethodGet, Path: "/items"},
		Baseline: &model.Response{URL: testBaseURL + "/items", StatusCode: 200, ProbedMethod: http.MethodGet, Headers: http.Header{}},
	}

	res := newEngine(t, false).runJob(t.Context(), Job{Target: target, Check: check})

	if check.runs != 1 {
		t.Errorf("check ran %d time(s), want 1", check.runs)
	}
	if res.Skipped {
		t.Errorf("Skipped = true (%q), want the check's own verdict", res.SkipReason)
	}
	if len(res.Findings) != 1 {
		t.Errorf("got %d findings, want the check's 1", len(res.Findings))
	}
}

// TestRun_ActiveCheckStillRunsOnASubstitutedBaseline is the control that
// matters most for coverage. An active check sends its own requests with
// the endpoint's own method and deliberately does not read the baseline's
// body — only its URL, for scheme and host. Silencing it here would lose
// SQLi and XSS coverage on every POST route for no reason at all.
func TestRun_ActiveCheckStillRunsOnASubstitutedBaseline(t *testing.T) {
	check := &countingCheck{meta: model.CheckMetadata{Name: "sqli", Kind: model.KindActive}}

	res := newEngine(t, false).runJob(t.Context(), Job{Target: postTarget(http.MethodGet), Check: check})

	if check.runs != 1 {
		t.Errorf("active check ran %d time(s), want 1 — it never relied on the baseline body", check.runs)
	}
	if res.Skipped {
		t.Errorf("Skipped = true (%q), want the active check to proceed", res.SkipReason)
	}
}
