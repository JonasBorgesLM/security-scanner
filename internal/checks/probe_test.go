package checks

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/JonasBorgesLM/security-scanner/internal/core/auth"
	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

func params(names ...string) []model.Parameter {
	out := make([]model.Parameter, len(names))
	for i, n := range names {
		out[i] = model.Parameter{Name: n, In: "query", Type: "string"}
	}
	return out
}

// TestRunPerParameter_PartialSweepReportsBoth is the defect this mechanism
// was extracted to fix. A parameter that could not be probed at all used to
// leave no trace whenever some other parameter had worked: no finding, no
// skip, no error — and the route was recorded as examined and clean.
func TestRunPerParameter_PartialSweepReportsBoth(t *testing.T) {
	ep := model.Endpoint{Method: "GET", Path: "/items"}
	ps := params("ok", "broken")
	cause := fmt.Errorf("%w: login endpoint returned status 500", auth.ErrReAuthFailed)

	res := runPerParameter(ps, func(p model.Parameter) (*model.Finding, error) {
		if p.Name == "broken" {
			return nil, cause
		}
		return &model.Finding{ID: p.Name}, nil
	})
	findings, err := res.outcome(ep, ps)

	if len(findings) != 1 {
		t.Fatalf("findings = %d, want the one parameter that could be tested to still be reported", len(findings))
	}
	if err == nil {
		t.Fatal("err = nil; the untested parameter must be admitted, not dropped")
	}
	if !errors.Is(err, model.ErrSkipped) {
		t.Errorf("errors.Is(err, ErrSkipped) = false for %v", err)
	}
	if !strings.Contains(err.Error(), "broken") {
		t.Errorf("reason = %q, want it to name the parameter that could not be tested", err)
	}
	// The cause has to survive as a value, not only as text: this is what
	// lets a caller tell broken auth from a missing baseline without
	// parsing an error message.
	if !errors.Is(err, auth.ErrReAuthFailed) {
		t.Errorf("errors.Is(err, auth.ErrReAuthFailed) = false for %v; Skippedf must wrap the cause with %%w", err)
	}
}

// TestRunPerParameter_NothingTestableIsAPlainSkip pins the pre-existing
// behaviour the change must not have altered.
func TestRunPerParameter_NothingTestableIsAPlainSkip(t *testing.T) {
	ep := model.Endpoint{Method: "GET", Path: "/items"}
	ps := params("a", "b")

	res := runPerParameter(ps, func(model.Parameter) (*model.Finding, error) {
		return nil, errors.New("refused")
	})
	findings, err := res.outcome(ep, ps)

	if findings != nil {
		t.Errorf("findings = %v, want none when nothing could be tested", findings)
	}
	if !errors.Is(err, model.ErrSkipped) {
		t.Fatalf("err = %v, want a skip", err)
	}
	if !strings.Contains(err.Error(), "could not test any parameter") {
		t.Errorf("reason = %q, want it to say nothing was testable", err)
	}
}

// TestRunPerParameter_FullSweepDoesNotSkip is the control that keeps the
// admission from becoming noise on every result.
func TestRunPerParameter_FullSweepDoesNotSkip(t *testing.T) {
	ep := model.Endpoint{Method: "GET", Path: "/items"}
	ps := params("a", "b")

	res := runPerParameter(ps, func(p model.Parameter) (*model.Finding, error) {
		if p.Name == "a" {
			return &model.Finding{ID: p.Name}, nil
		}
		return nil, nil // tested, nothing found
	})
	findings, err := res.outcome(ep, ps)

	if err != nil {
		t.Errorf("err = %v, want nil when every parameter was reachable", err)
	}
	if len(findings) != 1 {
		t.Errorf("findings = %d, want 1", len(findings))
	}
}

// authBreaksAfter serves normally until callN, then fails every request the
// way the Authenticator does once re-login has failed. It reproduces the
// realistic shape of a partial sweep: a token that expires between two
// parameters of the same endpoint.
type authBreaksAfter struct {
	after int64
	calls atomic.Int64
}

func (c *authBreaksAfter) Do(*http.Request) (*http.Response, error) {
	if c.calls.Add(1) > c.after {
		return nil, fmt.Errorf("%w: login endpoint returned status 500", auth.ErrReAuthFailed)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"rows":[]}`)),
		Header:     http.Header{},
	}, nil
}

// TestSQLi_AuthBreakingMidSweepIsAdmitted drives the same defect through
// the real check rather than the extracted helper. The budget is computed
// from the payload file so it stays correct as that file grows.
func TestSQLi_AuthBreakingMidSweepIsAdmitted(t *testing.T) {
	firstParameterBudget := int64(sqliNoiseSamples + 2*len(sqliPairs))

	target := model.Target{
		Endpoint: model.Endpoint{Method: "GET", Path: "/items", Parameters: params("first", "second")},
		Baseline: &model.Response{URL: "http://lab.test/items", StatusCode: 200, ProbedMethod: "GET"},
	}

	_, err := sqliCheck().Run(t.Context(), target, model.Clients{Default: &authBreaksAfter{after: firstParameterBudget}})

	if err == nil {
		t.Fatal("Run() = nil error; the second parameter was never probed and must be admitted")
	}
	if !errors.Is(err, model.ErrSkipped) {
		t.Errorf("errors.Is(err, ErrSkipped) = false for %v", err)
	}
	if !strings.Contains(err.Error(), "second") {
		t.Errorf("reason = %q, want it to name the parameter that went untested", err)
	}
}

// ------------------------------------------------- rejected probes are not results

// newValidatingServer answers 400 to any value of "id" that accept rejects,
// the way a parameter declared as an enum, an integer or a uuid does.
func newValidatingServer(t *testing.T, accept func(string) bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !accept(r.URL.Query().Get("id")) {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"invalid value for id"}`)
			return
		}
		fmt.Fprint(w, `{"rows":[{"id":1}]}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestActiveChecks_BenignValueRejectedIsInconclusive is the defect measured
// against the real task-api: GET /v1/tasks?status=1 answers 400 because
// status is an enum, so the benign filler is refused exactly as the payload
// is. The noise floor then gets measured over error pages, two error pages
// are compared, the difference is zero — and 68 requests later the route is
// recorded as examined and clean.
func TestActiveChecks_BenignValueRejectedIsInconclusive(t *testing.T) {
	srv := newValidatingServer(t, func(string) bool { return false })
	target := endpointFor(srv, "/items", queryParam("id"))

	tests := []struct {
		name  string
		check model.Check
	}{
		{name: "sqli-boolean", check: sqliCheck()},
		{name: "xss-reflected", check: &xssReflected{templates: xssMarkerTemplates}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := tt.check.Run(t.Context(), target, model.Clients{Default: http.DefaultClient})

			if len(findings) != 0 {
				t.Errorf("got %d findings, want 0", len(findings))
			}
			if err == nil {
				t.Fatal("Run() = nil error; the parameter was never exercised and must be admitted, not reported as clean")
			}
			if !errors.Is(err, model.ErrSkipped) {
				t.Errorf("errors.Is(err, ErrSkipped) = false for %v", err)
			}
			if !errors.Is(err, ErrNotExercised) {
				t.Errorf("errors.Is(err, ErrNotExercised) = false for %v", err)
			}
		})
	}
}

// TestActiveChecks_ValidationRejectingOnlyThePayloadIsAResult is the
// control, and the distinction the whole rule turns on. A benign value that
// succeeds while the payload is refused is the OPPOSITE outcome: the
// parameter was exercised and the target's validation held. Treating every
// 4xx as inconclusive would throw that away and report a defended parameter
// as unexamined — turning a working control into a gap in the report.
func TestActiveChecks_ValidationRejectingOnlyThePayloadIsAResult(t *testing.T) {
	srv := newValidatingServer(t, func(v string) bool { return v == sqliProbeFiller })
	target := endpointFor(srv, "/items", queryParam("id"))

	tests := []struct {
		name  string
		check model.Check
	}{
		{name: "sqli-boolean", check: sqliCheck()},
		{name: "xss-reflected", check: &xssReflected{templates: xssMarkerTemplates}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := tt.check.Run(t.Context(), target, model.Clients{Default: http.DefaultClient})

			if err != nil {
				t.Errorf("Run() error = %v, want nil — the benign value was accepted, so the parameter WAS exercised", err)
			}
			if len(findings) != 0 {
				t.Errorf("got %d findings, want 0 — validation refused every payload", len(findings))
			}
		})
	}
}
