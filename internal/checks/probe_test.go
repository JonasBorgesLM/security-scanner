package checks

import (
	"errors"
	"fmt"
	"io"
	"net/http"
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

	_, err := sqliCheck().Run(t.Context(), target, &authBreaksAfter{after: firstParameterBudget})

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
