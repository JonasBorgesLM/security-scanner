package checks

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/warden/internal/core/model"
)

func corsTarget(headers map[string]string) model.Target {
	h := http.Header{}
	for k, v := range headers {
		h.Set(k, v)
	}
	return model.Target{
		Endpoint: model.Endpoint{Method: http.MethodGet, Path: "/items"},
		Baseline: &model.Response{URL: "http://lab.test/items", StatusCode: 200, ProbedMethod: http.MethodGet},
		Probes: model.Probes{
			Origin: &model.Response{URL: "http://lab.test/items", StatusCode: 200, ProbedMethod: http.MethodGet, Headers: h},
		},
	}
}

func runCORS(t *testing.T, target model.Target) ([]model.Finding, error) {
	t.Helper()
	return (&corsMisconfigured{}).Run(t.Context(), target, model.Clients{})
}

// TestCORS_AbsenceIsTheSecureState is the inversion this check turns on,
// and the mistake that writing it like every other check would produce.
//
// A route saying nothing about cross-origin access is one the same-origin
// policy protects on its own. Reporting that as a missing header would flag
// every correctly configured route on the target.
func TestCORS_AbsenceIsTheSecureState(t *testing.T) {
	findings, err := runCORS(t, corsTarget(nil))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings for a response granting nothing, want 0: %+v", len(findings), findings)
	}
}

// TestCORS_Tiers grades each way a grant can be wrong, and the two ways it
// can be deliberate.
func TestCORS_Tiers(t *testing.T) {
	tests := []struct {
		name         string
		headers      map[string]string
		wantSeverity string
		wantReason   string
	}{
		{
			name: "reflects any origin, with credentials",
			headers: map[string]string{
				"Access-Control-Allow-Origin":      model.ProbeOrigin,
				"Access-Control-Allow-Credentials": "true",
				"Vary":                             "Origin",
			},
			wantSeverity: "high",
			wantReason:   "victim's session attached",
		},
		{
			name:         "reflects any origin, no credentials",
			headers:      map[string]string{"Access-Control-Allow-Origin": model.ProbeOrigin, "Vary": "Origin"},
			wantSeverity: "medium",
			wantReason:   "reflects whatever origin asks",
		},
		{
			name: "wildcard with credentials is broken, not exploitable",
			headers: map[string]string{
				"Access-Control-Allow-Origin":      "*",
				"Access-Control-Allow-Credentials": "true",
			},
			wantSeverity: "low",
			wantReason:   "Browsers refuse that combination",
		},
		{
			name:         "a plain wildcard is a deliberate public API",
			headers:      map[string]string{"Access-Control-Allow-Origin": "*"},
			wantSeverity: "",
		},
		{
			name:         "an allow-list that did not include the probe",
			headers:      map[string]string{"Access-Control-Allow-Origin": "https://app.example.com"},
			wantSeverity: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := runCORS(t, corsTarget(tt.headers))
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}

			if tt.wantSeverity == "" {
				if len(findings) != 0 {
					t.Fatalf("got %d findings, want none: %+v", len(findings), findings)
				}
				return
			}
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
			if findings[0].Severity != tt.wantSeverity {
				t.Errorf("Severity = %q, want %q", findings[0].Severity, tt.wantSeverity)
			}
			if !strings.Contains(findings[0].Evidence.ResponseSnippet, tt.wantReason) {
				t.Errorf("evidence = %q, want it to mention %q", findings[0].Evidence.ResponseSnippet, tt.wantReason)
			}
		})
	}
}

// TestCORS_MissingVaryIsCalledOutOnAReflection covers the cache half: a
// reflected origin without Vary: Origin lets a shared cache store the
// answer and hand it to a different origin.
func TestCORS_MissingVaryIsCalledOutOnAReflection(t *testing.T) {
	with := corsTarget(map[string]string{"Access-Control-Allow-Origin": model.ProbeOrigin, "Vary": "Origin"})
	without := corsTarget(map[string]string{"Access-Control-Allow-Origin": model.ProbeOrigin})

	a, _ := runCORS(t, with)
	b, _ := runCORS(t, without)
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("expected one finding each, got %d and %d", len(a), len(b))
	}

	if strings.Contains(a[0].Evidence.ResponseSnippet, "Vary: Origin") {
		t.Error("a response that does set Vary: Origin was told it does not")
	}
	if !strings.Contains(b[0].Evidence.ResponseSnippet, "Vary: Origin") {
		t.Errorf("evidence = %q, want the missing Vary called out", b[0].Evidence.ResponseSnippet)
	}
}

// TestCORS_VaryIsMatchedCaseInsensitivelyInAList guards a header servers
// write however they like: "Accept-Encoding, origin" still varies on it.
func TestCORS_VaryIsMatchedCaseInsensitivelyInAList(t *testing.T) {
	findings, err := runCORS(t, corsTarget(map[string]string{
		"Access-Control-Allow-Origin": model.ProbeOrigin,
		"Vary":                        "Accept-Encoding, origin",
	}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if strings.Contains(findings[0].Evidence.ResponseSnippet, "omits Vary: Origin") {
		t.Error("Vary listed origin in lower case among others and was read as absent")
	}
}

// TestCORS_NoProbeIsASkip keeps invariant 6: a policy nobody observed
// cannot be judged, and silence would read as judging it fine.
func TestCORS_NoProbeIsASkip(t *testing.T) {
	target := model.Target{
		Endpoint:    model.Endpoint{Method: http.MethodGet, Path: "/items"},
		BaselineErr: errors.New("connection refused"),
	}
	if _, err := runCORS(t, target); !errors.Is(err, model.ErrSkipped) {
		t.Errorf("err = %v, want a skip", err)
	}
}

// TestCORS_IsPassive pins that it costs no request of its own: the probe it
// reads was collected once, during the pass that already runs.
func TestCORS_IsPassive(t *testing.T) {
	if got := (&corsMisconfigured{}).Metadata().Kind; got != model.KindPassive {
		t.Errorf("Kind = %q, want passive", got)
	}
}
