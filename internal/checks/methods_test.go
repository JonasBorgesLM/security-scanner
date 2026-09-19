package checks

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

// newTraceServer echoes the request back when TRACE is allowed, the way a
// server with TRACE enabled does, and records every Authorization header it
// received so a test can prove none arrived.
func newTraceServer(t *testing.T, enabled bool) (srv *httptest.Server, authSeen func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()

		if r.Method != http.MethodTrace {
			w.WriteHeader(http.StatusOK)
			return
		}
		if !enabled {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "message/http")
		fmt.Fprintf(w, "TRACE %s HTTP/1.1\r\n", r.URL.Path)
		for name, values := range r.Header {
			fmt.Fprintf(w, "%s: %s\r\n", name, strings.Join(values, ", "))
		}
	}))
	t.Cleanup(srv.Close)

	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func methodsTarget(srv *httptest.Server) model.Target {
	return model.Target{
		Endpoint: model.Endpoint{Method: http.MethodGet, Path: "/items"},
		Baseline: &model.Response{URL: srv.URL + "/items", StatusCode: 200, ProbedMethod: http.MethodGet},
	}
}

// TestDangerousMethods_EchoIsTheProof separates TRACE working from the
// server merely answering 200. The marker header is one the target has no
// reason to know, so finding it in the body is the behaviour itself rather
// than the server's account of itself.
func TestDangerousMethods_EchoIsTheProof(t *testing.T) {
	srv, _ := newTraceServer(t, true)

	findings, err := (&dangerousMethods{}).Run(t.Context(), methodsTarget(srv),
		model.Clients{Default: tokenClient{}, Anonymous: http.DefaultClient})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if got := findings[0].Evidence.StatusCode; got != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", got)
	}
	if !strings.Contains(findings[0].Evidence.ResponseSnippet, traceMarker) {
		t.Errorf("evidence = %q, want the echo that proves it", findings[0].Evidence.ResponseSnippet)
	}
}

// TestDangerousMethods_NeverSendsCredentials is the detail TRACE makes
// mandatory. The response is the request, so an authenticated probe would
// have the target hand the Authorization header straight back — and the
// evidence would carry a live credential into a findings.json that gets
// committed.
func TestDangerousMethods_NeverSendsCredentials(t *testing.T) {
	srv, authSeen := newTraceServer(t, true)

	findings, err := (&dangerousMethods{}).Run(t.Context(), methodsTarget(srv),
		model.Clients{Default: tokenClient{}, Anonymous: http.DefaultClient})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	for _, got := range authSeen() {
		if got != "" {
			t.Fatalf("the target received Authorization %q; TRACE would echo it straight into the evidence", got)
		}
	}
	if len(findings) == 1 && strings.Contains(findings[0].Evidence.ResponseSnippet, "Bearer") {
		t.Error("evidence contains a bearer token")
	}
}

// TestDangerousMethods_RefusedIsClean covers the answer everyone wants.
func TestDangerousMethods_RefusedIsClean(t *testing.T) {
	srv, _ := newTraceServer(t, false)

	findings, err := (&dangerousMethods{}).Run(t.Context(), methodsTarget(srv),
		model.Clients{Default: tokenClient{}, Anonymous: http.DefaultClient})
	if err != nil {
		t.Fatalf("Run() error = %v, want a clean verdict", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings against a server that refuses TRACE, want 0", len(findings))
	}
}

// TestDangerousMethods_TwoHundredWithoutTheEchoIsInconclusive keeps the
// check from reporting something that would not reproduce. A catch-all
// route, or a proxy answering on the server's behalf, returns 200 without
// TRACE ever running.
func TestDangerousMethods_TwoHundredWithoutTheEchoIsInconclusive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"catch":"all"}`)
	}))
	t.Cleanup(srv.Close)

	findings, err := (&dangerousMethods{}).Run(t.Context(), methodsTarget(srv),
		model.Clients{Default: tokenClient{}, Anonymous: http.DefaultClient})

	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
	if !errors.Is(err, model.ErrSkipped) {
		t.Fatalf("err = %v, want a skip — a 200 with no echo does not prove TRACE ran", err)
	}
	if !strings.Contains(err.Error(), "did not echo") {
		t.Errorf("reason = %q, want it to say what was missing", err)
	}
}

// TestDangerousMethods_SeverityIsLow pins the grading decision, which runs
// against what scanners traditionally report. Cross-Site Tracing has not
// been reachable since browsers stopped letting script issue TRACE; what
// remains is information disclosure.
func TestDangerousMethods_SeverityIsLow(t *testing.T) {
	meta := (&dangerousMethods{}).Metadata()
	if meta.Severity != "low" {
		t.Errorf("Severity = %q, want low — XST is not reachable and grading it medium repeats a habit", meta.Severity)
	}
	if meta.Kind != model.KindActive {
		t.Errorf("Kind = %q, want active — it proves the behaviour instead of reading a claim about it", meta.Kind)
	}
}

// TestDangerousMethods_NoBaselineIsASkip keeps invariant 6.
func TestDangerousMethods_NoBaselineIsASkip(t *testing.T) {
	_, err := (&dangerousMethods{}).Run(t.Context(),
		model.Target{Endpoint: model.Endpoint{Method: http.MethodGet, Path: "/items"}, BaselineErr: errors.New("refused")},
		model.Clients{Anonymous: http.DefaultClient})
	if !errors.Is(err, model.ErrSkipped) {
		t.Errorf("err = %v, want a skip", err)
	}
}
