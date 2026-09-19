package checks

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

func verboseServer(t *testing.T, onMalformed string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") == "1" || r.URL.Query().Get("q") == "" {
			fmt.Fprint(w, `{"ok":true}`)
			return
		}
		fmt.Fprint(w, onMalformed)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func verboseTarget(srv *httptest.Server, baselineBody string) model.Target {
	return model.Target{
		Endpoint: model.Endpoint{Method: http.MethodGet, Path: "/x", Parameters: []model.Parameter{queryParam("q")}},
		Baseline: &model.Response{URL: srv.URL + "/x", StatusCode: 200, ProbedMethod: http.MethodGet, Body: []byte(baselineBody)},
	}
}

func runVerbose(t *testing.T, target model.Target) ([]model.Finding, error) {
	t.Helper()
	return (&verboseErrors{}).Run(t.Context(), target, model.Clients{Default: http.DefaultClient})
}

// TestVerboseErrors_LeakAbsentFromBaselineIsAFinding is the core case.
func TestVerboseErrors_LeakAbsentFromBaselineIsAFinding(t *testing.T) {
	srv := verboseServer(t, `panic: runtime error

goroutine 1 [running]:
main.handler(0x0)
	/app/handler.go:42 +0x1a5`)

	findings, err := runVerbose(t, verboseTarget(srv, `{"ok":true}`))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Evidence.ResponseSnippet, "stack trace") {
		t.Errorf("evidence = %q, want it to name the leak", findings[0].Evidence.ResponseSnippet)
	}
}

// TestVerboseErrors_LeakAlsoInBaselineIsNotAFinding is the discriminator:
// a signature the route returns anyway is not something the malformed input
// caused. Without the baseline comparison this would be a false positive.
func TestVerboseErrors_LeakAlsoInBaselineIsNotAFinding(t *testing.T) {
	leak := `see /usr/share/docs for details`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, leak) // every response, malformed or not
	}))
	t.Cleanup(srv.Close)

	findings, err := runVerbose(t, verboseTarget(srv, leak))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 — the path is in the baseline too", len(findings))
	}
}

// TestVerboseErrors_StructuredEnvelopeIsClean keeps it from firing on a
// well-formed error, which is the whole reason the patterns are specific.
func TestVerboseErrors_StructuredEnvelopeIsClean(t *testing.T) {
	srv := verboseServer(t, `{"error":{"code":"invalid_input","message":"q must be an integer"}}`)

	findings, err := runVerbose(t, verboseTarget(srv, `{"ok":true}`))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings against a clean error envelope, want 0: %v", len(findings), findings)
	}
}

// TestLooksLikeErrorLeak_Signatures pins the matcher the check and the
// confirmer share.
func TestLooksLikeErrorLeak_Signatures(t *testing.T) {
	leaky := map[string]string{
		"go":     "goroutine 17 [select]:",
		"python": `Traceback (most recent call last):`,
		"sql":    "pq: syntax error at or near \"'\"",
		"path":   "open /var/secrets/key: no such file",
	}
	for name, body := range leaky {
		if _, ok := LooksLikeErrorLeak(body); !ok {
			t.Errorf("%s: LooksLikeErrorLeak returned false for %q", name, body)
		}
	}

	clean := []string{`{"error":"not found"}`, "an error occurred", "please try again"}
	for _, body := range clean {
		if name, ok := LooksLikeErrorLeak(body); ok {
			t.Errorf("LooksLikeErrorLeak flagged clean text %q as %q", body, name)
		}
	}
}
