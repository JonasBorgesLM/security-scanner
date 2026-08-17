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

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
	"github.com/JonasBorgesLM/security-scanner/internal/ports"
)

func sqliCheck() *sqliBoolean {
	return &sqliBoolean{pairs: mustParsePayloadPairs(sqliPayloadsFile)}
}

// endpointFor builds a Target pointed at srv, with a single query parameter
// named "id" and a baseline whose URL carries srv's real origin — exactly
// what the engine's collection phase would have produced.
func endpointFor(srv *httptest.Server, path string, params ...model.Parameter) model.Target {
	return model.Target{
		Endpoint: model.Endpoint{
			Method:     http.MethodGet,
			Path:       path,
			Parameters: params,
		},
		Baseline: &model.Response{
			URL:          srv.URL + path,
			StatusCode:   http.StatusOK,
			ProbedMethod: http.MethodGet,
		},
	}
}

func queryParam(name string) model.Parameter {
	return model.Parameter{Name: name, In: "query", Type: "string"}
}

func pathParam(name string) model.Parameter {
	return model.Parameter{Name: name, In: "path", Type: "string"}
}

func runSQLi(t *testing.T, target model.Target) ([]model.Finding, error) {
	t.Helper()
	return sqliCheck().Run(t.Context(), target, http.DefaultClient)
}

// ------------------------------------------------------------------ metadata

func TestSQLiBoolean_Metadata(t *testing.T) {
	meta := sqliCheck().Metadata()

	if meta.Name != "sqli-boolean" {
		t.Errorf("Name = %q", meta.Name)
	}
	if meta.Kind != model.KindActive {
		t.Errorf("Kind = %q, want active — this check must send its own requests", meta.Kind)
	}
	if meta.Severity != "high" {
		t.Errorf("Severity = %q, want high", meta.Severity)
	}
	if !strings.HasPrefix(meta.OWASPCategory, "A03") {
		t.Errorf("OWASPCategory = %q, want an A03 (Injection) category", meta.OWASPCategory)
	}
}

func TestSQLiBoolean_RegisteredByInit(t *testing.T) {
	if names := Names(); !contains(names, "sqli-boolean") {
		t.Errorf("registered checks = %v, want sqli-boolean among them", names)
	}
}

func contains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

func TestSQLiBoolean_AppliesToOnlyEndpointsWithQueryOrPathParams(t *testing.T) {
	tests := []struct {
		name string
		ep   model.Endpoint
		want bool
	}{
		{"query param", model.Endpoint{Parameters: []model.Parameter{queryParam("id")}}, true},
		{"path param", model.Endpoint{Parameters: []model.Parameter{pathParam("id")}}, true},
		{"header param only", model.Endpoint{Parameters: []model.Parameter{{Name: "X-Trace", In: "header"}}}, false},
		{"no params", model.Endpoint{}, false},
	}
	applies := sqliCheck().Metadata().AppliesTo
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := applies(tt.ep); got != tt.want {
				t.Errorf("AppliesTo() = %v, want %v", got, tt.want)
			}
		})
	}
}

// -------------------------------------------------------- vulnerable target

// vulnerableSQLiServer simulates `SELECT * FROM items WHERE id = '<id>'`
// concatenated without sanitisation: an always-true condition returns every
// row, an always-false one returns none, and the ordinary filler value
// returns exactly the one matching row. The response is fully deterministic
// — same input, same output, every time — so the noise floor this check
// measures is exactly zero and any real difference stands out completely.
func vulnerableSQLiServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		n := rowsFor(id)

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"items":[`)
		for i := range n {
			if i > 0 {
				fmt.Fprint(w, ",")
			}
			fmt.Fprintf(w, `{"id":%d,"name":"item-%d"}`, i, i)
		}
		fmt.Fprint(w, `]}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// rowsFor mimics evaluating the injected condition: every true-payload in
// payloads/sqli.txt contains one of these "always true" markers, every
// false-payload one of the "always false" ones, and the plain filler value
// matches neither.
func rowsFor(id string) int {
	trueMarkers := []string{"1'='1", `1"="1`, "1=1"}
	falseMarkers := []string{"1'='2", `1"="2`, "1=2"}

	for _, m := range trueMarkers {
		if strings.Contains(id, m) {
			return 25
		}
	}
	for _, m := range falseMarkers {
		if strings.Contains(id, m) {
			return 0
		}
	}
	return 1 // the ordinary probe filler: one normal match
}

func TestSQLiBoolean_FindsInjectionInQueryParameter(t *testing.T) {
	srv := vulnerableSQLiServer(t)
	target := endpointFor(srv, "/items", queryParam("id"))

	findings, err := runSQLi(t, target)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}

	f := findings[0]
	if f.ID != "id" {
		t.Errorf("ID = %q, want the parameter name", f.ID)
	}
	if f.Evidence.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", f.Evidence.StatusCode)
	}
}

func TestSQLiBoolean_FindsInjectionInPathParameter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/items/")
		n := rowsFor(id)
		fmt.Fprint(w, strings.Repeat("x", n*10)) // body length scales with row count
	}))
	t.Cleanup(srv.Close)

	target := endpointFor(srv, "/items/{id}", pathParam("id"))

	findings, err := runSQLi(t, target)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
}

// ----------------------------------------------- CapturedRequest completeness

func TestSQLiBoolean_CapturedRequestReproducesTheAttack(t *testing.T) {
	srv := vulnerableSQLiServer(t)
	target := endpointFor(srv, "/items", queryParam("id"))

	findings, err := runSQLi(t, target)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	req := findings[0].Request

	if req.Method != http.MethodGet {
		t.Errorf("Request.Method = %q, want GET", req.Method)
	}
	if req.InjectedParam != "id" {
		t.Errorf("Request.InjectedParam = %q, want id", req.InjectedParam)
	}
	if req.Payload == "" {
		t.Error("Request.Payload is empty — attack has nothing to replay")
	}
	if !strings.Contains(req.Payload, "1'='1") && !strings.Contains(req.Payload, `1"="1`) && !strings.Contains(req.Payload, "1=1") {
		t.Errorf("Request.Payload = %q, want one of the true-payloads", req.Payload)
	}

	// The captured URL must actually be the request that produced the
	// finding: resending it should reproduce the same "vulnerable" response
	// shape, which is exactly what the attack stage needs.
	resp, err := http.Get(req.URL)
	if err != nil {
		t.Fatalf("replaying Request.URL failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("replayed request status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(req.URL, srv.URL) {
		t.Errorf("Request.URL = %q, want it to target %s", req.URL, srv.URL)
	}
}

// ----------------------------------------------------- stable-but-dynamic target

// dynamicSQLiServer ignores the injected parameter entirely — it is not
// vulnerable — but every response carries a small auxiliary field (a nonce,
// a request ID, a timestamp: the ordinary churn of a real API) whose length
// rotates through a fixed, repeating cycle. That makes two identical
// requests return bodies of slightly different length even though nothing
// about the query changed, which is exactly the false-positive trap
// invariant #4 exists to guard against.
//
// The cycle is deterministic rather than random on purpose: a flaky test
// would either hide a real bug or train everyone to re-run it, and neither
// is acceptable for a check whose entire job is telling signal from noise.
func dynamicSQLiServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	paddings := []string{"", "abc", "a"} // lengths 0, 3, 1 — deliberately uneven

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1) - 1
		p := paddings[int(n)%len(paddings)]
		fmt.Fprintf(w, `{"items":[{"id":1,"name":"item-1"}],"nonce":%q}`, p)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestSQLiBoolean_DynamicButUnaffectedResponseIsNotFlagged(t *testing.T) {
	srv, calls := dynamicSQLiServer(t)
	target := endpointFor(srv, "/items", queryParam("id"))

	findings, err := runSQLi(t, target)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0 — the endpoint's own noise must not be mistaken for injection\n%+v",
			len(findings), findings)
	}
	// Sanity: the server was actually exercised across the noise samples and
	// every payload pair, not short-circuited into never running.
	if got := calls.Load(); got < sqliNoiseSamples+2 {
		t.Errorf("server received %d requests, want at least %d", got, sqliNoiseSamples+2)
	}
}

// A fully static clean endpoint (zero noise, zero signal) is the simplest
// case and must also stay quiet.
func TestSQLiBoolean_StaticCleanEndpointIsNotFlagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"items":[{"id":1,"name":"item-1"}]}`)
	}))
	t.Cleanup(srv.Close)

	findings, err := runSQLi(t, endpointFor(srv, "/items", queryParam("id")))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

// --------------------------------------------------------------- other params

// When testing one parameter, every other parameter must be filled with the
// inert filler rather than left empty — otherwise a route requiring several
// parameters would 400 on every probe regardless of injection, which would
// either mask a real vulnerability or (worse) look like a signal.
func TestSQLiBoolean_OtherParametersAreFilledNotLeftEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("category") == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":"category is required"}`)
			return
		}
		n := rowsFor(q.Get("id"))
		fmt.Fprint(w, strings.Repeat("x", n*10))
	}))
	t.Cleanup(srv.Close)

	target := endpointFor(srv, "/items", queryParam("id"), queryParam("category"))

	findings, err := runSQLi(t, target)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 — a missing sibling parameter must not have masked the injection", len(findings))
	}
}

// ------------------------------------------------------------------- skipping

func TestSQLiBoolean_SkipsWithoutABaseline(t *testing.T) {
	target := model.Target{
		Endpoint: model.Endpoint{
			Method:     http.MethodGet,
			Path:       "/items",
			Parameters: []model.Parameter{queryParam("id")},
		},
		BaselineErr: errors.New("connection refused"),
	}

	_, err := runSQLi(t, target)
	if !errors.Is(err, model.ErrSkipped) {
		t.Fatalf("error = %v, want it to wrap model.ErrSkipped", err)
	}
}

func TestSQLiBoolean_NoInjectableParametersProducesNoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{}`)
	}))
	t.Cleanup(srv.Close)

	target := endpointFor(srv, "/health") // no parameters at all
	findings, err := runSQLi(t, target)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestSQLiBoolean_UnreachableTargetIsSkipped(t *testing.T) {
	target := model.Target{
		Endpoint: model.Endpoint{
			Method:     http.MethodGet,
			Path:       "/items",
			Parameters: []model.Parameter{queryParam("id")},
		},
		Baseline: &model.Response{URL: "http://127.0.0.1:1/items", StatusCode: http.StatusOK},
	}

	_, err := runSQLi(t, target)
	if !errors.Is(err, model.ErrSkipped) {
		t.Fatalf("error = %v, want it to wrap model.ErrSkipped when the target cannot be reached at all", err)
	}
}

// ----------------------------------------------------------------- determinism

func TestSQLiBoolean_IsDeterministicAgainstAStaticTarget(t *testing.T) {
	srv := vulnerableSQLiServer(t)
	target := endpointFor(srv, "/items", queryParam("id"))

	var first []string
	for run := range 10 {
		findings, err := runSQLi(t, target)
		if err != nil {
			t.Fatalf("run %d: Run() error = %v", run, err)
		}
		ids := make([]string, len(findings))
		for i, f := range findings {
			ids[i] = f.ID
		}
		if run == 0 {
			first = ids
			continue
		}
		if strings.Join(ids, ",") != strings.Join(first, ",") {
			t.Fatalf("run %d findings = %v, differ from first run %v", run, ids, first)
		}
	}
}

// ------------------------------------------------------------------- noise math

func TestAbsInt(t *testing.T) {
	tests := []struct{ in, want int }{{5, 5}, {-5, 5}, {0, 0}, {-1, 1}}
	for _, tt := range tests {
		if got := absInt(tt.in); got != tt.want {
			t.Errorf("absInt(%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestSnippetOf(t *testing.T) {
	if got := snippetOf(nil); got != "<empty body>" {
		t.Errorf("snippetOf(nil) = %q", got)
	}
	if got := snippetOf([]byte("  a   b  ")); got != "a b" {
		t.Errorf("snippetOf collapsed whitespace = %q, want %q", got, "a b")
	}
	long := strings.Repeat("x", sqliSnippetLimit+50)
	if got := snippetOf([]byte(long)); !strings.HasSuffix(got, "…") {
		t.Errorf("snippetOf() did not truncate a long body")
	}
}

// ------------------------------------------------------------------- payloads

func TestPayloadFileIsWellFormed(t *testing.T) {
	pairs := mustParsePayloadPairs(sqliPayloadsFile)

	if len(pairs) < 3 {
		t.Errorf("parsed %d pairs, want a useful embedded set", len(pairs))
	}
	seen := map[string]bool{}
	for _, p := range pairs {
		if seen[p.name] {
			t.Errorf("duplicate pattern name %q", p.name)
		}
		seen[p.name] = true
		if p.truePayload == p.falsePayload {
			t.Errorf("%s: true and false payloads are identical", p.name)
		}
	}
}

func TestMustParsePayloadPairs_RejectsMalformedLines(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"missing fields", "name ||| only-one-payload\n"},
		{"empty name", " ||| a ||| b\n"},
		{"identical payloads", "name ||| same ||| same\n"},
		{"duplicate name", "dup ||| a ||| b\ndup ||| c ||| d\n"},
		{"no pairs at all", "# just a comment\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("did not panic — a malformed embedded payload file is a build-time mistake")
				}
			}()
			mustParsePayloadPairs(tt.in)
		})
	}
}

func TestMustParsePayloadPairs_SkipsCommentsAndBlankLines(t *testing.T) {
	pairs := mustParsePayloadPairs("# comment\n\n   \nname ||| a ||| b\n")
	if len(pairs) != 1 || pairs[0].name != "name" {
		t.Errorf("parsed %+v", pairs)
	}
}

// ---------------------------------------------------------- probe error paths

// An endpoint whose method net/http refuses to send at all must make every
// probe fail the same way, including the noise-measurement stage — so the
// parameter is reported untestable rather than silently skipped.
func TestSQLiBoolean_UnbuildableRequestMakesTheParameterUntestable(t *testing.T) {
	target := model.Target{
		Endpoint: model.Endpoint{
			Method:     "BAD METHOD", // rejected by net/http's method validation
			Path:       "/items",
			Parameters: []model.Parameter{queryParam("id")},
		},
		Baseline: &model.Response{URL: "http://lab.invalid/items", StatusCode: http.StatusOK},
	}

	_, err := runSQLi(t, target)
	if !errors.Is(err, model.ErrSkipped) {
		t.Fatalf("error = %v, want it to wrap model.ErrSkipped when no request can even be built", err)
	}
}

// A pair whose true or false probe fails mid-test (a transient network
// error, say) must not abort testing the rest of the pairs — nor the rest
// of the endpoint's parameters.
func TestSQLiBoolean_FailedPairProbeIsSkippedNotFatal(t *testing.T) {
	srv := vulnerableSQLiServer(t)

	var calls atomic.Int32
	flaky := flakyClient{
		inner: http.DefaultClient,
		fail: func() bool {
			// Let the three noise-measurement calls through, then fail
			// every call after that — so every payload pair's probe trips
			// the error path in testParameter's loop.
			return calls.Add(1) > sqliNoiseSamples
		},
	}

	target := endpointFor(srv, "/items", queryParam("id"))
	findings, err := sqliCheck().Run(t.Context(), target, flaky)
	if err != nil {
		t.Fatalf("Run() error = %v, want nil — the noise measurement itself succeeded", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 — every pair's probe failed, so nothing was confirmed", len(findings))
	}
}

// flakyClient wraps a real client but fails calls on demand, so tests can
// exercise probe()'s and testParameter()'s error-handling branches without
// depending on real network flakiness.
type flakyClient struct {
	inner ports.HTTPClient
	fail  func() bool
}

func (c flakyClient) Do(req *http.Request) (*http.Response, error) {
	if c.fail() {
		return nil, errors.New("flakyClient: simulated failure")
	}
	return c.inner.Do(req)
}

// brokenBodyClient answers every request with a body that errors on read,
// exercising probe()'s io.ReadAll error path — not reachable through a real
// httptest.Server, which always serves a well-formed body.
type brokenBodyClient struct{}

func (brokenBodyClient) Do(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(errReader{}),
		Request:    req,
	}, nil
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("errReader: simulated read failure") }

func TestSQLiBoolean_UnreadableBodyMakesTheParameterUntestable(t *testing.T) {
	target := model.Target{
		Endpoint: model.Endpoint{
			Method:     http.MethodGet,
			Path:       "/items",
			Parameters: []model.Parameter{queryParam("id")},
		},
		Baseline: &model.Response{URL: "http://lab.invalid/items", StatusCode: http.StatusOK},
	}

	_, err := sqliCheck().Run(t.Context(), target, brokenBodyClient{})
	if !errors.Is(err, model.ErrSkipped) {
		t.Fatalf("error = %v, want it to wrap model.ErrSkipped when the response body cannot be read", err)
	}
}
