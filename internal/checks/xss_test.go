package checks

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

func xssCheck() *xssReflected {
	return &xssReflected{templates: mustParseMarkerTemplates(xssPayloadsFile)}
}

func runXSS(t *testing.T, target model.Target) ([]model.Finding, error) {
	t.Helper()
	return xssCheck().Run(t.Context(), target, http.DefaultClient)
}

// ------------------------------------------------------------------ metadata

func TestXSSReflected_Metadata(t *testing.T) {
	meta := xssCheck().Metadata()

	if meta.Name != "xss-reflected" {
		t.Errorf("Name = %q, want xss-reflected", meta.Name)
	}
	if meta.Kind != model.KindActive {
		t.Errorf("Kind = %q, want active — this check must send its own requests", meta.Kind)
	}
	if meta.Severity != "high" {
		t.Errorf("Severity = %q, want high", meta.Severity)
	}
	if meta.OWASPCategory != "A03:2021-Injection" {
		t.Errorf("OWASPCategory = %q, want A03:2021-Injection", meta.OWASPCategory)
	}
}

func TestXSSReflected_RegisteredByInit(t *testing.T) {
	if names := Names(); !contains(names, "xss-reflected") {
		t.Errorf("registered checks = %v, want xss-reflected among them", names)
	}
}

func TestXSSReflected_AppliesToOnlyEndpointsWithQueryOrPathParams(t *testing.T) {
	meta := xssCheck().Metadata()

	tests := []struct {
		name string
		ep   model.Endpoint
		want bool
	}{
		{"query param", model.Endpoint{Parameters: []model.Parameter{queryParam("q")}}, true},
		{"path param", model.Endpoint{Parameters: []model.Parameter{pathParam("id")}}, true},
		{"header param only", model.Endpoint{Parameters: []model.Parameter{{Name: "X-Trace", In: "header"}}}, false},
		{"no params", model.Endpoint{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := meta.AppliesTo(tt.ep); got != tt.want {
				t.Errorf("AppliesTo(%+v) = %v, want %v", tt.ep, got, tt.want)
			}
		})
	}
}

// ------------------------------------------------------------- true positive

// reflectingServer echoes the `q` query parameter straight into the HTML
// response with no encoding — a textbook reflected-XSS sink.
func reflectingServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body>You searched for: %s</body></html>", r.URL.Query().Get("q"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestXSSReflected_VulnerableEndpointProducesAFinding(t *testing.T) {
	srv := reflectingServer(t)
	target := endpointFor(srv, "/search", queryParam("q"))

	findings, err := runXSS(t, target)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 — the endpoint reflects the marker unescaped", len(findings))
	}

	f := findings[0]
	if f.ID != "q" {
		t.Errorf("ID = %q, want the parameter name", f.ID)
	}
	if f.Evidence.StatusCode != http.StatusOK {
		t.Errorf("Evidence.StatusCode = %d, want 200", f.Evidence.StatusCode)
	}
	if !strings.Contains(f.Evidence.ResponseSnippet, "reflected unescaped") {
		t.Errorf("Evidence.ResponseSnippet = %q, want it to say the marker was reflected unescaped", f.Evidence.ResponseSnippet)
	}
}

// CapturedRequest must be exactly what internal/attack's xss-reflected
// confirmer needs: Method/URL to replay, InjectedParam by name, and Payload
// as the literal string that was actually substituted into the request —
// byte-for-byte, since the confirmer finds it later as a substring.
func TestXSSReflected_CapturedRequestMatchesWhatWasSent(t *testing.T) {
	srv := reflectingServer(t)
	target := endpointFor(srv, "/search", queryParam("q"))

	findings, err := runXSS(t, target)
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
	if req.InjectedParam != "q" {
		t.Errorf("Request.InjectedParam = %q, want q", req.InjectedParam)
	}
	if req.Payload == "" {
		t.Fatal("Request.Payload is empty — attack has nothing to replay")
	}
	if !strings.HasPrefix(req.Payload, "<xssscan-") {
		t.Errorf("Request.Payload = %q, want it to start with the marker template's prefix", req.Payload)
	}

	// The captured URL must be the exact request that produced the finding:
	// its query value, decoded, must equal Payload byte-for-byte — this is
	// the invariant internal/attack/request.go's withInjectedValue depends
	// on to find and replace the old value later.
	parsed, err := url.Parse(req.URL)
	if err != nil {
		t.Fatalf("parsing Request.URL: %v", err)
	}
	if got := parsed.Query().Get("q"); got != req.Payload {
		t.Errorf("Request.URL carries q=%q, want it to equal Request.Payload %q byte-for-byte", got, req.Payload)
	}
}

// ------------------------------------------------------------ false positive

// escapingServer HTML-escapes the parameter before echoing it — the report
// must not treat "reflected but safely encoded" as a finding.
func escapingServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		escaped := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;", "'", "&#39;").Replace(q)
		fmt.Fprintf(w, "<html><body>You searched for: %s</body></html>", escaped)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// This is the test that proves there is no false positive: a parameter that
// is reflected, but always safely, must never produce a Finding.
func TestXSSReflected_EscapedReflectionProducesNoFinding(t *testing.T) {
	srv := escapingServer(t)
	target := endpointFor(srv, "/search", queryParam("q"))

	findings, err := runXSS(t, target)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0 — the endpoint HTML-escapes the parameter before reflecting it: %+v", len(findings), findings)
	}
}

func TestXSSReflected_NoReflectionAtAllProducesNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html><body>nothing to see here</body></html>")
	}))
	t.Cleanup(srv.Close)

	target := endpointFor(srv, "/search", queryParam("q"))
	findings, err := runXSS(t, target)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

// --------------------------------------------------------------- edge cases

func TestXSSReflected_SkipsWithoutABaseline(t *testing.T) {
	target := model.Target{
		Endpoint:    model.Endpoint{Method: http.MethodGet, Path: "/search", Parameters: []model.Parameter{queryParam("q")}},
		BaselineErr: fmt.Errorf("collection failed"),
	}

	findings, err := runXSS(t, target)
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
	if !errors.Is(err, model.ErrSkipped) {
		t.Errorf("Run() error = %v, want a Skippedf error", err)
	}
}

func TestXSSReflected_NoInjectableParametersProducesNoFindings(t *testing.T) {
	srv := reflectingServer(t)
	target := endpointFor(srv, "/search")

	findings, err := runXSS(t, target)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0 — no injectable parameters", len(findings))
	}
}

func TestXSSReflected_UnreachableTargetIsSkipped(t *testing.T) {
	target := model.Target{
		Endpoint: model.Endpoint{Method: http.MethodGet, Path: "/search", Parameters: []model.Parameter{queryParam("q")}},
		Baseline: &model.Response{URL: "http://127.0.0.1:1/search"},
	}

	findings, err := runXSS(t, target)
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
	if !errors.Is(err, model.ErrSkipped) {
		t.Errorf("Run() error = %v, want a Skippedf error", err)
	}
}

// -------------------------------------------------------------- payload file

func TestXSSPayloadFileIsWellFormed(t *testing.T) {
	templates := mustParseMarkerTemplates(xssPayloadsFile)
	if len(templates) == 0 {
		t.Fatal("no marker templates parsed from the embedded payloads/xss.txt")
	}
	for _, tmpl := range templates {
		if tmpl.name == "" {
			t.Error("a template has an empty name")
		}
		if tmpl.prefix == "" && tmpl.suffix == "" {
			t.Errorf("template %q has both prefix and suffix empty", tmpl.name)
		}
	}
}

func TestMustParseMarkerTemplates_RejectsMalformedLines(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"missing separator", "onlyname\n"},
		{"empty name", " ||| < ||| >\n"},
		{"empty prefix and suffix", "name |||  |||  \n"},
		{"duplicate name", "dup ||| < ||| >\ndup ||| ( ||| )\n"},
		{"no templates at all", "# just a comment\n\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("mustParseMarkerTemplates() did not panic")
				}
			}()
			mustParseMarkerTemplates(tt.content)
		})
	}
}

func TestMustParseMarkerTemplates_SkipsCommentsAndBlankLines(t *testing.T) {
	got := mustParseMarkerTemplates("# comment\n\nreal ||| < ||| >\n")
	if len(got) != 1 || got[0].name != "real" {
		t.Errorf("got %+v, want a single template named %q", got, "real")
	}
}

func TestMarkerValue_DeterministicButDistinctPerInjectionPoint(t *testing.T) {
	ep := model.Endpoint{Method: "GET", Path: "/search"}
	tmpl := xssMarkerTemplate{name: "angle-bracket-tag", prefix: "<xssscan-", suffix: ">"}
	q := queryParam("q")
	name := queryParam("name")

	// Determinism: the same injection point yields the same marker every
	// call — this is what keeps findings.json byte-identical across scans.
	first := markerValue(ep, q, tmpl)
	second := markerValue(ep, q, tmpl)
	if first != second {
		t.Errorf("markerValue is not stable for the same injection point: %q vs %q", first, second)
	}

	// Distinctness: a different parameter (or endpoint, or template) yields
	// a different marker, so two findings never collide.
	if first == markerValue(ep, name, tmpl) {
		t.Error("markerValue collides across different parameters")
	}
	otherEP := model.Endpoint{Method: "GET", Path: "/other"}
	if first == markerValue(otherEP, q, tmpl) {
		t.Error("markerValue collides across different endpoints")
	}

	if len(first) != xssMarkerHexLen {
		t.Errorf("markerValue() = %q, want %d hex characters", first, xssMarkerHexLen)
	}
}

// The check as a whole must be deterministic: two runs against the same
// reflecting target must produce byte-identical findings (invariant #8).
func TestXSSReflected_IsDeterministicAgainstAReflectingTarget(t *testing.T) {
	srv := reflectingServer(t)
	target := endpointFor(srv, "/search", queryParam("q"))

	first, err := runXSS(t, target)
	if err != nil {
		t.Fatalf("Run() (first) error = %v", err)
	}
	second, err := runXSS(t, target)
	if err != nil {
		t.Fatalf("Run() (second) error = %v", err)
	}

	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("got %d and %d findings, want 1 each", len(first), len(second))
	}
	if first[0].Request.Payload != second[0].Request.Payload {
		t.Errorf("payload differs between runs: %q vs %q — findings.json would not be byte-identical",
			first[0].Request.Payload, second[0].Request.Payload)
	}
	if first[0].Request.URL != second[0].Request.URL {
		t.Errorf("URL differs between runs: %q vs %q", first[0].Request.URL, second[0].Request.URL)
	}
	if first[0].Evidence.ResponseSnippet != second[0].Evidence.ResponseSnippet {
		t.Errorf("evidence differs between runs — a random marker leaked into output")
	}
}
