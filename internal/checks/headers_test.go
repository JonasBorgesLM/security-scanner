package checks

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/warden/internal/core/model"
)

// allHeaders is a fake response carrying every header the check looks for.
func allHeaders() http.Header {
	return http.Header{
		"Content-Security-Policy":   []string{"default-src 'none'"},
		"Strict-Transport-Security": []string{"max-age=31536000"},
		"X-Frame-Options":           []string{"DENY"},
		"X-Content-Type-Options":    []string{"nosniff"},
	}
}

// target builds a Target around a fake baseline response.
func target(h http.Header) model.Target {
	return model.Target{
		Endpoint: model.Endpoint{Method: "GET", Path: "/items"},
		Baseline: &model.Response{
			URL:          "http://lab.invalid:8080/items",
			StatusCode:   http.StatusOK,
			Headers:      h,
			Body:         []byte(`{"ok":true}`),
			ProbedMethod: "GET",
		},
	}
}

func runHeaders(t *testing.T, target model.Target) ([]model.Finding, error) {
	t.Helper()
	// The nil client is deliberate: a passive check must never touch it, and
	// a nil dereference here would be the loudest possible proof it did.
	return (&missingHeaders{}).Run(t.Context(), target, model.Clients{})
}

// reported lists the headers the findings name, via the discriminator the
// check sets as Finding.ID.
func reported(findings []model.Finding) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		out[i] = f.ID
	}
	return out
}

func TestMissingHeaders_Metadata(t *testing.T) {
	meta := (&missingHeaders{}).Metadata()

	if meta.Name != "missing-headers" {
		t.Errorf("Name = %q, want missing-headers", meta.Name)
	}
	if meta.OWASPCategory != "A05:2021-Security Misconfiguration" {
		t.Errorf("OWASPCategory = %q, want A05", meta.OWASPCategory)
	}
	if meta.Severity != "medium" {
		t.Errorf("Severity = %q, want medium", meta.Severity)
	}
	if meta.Kind != model.KindPassive {
		t.Errorf("Kind = %q, want passive — this check reads the collected baseline", meta.Kind)
	}
}

func TestMissingHeaders_RegisteredByInit(t *testing.T) {
	// The real registry, not an isolated one: this proves the init() in
	// headers.go actually ran, which is what makes `checks.enabled:
	// [missing-headers]` resolve at all.
	if names := Names(); !slices.Contains(names, "missing-headers") {
		t.Errorf("registered checks = %v, want missing-headers among them", names)
	}
}

// A response with none of the headers must report all four.
func TestMissingHeaders_ResponseWithoutHeaders(t *testing.T) {
	findings, err := runHeaders(t, target(http.Header{}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	want := []string{
		"Content-Security-Policy",
		"Strict-Transport-Security",
		"X-Frame-Options",
		"X-Content-Type-Options",
	}
	if got := reported(findings); !slices.Equal(got, want) {
		t.Fatalf("findings = %v, want %v", got, want)
	}

	for _, f := range findings {
		if f.Evidence.ResponseSnippet == "" {
			t.Errorf("%s: no evidence — the report needs to say why it matters", f.ID)
		}
		if !strings.Contains(f.Evidence.ResponseSnippet, f.ID) {
			t.Errorf("%s: evidence %q does not name the header", f.ID, f.Evidence.ResponseSnippet)
		}
		if f.Evidence.StatusCode != http.StatusOK {
			t.Errorf("%s: StatusCode = %d, want it carried from the baseline", f.ID, f.Evidence.StatusCode)
		}
		if f.Request.URL != "http://lab.invalid:8080/items" || f.Request.Method != "GET" {
			t.Errorf("%s: Request = %+v, want the probed request", f.ID, f.Request)
		}
		// Wall-clock in a finding that has nothing to do with timing would
		// make two identical scans produce different files.
		if f.Evidence.ResponseTime != 0 {
			t.Errorf("%s: ResponseTime = %v, want zero for a non-timing finding", f.ID, f.Evidence.ResponseTime)
		}
	}
}

// A response carrying all of them must report nothing.
func TestMissingHeaders_ResponseWithHeaders(t *testing.T) {
	findings, err := runHeaders(t, target(allHeaders()))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %v, want none when every header is present", reported(findings))
	}
}

// The interesting case is the partial one: only what is actually absent
// gets reported.
func TestMissingHeaders_ReportsOnlyTheAbsentOnes(t *testing.T) {
	tests := []struct {
		name   string
		remove []string
		want   []string
	}{
		{"only CSP missing", []string{"Content-Security-Policy"}, []string{"Content-Security-Policy"}},
		{"only HSTS missing", []string{"Strict-Transport-Security"}, []string{"Strict-Transport-Security"}},
		{"only XFO missing", []string{"X-Frame-Options"}, []string{"X-Frame-Options"}},
		{"only XCTO missing", []string{"X-Content-Type-Options"}, []string{"X-Content-Type-Options"}},
		{
			"two missing, reported in table order",
			[]string{"X-Content-Type-Options", "Content-Security-Policy"},
			[]string{"Content-Security-Policy", "X-Content-Type-Options"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := allHeaders()
			for _, name := range tt.remove {
				h.Del(name)
			}

			findings, err := runHeaders(t, target(h))
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if got := reported(findings); !slices.Equal(got, tt.want) {
				t.Errorf("findings = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMissingHeaders_PresentButEmptyCountsAsMissing(t *testing.T) {
	h := allHeaders()
	h.Set("X-Frame-Options", "")

	findings, err := runHeaders(t, target(h))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := reported(findings); !slices.Contains(got, "X-Frame-Options") {
		t.Errorf("findings = %v, want X-Frame-Options — an empty value protects nothing", got)
	}
}

func TestMissingHeaders_LookupIsCaseInsensitive(t *testing.T) {
	// http.Header.Get canonicalises, so a server answering in lower case
	// must not be reported as missing the header.
	h := http.Header{}
	h.Set("content-security-policy", "default-src 'none'")
	h.Set("strict-transport-security", "max-age=31536000")
	h.Set("x-frame-options", "DENY")
	h.Set("x-content-type-options", "nosniff")

	findings, err := runHeaders(t, target(h))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %v, want none", reported(findings))
	}
}

func TestMissingHeaders_SkipsWithoutABaseline(t *testing.T) {
	failed := model.Target{
		Endpoint:    model.Endpoint{Method: "GET", Path: "/items"},
		BaselineErr: errors.New("connection refused"),
	}

	findings, err := runHeaders(t, failed)

	// Reporting "no missing headers" here would claim the route is clean
	// when nothing was ever examined.
	if !errors.Is(err, model.ErrSkipped) {
		t.Fatalf("error = %v, want it to wrap model.ErrSkipped", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want none when there is nothing to look at", len(findings))
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error = %q, want it to relay why the baseline is missing", err)
	}
}

func TestMissingHeaders_IsDeterministic(t *testing.T) {
	h := allHeaders()
	h.Del("Content-Security-Policy")
	h.Del("X-Frame-Options")

	var first []string
	for run := range 20 {
		findings, err := runHeaders(t, target(h))
		if err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		got := reported(findings)
		if run == 0 {
			first = got
			continue
		}
		if !slices.Equal(got, first) {
			t.Fatalf("run %d = %v, differs from first run %v", run, got, first)
		}
	}
}

func TestSecurityHeaderTableIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, h := range securityHeaders {
		// Headers.Get canonicalises its argument, so a non-canonical name
		// in the table would silently never match.
		if got := http.CanonicalHeaderKey(h.name); got != h.name {
			t.Errorf("header %q is not canonical, want %q", h.name, got)
		}
		if h.why == "" {
			t.Errorf("header %q has no explanation for the report", h.name)
		}
		if seen[h.name] {
			t.Errorf("header %q listed twice — it would be reported twice", h.name)
		}
		seen[h.name] = true
	}
}

// headerTarget builds a Target whose baseline carries the given
// Content-Type and none of the security headers.
func headerTarget(contentType string) model.Target {
	h := http.Header{}
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	return model.Target{
		Endpoint: model.Endpoint{Method: http.MethodGet, Path: "/items"},
		Baseline: &model.Response{URL: "http://lab.test/items", StatusCode: 200, ProbedMethod: http.MethodGet, Headers: h},
	}
}

func severityByHeader(t *testing.T, findings []model.Finding, err error) map[string]string {
	t.Helper()
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	out := map[string]string{}
	for _, f := range findings {
		out[f.ID] = f.Severity
	}
	return out
}

// TestMissingHeaders_SeverityFollowsWhatTheResponseIs is the point of the
// change. A missing framing or script policy is an exposure on a page and a
// hardening gap on an API, and a report that grades them the same buries the
// first under a pile of the second.
//
// It downgrades rather than suppresses on purpose: OWASP recommends all four
// on API responses, and a check that stayed silent would make "no CSP
// finding" mean either "it is set" or "we decided not to look" — the same
// ambiguity the coverage block exists to prevent.
func TestMissingHeaders_SeverityFollowsWhatTheResponseIs(t *testing.T) {
	docFindings, docErr := runHeaders(t, headerTarget("text/html; charset=utf-8"))
	document := severityByHeader(t, docFindings, docErr)
	dataFindings, dataErr := runHeaders(t, headerTarget("application/json"))
	data := severityByHeader(t, dataFindings, dataErr)

	if len(document) != len(securityHeaders) || len(data) != len(securityHeaders) {
		t.Fatalf("got %d document and %d data findings, want %d each — nothing may be suppressed",
			len(document), len(data), len(securityHeaders))
	}

	for _, name := range []string{"Content-Security-Policy", "X-Frame-Options"} {
		if document[name] != "" {
			t.Errorf("%s on an HTML response has severity %q, want the check's own", name, document[name])
		}
		if data[name] != "low" {
			t.Errorf("%s on a JSON response has severity %q, want low", name, data[name])
		}
	}

	// Sniffing a JSON body into HTML is the exact attack nosniff prevents,
	// and HSTS is about transport. Neither depends on what the body is.
	for _, name := range []string{"X-Content-Type-Options", "Strict-Transport-Security"} {
		if data[name] != "" {
			t.Errorf("%s on a JSON response has severity %q, want it unchanged — it matters regardless of the body", name, data[name])
		}
	}
}

// TestMissingHeaders_ReasonExplainsTheDowngrade keeps the report useful: a
// finding marked low without saying why reads as the scanner being unsure,
// not as a judgement it made deliberately.
func TestMissingHeaders_ReasonExplainsTheDowngrade(t *testing.T) {
	findings, err := runHeaders(t, headerTarget("application/json"))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	for _, f := range findings {
		if f.ID != "Content-Security-Policy" {
			continue
		}
		if !strings.Contains(f.Evidence.ResponseSnippet, "data, not a document") {
			t.Errorf("evidence = %q, want it to say why this is a lesser finding here", f.Evidence.ResponseSnippet)
		}
		return
	}
	t.Fatal("no Content-Security-Policy finding")
}

// TestMissingHeaders_UnclassifiableContentTypeIsTreatedAsADocument pins the
// safe direction. Over-reporting a low-severity finding costs attention;
// quietly demoting a real one costs the finding.
func TestMissingHeaders_UnclassifiableContentTypeIsTreatedAsADocument(t *testing.T) {
	for _, ct := range []string{"", "not a media type", "application/vnd.acme.thing+xml"} {
		t.Run(ct, func(t *testing.T) {
			f, err := runHeaders(t, headerTarget(ct))
			got := severityByHeader(t, f, err)
			if got["Content-Security-Policy"] != "" {
				t.Errorf("severity = %q for Content-Type %q, want the check's own — an unclassifiable response must not be downgraded",
					got["Content-Security-Policy"], ct)
			}
		})
	}
}
