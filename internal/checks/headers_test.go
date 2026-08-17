package checks

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

func headersTarget(url string, h http.Header) model.Target {
	return model.Target{
		Endpoint: model.Endpoint{Method: "GET", Path: "/items"},
		Baseline: &model.Response{
			URL:          url,
			StatusCode:   http.StatusOK,
			Headers:      h,
			ProbedMethod: "GET",
		},
	}
}

func runHeaders(t *testing.T, target model.Target) ([]model.Finding, error) {
	t.Helper()
	// The nil client is deliberate: a passive check must never touch it, and
	// a nil dereference here would be the loudest possible proof it did.
	return (&missingHeaders{}).Run(t.Context(), target, nil)
}

func foundHeaders(findings []model.Finding) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		out[i] = f.ID
	}
	return out
}

func TestMissingHeaders_Metadata(t *testing.T) {
	meta := (&missingHeaders{}).Metadata()

	if meta.Name != "missing-headers" {
		t.Errorf("Name = %q", meta.Name)
	}
	if meta.Kind != model.KindPassive {
		t.Errorf("Kind = %q, want passive — this check reads the collected baseline", meta.Kind)
	}
	if meta.OWASPCategory == "" || meta.Severity == "" {
		t.Error("metadata must carry a severity and an OWASP category for the report")
	}
}

func TestMissingHeaders_RegisteredByInit(t *testing.T) {
	// The real registry, not an isolated one: this proves the init() in
	// headers.go actually ran.
	names := Names()
	if !slicesContains(names, "missing-headers") {
		t.Errorf("registered checks = %v, want missing-headers among them", names)
	}
}

func slicesContains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

func TestMissingHeaders_ReportsAbsentHeaders(t *testing.T) {
	findings, err := runHeaders(t, headersTarget("http://lab.invalid/items", http.Header{}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	got := foundHeaders(findings)
	want := []string{"X-Content-Type-Options", "Content-Security-Policy", "Referrer-Policy"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("findings = %v, want %v", got, want)
	}

	for _, f := range findings {
		if f.Evidence.ResponseSnippet == "" {
			t.Errorf("%s: evidence is empty — the report needs to say why it matters", f.ID)
		}
		if f.Evidence.StatusCode != http.StatusOK {
			t.Errorf("%s: StatusCode = %d, want it carried from the baseline", f.ID, f.Evidence.StatusCode)
		}
		// Wall-clock in a finding that has nothing to do with timing would
		// make two identical scans produce different files.
		if f.Evidence.ResponseTime != 0 {
			t.Errorf("%s: ResponseTime = %v, want zero for a non-timing finding", f.ID, f.Evidence.ResponseTime)
		}
		if f.Request.URL != "http://lab.invalid/items" {
			t.Errorf("%s: Request.URL = %q, want the probed URL", f.ID, f.Request.URL)
		}
	}
}

func TestMissingHeaders_SilentWhenAllPresent(t *testing.T) {
	findings, err := runHeaders(t, headersTarget("https://lab.invalid/items", http.Header{
		"Strict-Transport-Security": []string{"max-age=31536000"},
		"X-Content-Type-Options":    []string{"nosniff"},
		"Content-Security-Policy":   []string{"default-src 'none'"},
		"Referrer-Policy":           []string{"no-referrer"},
	}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %v, want none when every header is present", foundHeaders(findings))
	}
}

// HSTS does nothing over plaintext; reporting it against an http:// lab
// would be noise, and a check people learn to ignore is worse than none.
func TestMissingHeaders_HSTSOnlyOverHTTPS(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		wantHSTS bool
	}{
		{"plain http", "http://lab.invalid/items", false},
		{"https", "https://lab.invalid/items", true},
		{"uppercase scheme", "HTTPS://lab.invalid/items", true},
		{"unparseable url", "://nonsense", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := runHeaders(t, headersTarget(tt.url, http.Header{}))
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			got := slicesContains(foundHeaders(findings), "Strict-Transport-Security")
			if got != tt.wantHSTS {
				t.Errorf("HSTS reported = %v, want %v for %s", got, tt.wantHSTS, tt.url)
			}
		})
	}
}

func TestMissingHeaders_SkipsWithoutABaseline(t *testing.T) {
	target := model.Target{
		Endpoint:    model.Endpoint{Method: "GET", Path: "/items"},
		BaselineErr: errors.New("connection refused"),
	}

	findings, err := runHeaders(t, target)

	// Reporting "no missing headers" here would be a lie the report has no
	// way to walk back: nothing was ever examined.
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

func TestMissingHeaders_HeaderLookupIsCaseInsensitive(t *testing.T) {
	// http.Header.Get canonicalises, so a server answering in lower case
	// must not be reported as missing the header.
	h := http.Header{}
	h.Set("x-content-type-options", "nosniff")
	h.Set("content-security-policy", "default-src 'none'")
	h.Set("referrer-policy", "no-referrer")

	findings, err := runHeaders(t, headersTarget("http://lab.invalid/items", h))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("findings = %v, want none", foundHeaders(findings))
	}
}

func TestSecurityHeaderNamesAreCanonical(t *testing.T) {
	// Headers.Get canonicalises its argument, so a non-canonical name in the
	// table would silently never match.
	for _, h := range securityHeaders {
		if got := http.CanonicalHeaderKey(h.name); got != h.name {
			t.Errorf("header %q is not canonical, want %q", h.name, got)
		}
		if h.why == "" {
			t.Errorf("header %q has no explanation for the report", h.name)
		}
	}
}
