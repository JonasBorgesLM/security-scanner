package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

// exampleFindings mirrors what confirmed.json actually contains: a mix of
// severities, confirmed and unconfirmed, one carrying content an attacker
// could have influenced (an XSS marker in a response snippet) that must
// come out escaped rather than executable.
func exampleFindings() []model.Finding {
	return []model.Finding{
		{
			ID:            "sqli-boolean:/items:q",
			CheckName:     "sqli-boolean",
			Endpoint:      model.Endpoint{Method: "GET", Path: "/items"},
			Severity:      "high",
			OWASPCategory: "A03:2021-Injection",
			Confirmed:     true,
			Request: model.CapturedRequest{
				Method:        "GET",
				URL:           "http://lab.invalid/items?q=1%27%3D%271",
				InjectedParam: "q",
				Payload:       "1'='1",
			},
			Evidence: model.Evidence{
				StatusCode:      200,
				ResponseSnippet: "reproduced: true/false response-length difference is 812 bytes against a 4-byte noise floor",
			},
		},
		{
			ID:            "xss-reflected:/search:term",
			CheckName:     "xss-reflected",
			Endpoint:      model.Endpoint{Method: "GET", Path: "/search"},
			Severity:      "medium",
			OWASPCategory: "A03:2021-Injection",
			Confirmed:     false,
			Request: model.CapturedRequest{
				Method:        "GET",
				URL:           "http://lab.invalid/search?term=%3Cscript%3Emarker%3C%2Fscript%3E",
				InjectedParam: "term",
				Payload:       "<script>marker</script>",
			},
			Evidence: model.Evidence{
				StatusCode:      200,
				ResponseSnippet: "marker not reflected in response body: <script>marker</script>",
			},
		},
		{
			ID:            "missing-headers:/health:hsts",
			CheckName:     "missing-headers",
			Endpoint:      model.Endpoint{Method: "GET", Path: "/health"},
			Severity:      "medium",
			OWASPCategory: "A05:2021-Security Misconfiguration",
			Confirmed:     true,
			Evidence: model.Evidence{
				StatusCode:       200,
				BaselineResponse: `{"ok":true}`,
				ResponseSnippet:  "missing header: Strict-Transport-Security",
			},
		},
		{
			ID:            "exposed-secrets:/debug:body",
			CheckName:     "exposed-secrets",
			Endpoint:      model.Endpoint{Method: "GET", Path: "/debug"},
			Severity:      "critical",
			OWASPCategory: "A02:2021-Cryptographic Failures",
			Confirmed:     true,
			Evidence: model.Evidence{
				StatusCode:      200,
				ResponseSnippet: "found pattern aws-secret-key: AKIA****REDACTED****",
			},
		},
	}
}

func TestBuild_SummarisesBySeverity(t *testing.T) {
	data := Build(exampleFindings(), model.Coverage{})

	if data.Summary.TotalFindings != 4 {
		t.Fatalf("TotalFindings = %d, want 4", data.Summary.TotalFindings)
	}
	if data.Summary.TotalConfirmed != 3 {
		t.Fatalf("TotalConfirmed = %d, want 3", data.Summary.TotalConfirmed)
	}

	want := []string{"critical", "high", "medium"}
	if len(data.Summary.BySeverity) != len(want) {
		t.Fatalf("BySeverity = %+v, want %d rows", data.Summary.BySeverity, len(want))
	}
	for i, sev := range want {
		if data.Summary.BySeverity[i].Severity != sev {
			t.Errorf("BySeverity[%d].Severity = %q, want %q", i, data.Summary.BySeverity[i].Severity, sev)
		}
	}
	// medium has two findings, one confirmed (missing-headers) and one not
	// (xss-reflected).
	for _, row := range data.Summary.BySeverity {
		if row.Severity == "medium" {
			if row.Total != 2 || row.Confirmed != 1 {
				t.Errorf("medium row = %+v, want Total=2 Confirmed=1", row)
			}
		}
	}
}

func TestBuild_OrdersMostSevereAndConfirmedFirst(t *testing.T) {
	data := Build(exampleFindings(), model.Coverage{})

	if len(data.Findings) != 4 {
		t.Fatalf("got %d findings, want 4", len(data.Findings))
	}
	if data.Findings[0].CheckName != "exposed-secrets" {
		t.Errorf("Findings[0] = %s, want exposed-secrets (critical)", data.Findings[0].CheckName)
	}
	if data.Findings[1].CheckName != "sqli-boolean" {
		t.Errorf("Findings[1] = %s, want sqli-boolean (high)", data.Findings[1].CheckName)
	}
	// Both remaining are medium: confirmed (missing-headers) must sort
	// before unconfirmed (xss-reflected).
	if data.Findings[2].CheckName != "missing-headers" || !data.Findings[2].Confirmed {
		t.Errorf("Findings[2] = %+v, want confirmed missing-headers", data.Findings[2])
	}
	if data.Findings[3].CheckName != "xss-reflected" || data.Findings[3].Confirmed {
		t.Errorf("Findings[3] = %+v, want unconfirmed xss-reflected", data.Findings[3])
	}
}

func TestBuild_UnknownCheckGetsDefaultRecommendation(t *testing.T) {
	data := Build([]model.Finding{{CheckName: "some-future-check", Severity: "low"}}, model.Coverage{})
	if data.Findings[0].Recommendation != defaultRecommendation {
		t.Errorf("Recommendation = %q, want the default fallback", data.Findings[0].Recommendation)
	}
}

func TestBuild_UnknownSeveritySortsLastAndGetsUnknownClass(t *testing.T) {
	data := Build([]model.Finding{
		{ID: "b", CheckName: "x", Severity: "low"},
		{ID: "a", CheckName: "x", Severity: "totally-made-up"},
	}, model.Coverage{})
	if got := data.Findings[0].Severity; got != "low" {
		t.Fatalf("Findings[0].Severity = %q, want low to sort before an unrecognised severity", got)
	}
	if got := data.Findings[1].SeverityClass; got != "unknown" {
		t.Errorf("SeverityClass = %q, want unknown", got)
	}
}

// Two findings that tie on severity and confirmed status must still sort
// deterministically, by check name, then endpoint path, then ID — the
// documented tie-break order Build relies on for byte-identical output.
func TestBuild_TieBreaksOnCheckNameThenPathThenID(t *testing.T) {
	data := Build([]model.Finding{
		{ID: "id-2", CheckName: "sqli-boolean", Endpoint: model.Endpoint{Path: "/b"}, Severity: "high"},
		{ID: "id-1", CheckName: "sqli-boolean", Endpoint: model.Endpoint{Path: "/a"}, Severity: "high"},
		{ID: "id-1", CheckName: "missing-headers", Endpoint: model.Endpoint{Path: "/a"}, Severity: "high"},
	}, model.Coverage{})

	got := []string{
		data.Findings[0].CheckName + " " + data.Findings[0].Endpoint.Path,
		data.Findings[1].CheckName + " " + data.Findings[1].Endpoint.Path,
		data.Findings[2].CheckName + " " + data.Findings[2].Endpoint.Path,
	}
	want := []string{"missing-headers /a", "sqli-boolean /a", "sqli-boolean /b"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("order[%d] = %q, want %q (full order: %v)", i, got[i], want[i], got)
		}
	}
}

func TestBuild_IsDeterministic(t *testing.T) {
	a := Build(exampleFindings(), model.Coverage{})
	b := Build(exampleFindings(), model.Coverage{})

	var bufA, bufB bytes.Buffer
	if err := a.WriteJSON(&bufA); err != nil {
		t.Fatalf("WriteJSON (a) error = %v", err)
	}
	if err := b.WriteJSON(&bufB); err != nil {
		t.Fatalf("WriteJSON (b) error = %v", err)
	}
	if bufA.String() != bufB.String() {
		t.Fatalf("two Build(, model.Coverage{}) calls over identical input produced different JSON")
	}
}

func TestWriteHTML_GeneratesWithoutError(t *testing.T) {
	data := Build(exampleFindings(), model.Coverage{})

	var buf bytes.Buffer
	if err := data.WriteHTML(&buf); err != nil {
		t.Fatalf("WriteHTML() error = %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "<html") {
		t.Error("output does not look like HTML")
	}
	if !strings.Contains(out, "sqli-boolean") {
		t.Error("output missing a known check name")
	}
	if !strings.Contains(out, "A03:2021-Injection") {
		t.Error("output missing an OWASP category")
	}
}

func TestWriteHTML_EscapesAttackerControlledContent(t *testing.T) {
	// The xss-reflected finding's payload and evidence both contain a raw
	// <script> tag. html/template must escape it — a report that executes
	// the very payload it is reporting on would itself be an XSS sink.
	data := Build(exampleFindings(), model.Coverage{})

	var buf bytes.Buffer
	if err := data.WriteHTML(&buf); err != nil {
		t.Fatalf("WriteHTML() error = %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "<script>marker</script>") {
		t.Fatal("raw <script> tag leaked into report HTML unescaped")
	}
	if !strings.Contains(out, "&lt;script&gt;marker&lt;/script&gt;") {
		t.Error("expected the payload to appear HTML-escaped somewhere in the report")
	}
}

func TestWriteHTML_EmptyFindingsStillRenders(t *testing.T) {
	data := Build(nil, model.Coverage{})

	var buf bytes.Buffer
	if err := data.WriteHTML(&buf); err != nil {
		t.Fatalf("WriteHTML() error = %v", err)
	}
	if !strings.Contains(buf.String(), "No findings") {
		t.Error("expected an explicit empty-state message, not a silently blank section")
	}
}

func TestWriteJSON_RoundTripsSchema(t *testing.T) {
	data := Build(exampleFindings(), model.Coverage{})

	var buf bytes.Buffer
	if err := data.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON() error = %v", err)
	}

	var decoded jsonFile
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if decoded.SchemaVersion != model.SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", decoded.SchemaVersion, model.SchemaVersion)
	}
	if len(decoded.Findings) != 4 {
		t.Errorf("got %d findings in report.json, want 4", len(decoded.Findings))
	}
	if decoded.Summary.TotalFindings != 4 || decoded.Summary.TotalConfirmed != 3 {
		t.Errorf("Summary = %+v, want TotalFindings=4 TotalConfirmed=3", decoded.Summary)
	}
	// Findings in report.json follow the same severity-first order as the
	// HTML, not the original scan order.
	if decoded.Findings[0].CheckName != "exposed-secrets" {
		t.Errorf("Findings[0] = %s, want exposed-secrets first (critical)", decoded.Findings[0].CheckName)
	}
}

// TestWriteHTML_EmptyFindingsWithCoverageDoesNotClaimClean is the report
// half of the reason the coverage block exists. Before it, a scan that
// reached nothing and a scan of a healthy target rendered the same page:
// "No findings." The reader had no way to tell an earned clean bill of
// health from an unearned one, and the unearned reading is the dangerous
// one — so an empty findings list must say which it is.
func TestWriteHTML_EmptyFindingsWithCoverageDoesNotClaimClean(t *testing.T) {
	coverage := model.Coverage{
		EndpointsTotal: 3,
		ChecksRun:      2,
		Skipped: []model.Unexamined{
			{Check: "sqli-boolean", Method: "GET", Path: "/items", Reason: "auth failed after re-auth"},
			{Method: "DELETE", Path: "/items/{id}", Reason: "endpoint is destructive; engine.test_destructive is not set"},
		},
	}

	var buf bytes.Buffer
	if err := Build(nil, coverage).WriteHTML(&buf); err != nil {
		t.Fatalf("WriteHTML() error = %v", err)
	}
	html := buf.String()

	if strings.Contains(html, "No findings, and nothing went unexamined") {
		t.Error("report claims nothing went unexamined while coverage lists two entries")
	}
	for _, want := range []string{
		"not a clean bill of health",
		"sqli-boolean",
		"auth failed after re-auth",
		"/items/{id}",
		"engine.test_destructive is not set",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("report does not mention %q", want)
		}
	}
}

// TestWriteHTML_EmptyFindingsAndEmptyCoverageMayClaimClean is the control
// for the test above: when nothing went unexamined, the report is allowed
// to say so plainly. A caveat on every empty report would be as useless as
// none at all.
func TestWriteHTML_EmptyFindingsAndEmptyCoverageMayClaimClean(t *testing.T) {
	var buf bytes.Buffer
	if err := Build(nil, model.Coverage{EndpointsTotal: 3, ChecksRun: 6}).WriteHTML(&buf); err != nil {
		t.Fatalf("WriteHTML() error = %v", err)
	}
	if html := buf.String(); !strings.Contains(html, "nothing went unexamined") {
		t.Error("report with no findings and no gaps does not state the clean result plainly")
	}
}

// TestWriteHTML_CoverageReasonIsInertText guards the same property the
// findings already rely on: a reason string can carry whatever the target
// put in an error message, and it must render as text, never as markup.
func TestWriteHTML_CoverageReasonIsInertText(t *testing.T) {
	coverage := model.Coverage{
		Skipped: []model.Unexamined{
			{Check: "x", Method: "GET", Path: "/p", Reason: `<script>alert(1)</script>`},
		},
	}

	var buf bytes.Buffer
	if err := Build(nil, coverage).WriteHTML(&buf); err != nil {
		t.Fatalf("WriteHTML() error = %v", err)
	}
	if html := buf.String(); strings.Contains(html, "<script>alert(1)</script>") {
		t.Error("a coverage reason rendered as live markup; it must be escaped like every other target-influenced string")
	}
}

// TestWriteJSON_CarriesCoverage pins that report.json says the same thing
// the HTML does — it is the machine-readable half of the same report, and
// a gate reading it must see the gaps too.
func TestWriteJSON_CarriesCoverage(t *testing.T) {
	coverage := model.Coverage{
		EndpointsTotal: 7,
		ChecksRun:      11,
		Failed:         []model.Unexamined{{Check: "xss-reflected", Method: "GET", Path: "/q", Reason: "connection refused"}},
	}

	var buf bytes.Buffer
	if err := Build(nil, coverage).WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON() error = %v", err)
	}

	var got struct {
		Coverage model.Coverage `json:"coverage"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.Coverage.EndpointsTotal != 7 || got.Coverage.ChecksRun != 11 {
		t.Errorf("coverage counts = %+v, want 7 endpoints / 11 checks", got.Coverage)
	}
	if len(got.Coverage.Failed) != 1 || got.Coverage.Failed[0].Check != "xss-reflected" {
		t.Errorf("coverage.failed = %+v, want the one failed check", got.Coverage.Failed)
	}
}

// TestWriteHTML_NamesTheRoutesThatCameBackClean pins the report half of the
// same gap: a reader must be able to see that a route was looked at, not
// deduce it from the route's absence everywhere else.
func TestWriteHTML_NamesTheRoutesThatCameBackClean(t *testing.T) {
	coverage := model.Coverage{
		EndpointsTotal: 2,
		ChecksRun:      2,
		Examined: []model.ExaminedCheck{
			{Check: "missing-headers", Method: "GET", Path: "/health"},
		},
		Skipped: []model.Unexamined{
			{Check: "missing-headers", Method: "POST", Path: "/items", Reason: "baseline collected with GET"},
		},
	}

	var buf bytes.Buffer
	if err := Build(nil, coverage).WriteHTML(&buf); err != nil {
		t.Fatalf("WriteHTML() error = %v", err)
	}
	html := buf.String()

	for _, want := range []string{"Examined", "/health", "reached a verdict"} {
		if !strings.Contains(html, want) {
			t.Errorf("report does not mention %q", want)
		}
	}
	// The gaps must not have been displaced by the new section.
	if !strings.Contains(html, "Not examined") || !strings.Contains(html, "/items") {
		t.Error("the not-examined table was lost when the examined one arrived")
	}
}
