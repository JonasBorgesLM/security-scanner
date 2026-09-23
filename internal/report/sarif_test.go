package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/warden/internal/core/model"
)

func renderSARIF(t *testing.T, findings []model.Finding, cov model.Coverage) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if err := Build(findings, cov).WriteSARIF(&buf); err != nil {
		t.Fatalf("WriteSARIF() error = %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("the SARIF is not valid JSON: %v", err)
	}
	return out
}

func firstRun(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	runs, ok := doc["runs"].([]any)
	if !ok || len(runs) == 0 {
		t.Fatalf("no runs in %v", doc)
	}
	return runs[0].(map[string]any)
}

// TestSARIF_CoverageSurvivesTheFormat is the property that would be lost by
// the obvious implementation.
//
// Code Scanning has no concept of "could not examine", so a SARIF writer
// that only emits results makes this the one output where an empty findings
// list cannot be told from a clean target — undoing stage 1 in the format
// that machines read. The gaps go into toolExecutionNotifications, which is
// SARIF's own place for the tool having something to say about the run.
func TestSARIF_CoverageSurvivesTheFormat(t *testing.T) {
	cov := model.Coverage{
		EndpointsTotal: 3,
		ChecksRun:      4,
		Skipped: []model.Unexamined{
			{Check: "sqli-boolean", Method: "GET", Path: "/x", Reason: "parameter was never exercised"},
			{Method: "DELETE", Path: "/y", Reason: "endpoint is destructive"},
		},
		Failed: []model.Unexamined{
			{Check: "xss-reflected", Method: "GET", Path: "/z", Reason: "connection refused"},
		},
	}

	run := firstRun(t, renderSARIF(t, nil, cov))
	inv := run["invocations"].([]any)[0].(map[string]any)
	notes, _ := inv["toolExecutionNotifications"].([]any)

	if len(notes) != 3 {
		t.Fatalf("got %d notifications, want 3 — every gap must survive", len(notes))
	}

	var text []string
	for _, n := range notes {
		text = append(text, n.(map[string]any)["message"].(map[string]any)["text"].(string))
	}
	joined := strings.Join(text, "\n")
	for _, want := range []string{"parameter was never exercised", "endpoint is destructive", "connection refused"} {
		if !strings.Contains(joined, want) {
			t.Errorf("notifications do not mention %q:\n%s", want, joined)
		}
	}

	props := run["properties"].(map[string]any)
	if props["notExamined"].(float64) != 2 || props["examined"].(float64) != 0 {
		t.Errorf("properties = %v, want the counts alongside the list", props)
	}
}

// TestSARIF_SeverityReachesBothScales covers the mapping that decides how
// Code Scanning renders and sorts a finding. level has three values;
// security-severity is the 0-10 number GitHub filters on, and omitting it
// drops every finding into the same bucket regardless of what the scanner
// concluded.
func TestSARIF_SeverityReachesBothScales(t *testing.T) {
	tests := []struct {
		severity    string
		wantLevel   string
		wantNumeric string
	}{
		{"critical", "error", "9.5"},
		{"high", "error", "7.5"},
		{"medium", "warning", "5.0"},
		{"low", "note", "3.0"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			f := model.Finding{
				ID: "x", CheckName: "auth-required", Severity: tt.severity,
				Endpoint: model.Endpoint{Method: "GET", Path: "/x"},
				Request:  model.CapturedRequest{URL: "http://lab.test/x"},
			}
			run := firstRun(t, renderSARIF(t, []model.Finding{f}, model.Coverage{}))

			got := run["results"].([]any)[0].(map[string]any)
			if got["level"] != tt.wantLevel {
				t.Errorf("level = %v, want %q", got["level"], tt.wantLevel)
			}

			rule := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)[0].(map[string]any)
			props := rule["properties"].(map[string]any)
			if props["security-severity"] != tt.wantNumeric {
				t.Errorf("security-severity = %v, want %q", props["security-severity"], tt.wantNumeric)
			}
		})
	}
}

// TestSARIF_LocationIsTheURLItActuallyProbed keeps the format truthful.
// These findings are on routes of a running target, not lines of a file.
// artifactLocation.uri accepts an absolute URI, so the request URL is the
// honest answer; pointing at a source file the scanner never read, to make
// the annotation land on a line, would not be.
func TestSARIF_LocationIsTheURLItActuallyProbed(t *testing.T) {
	f := model.Finding{
		ID: "x", CheckName: "sqli-boolean", Severity: "high",
		Endpoint: model.Endpoint{Method: "POST", Path: "/v1/tasks"},
		Request:  model.CapturedRequest{URL: "http://lab.test/v1/tasks?q=1"},
	}

	run := firstRun(t, renderSARIF(t, []model.Finding{f}, model.Coverage{}))
	loc := run["results"].([]any)[0].(map[string]any)["locations"].([]any)[0].(map[string]any)

	uri := loc["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)["uri"]
	if uri != "http://lab.test/v1/tasks?q=1" {
		t.Errorf("uri = %v, want the URL that produced the finding", uri)
	}
	logical := loc["logicalLocations"].([]any)[0].(map[string]any)
	if logical["fullyQualifiedName"] != "POST /v1/tasks" {
		t.Errorf("fullyQualifiedName = %v, want the route", logical["fullyQualifiedName"])
	}
}

// TestSARIF_RulesCarryTheRemediation puts the most useful thing this tool
// produces where Code Scanning shows it.
func TestSARIF_RulesCarryTheRemediation(t *testing.T) {
	f := model.Finding{
		ID: "x", CheckName: "auth-required", Severity: "critical",
		Endpoint: model.Endpoint{Method: "GET", Path: "/x"},
	}
	run := firstRun(t, renderSARIF(t, []model.Finding{f}, model.Coverage{}))
	rule := run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)[0].(map[string]any)

	help := rule["help"].(map[string]any)["text"].(string)
	if help != recommendationFor("auth-required") {
		t.Errorf("help = %q, want the remediation text", help)
	}
	if strings.Contains(help, "no automated guidance") {
		t.Error("the rule carries the generic fallback; the remediation guard should have caught that")
	}
}

// TestSARIF_IsDeterministic pins the same property every stage file has:
// identical input, identical bytes, so a committed SARIF can be diffed.
func TestSARIF_IsDeterministic(t *testing.T) {
	findings := []model.Finding{
		{ID: "b", CheckName: "xss-reflected", Severity: "high", Endpoint: model.Endpoint{Method: "GET", Path: "/b"}},
		{ID: "a", CheckName: "auth-required", Severity: "critical", Endpoint: model.Endpoint{Method: "GET", Path: "/a"}},
	}
	cov := model.Coverage{Skipped: []model.Unexamined{{Check: "c", Method: "GET", Path: "/c", Reason: "r"}}}

	var first, second bytes.Buffer
	if err := Build(findings, cov).WriteSARIF(&first); err != nil {
		t.Fatalf("WriteSARIF() error = %v", err)
	}
	if err := Build(findings, cov).WriteSARIF(&second); err != nil {
		t.Fatalf("WriteSARIF() error = %v", err)
	}
	if first.String() != second.String() {
		t.Error("two renderings of the same report differ")
	}
}
