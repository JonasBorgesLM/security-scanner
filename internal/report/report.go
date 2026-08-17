// Package report renders the confirmed-findings pipeline stage into a
// human-readable HTML report and a machine-readable JSON summary. It reads
// no network state and mutates nothing — its only inputs are the
// []model.Finding the attack stage already produced.
package report

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"io"
	"slices"
	"strings"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

//go:embed template.html
var templateSource string

// tmpl is parsed once at package init: a malformed embedded template is a
// build-time programming error, not something that should surface per-run.
var tmpl = template.Must(template.New("report").Parse(templateSource))

// severityOrder ranks known severities from most to least urgent. Anything
// not listed here (a typo, a future severity the report package doesn't yet
// know about) sorts after all of these rather than being silently dropped.
var severityOrder = map[string]int{
	"critical": 0,
	"high":     1,
	"medium":   2,
	"low":      3,
}

func severityRank(s string) int {
	if r, ok := severityOrder[strings.ToLower(s)]; ok {
		return r
	}
	return len(severityOrder)
}

// severityClass maps a severity string onto a CSS class suffix. Anything
// unrecognised becomes "unknown" rather than leaking an arbitrary string
// (findings.json is attacker-adjacent data by the time it reaches report)
// into a class attribute.
func severityClass(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if _, ok := severityOrder[s]; ok {
		return s
	}
	return "unknown"
}

// recommendations gives static remediation guidance per check, kept in the
// report package rather than on model.Finding: the pipeline's JSON schema is
// a versioned contract checks and the engine populate, and remediation copy
// is presentation text that can be reworded without touching that contract.
var recommendations = map[string]string{
	"missing-headers": "Set the missing security header(s) on every response, not just this route — a shared middleware is more reliable than per-handler headers. Verify with a fresh scan afterward.",
	"exposed-secrets": "Rotate the exposed credential immediately, remove it from the response and from source, and load secrets from the environment or a secret manager instead of embedding or echoing them back to clients.",
	"sqli-boolean":    "Use parameterized queries or an ORM's bound-parameter API for this input — never concatenate user input into SQL. Apply least-privilege database credentials so a successful injection can't read more than the application itself needs.",
	"xss-reflected":   "HTML-encode this parameter before reflecting it into the response, or avoid reflecting user input as HTML entirely. A Content-Security-Policy is worthwhile defense in depth but is not a substitute for encoding at the point of output.",
}

const defaultRecommendation = "Review this finding manually and apply the fix appropriate to the underlying issue; no automated guidance is registered for this check yet."

func recommendationFor(checkName string) string {
	if r, ok := recommendations[checkName]; ok {
		return r
	}
	return defaultRecommendation
}

// SeverityCount is one row of the executive summary: how many findings of a
// given severity exist, and how many of those are confirmed rather than
// merely suspected.
type SeverityCount struct {
	Severity  string `json:"severity"`
	Total     int    `json:"total"`
	Confirmed int    `json:"confirmed"`
}

// Summary is the executive summary shown at the top of the report and
// carried into report.json alongside the findings themselves. Tagged
// snake_case to match every other field in the pipeline's JSON files
// (schema_version, check_name, owasp_category, ...) — untagged Go field
// names would serialise as PascalCase here and nowhere else in the format.
type Summary struct {
	TotalFindings  int             `json:"total_findings"`
	TotalConfirmed int             `json:"total_confirmed"`
	BySeverity     []SeverityCount `json:"by_severity"`
}

// findingView adds report-only, derived fields to a model.Finding for
// template convenience. Embedding keeps every Finding field reachable from
// the template without repeating field names here.
type findingView struct {
	model.Finding
	Recommendation string
	SeverityClass  string
}

// Data is everything the HTML template renders and, via its exported
// fields, everything report.json emits.
type Data struct {
	SchemaVersion int
	Summary       Summary
	Findings      []findingView
}

// Build computes the report's executive summary and orders findings most
// severe and most certain first — confirmed high-severity issues are what a
// reader needs to see before an unconfirmed low-severity one, regardless of
// scan order. The sort is over stable, deterministic keys only (severity,
// confirmed, check name, path, ID), so identical input always yields an
// identical Data, matching the rest of the pipeline's determinism guarantee.
func Build(findings []model.Finding) Data {
	views := make([]findingView, len(findings))
	for i, f := range findings {
		views[i] = findingView{
			Finding:        f,
			Recommendation: recommendationFor(f.CheckName),
			SeverityClass:  severityClass(f.Severity),
		}
	}

	slices.SortStableFunc(views, func(a, b findingView) int {
		if c := severityRank(a.Severity) - severityRank(b.Severity); c != 0 {
			return c
		}
		if a.Confirmed != b.Confirmed {
			if a.Confirmed {
				return -1
			}
			return 1
		}
		if c := strings.Compare(a.CheckName, b.CheckName); c != 0 {
			return c
		}
		if c := strings.Compare(a.Endpoint.Path, b.Endpoint.Path); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})

	return Data{
		SchemaVersion: model.SchemaVersion,
		Summary:       summarise(findings),
		Findings:      views,
	}
}

func summarise(findings []model.Finding) Summary {
	counts := map[string]*SeverityCount{}
	var seen []string
	totalConfirmed := 0

	for _, f := range findings {
		sev := f.Severity
		if sev == "" {
			sev = "unknown"
		}
		c, ok := counts[sev]
		if !ok {
			c = &SeverityCount{Severity: sev}
			counts[sev] = c
			seen = append(seen, sev)
		}
		c.Total++
		if f.Confirmed {
			c.Confirmed++
			totalConfirmed++
		}
	}

	slices.SortFunc(seen, func(a, b string) int { return severityRank(a) - severityRank(b) })

	bySeverity := make([]SeverityCount, len(seen))
	for i, sev := range seen {
		bySeverity[i] = *counts[sev]
	}

	return Summary{
		TotalFindings:  len(findings),
		TotalConfirmed: totalConfirmed,
		BySeverity:     bySeverity,
	}
}

// WriteHTML renders the report as HTML via html/template, which
// context-aware-escapes every field. That matters here specifically:
// Evidence and Request carry attacker-influenced strings (injected
// payloads, reflected XSS markers, raw response snippets) that must render
// as inert text in a report a human opens in a browser, never as executable
// markup.
func (d Data) WriteHTML(w io.Writer) error {
	return tmpl.Execute(w, d)
}

// jsonFile is report.json's shape: the same executive summary the HTML
// shows, plus the findings in the same severity-first order — but as plain
// model.Finding, not the report package's internal view type, so the JSON
// output stays a clean reflection of the pipeline's own model rather than
// leaking presentation-only fields into a file other tooling might parse.
type jsonFile struct {
	SchemaVersion int             `json:"schema_version"`
	Summary       Summary         `json:"summary"`
	Findings      []model.Finding `json:"findings"`
}

// WriteJSON writes the same report data as indented JSON.
func (d Data) WriteJSON(w io.Writer) error {
	findings := make([]model.Finding, len(d.Findings))
	for i, v := range d.Findings {
		findings[i] = v.Finding
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonFile{
		SchemaVersion: d.SchemaVersion,
		Summary:       d.Summary,
		Findings:      findings,
	})
}
