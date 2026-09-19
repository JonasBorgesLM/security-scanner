package report

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

// SARIF is how findings reach somewhere people already look. GitHub Code
// Scanning reads it natively, so a report that would otherwise be an HTML
// file in a CI artifact becomes annotations in the Security tab.
//
// # Where a finding is
//
// SARIF locations are usually files in a repository, and these findings are
// not in files — they are on routes of a running target. artifactLocation.uri
// takes an absolute URI, which is what this emits: the request URL that
// produced the finding. That is truthful. Pointing at a source file the
// scanner never read, to make the annotation land on a line, would not be.
//
// # Coverage survives the format
//
// Code Scanning has no concept of "could not examine", so the obvious SARIF
// writer silently drops the coverage block — and this would become the one
// output where an empty result reads as a clean target again. The gaps go
// into invocations[].toolExecutionNotifications instead, which is SARIF's
// own place for "the tool has something to say about the run rather than
// about the code".
const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
	toolName     = "security-scanner"
)

// sarifLevel maps a severity onto the three levels Code Scanning renders.
// Anything unrecognised becomes a warning rather than vanishing.
func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "low":
		return "note"
	default:
		return "warning"
	}
}

// securitySeverity is the 0-10 number GitHub sorts and filters on. It is a
// separate scale from level, and omitting it makes every finding land in
// the same bucket regardless of what this scanner concluded.
func securitySeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "9.5"
	case "high":
		return "7.5"
	case "medium":
		return "5.0"
	case "low":
		return "3.0"
	default:
		return "0.0"
	}
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations"`
	Properties  map[string]any    `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	FullDescription  sarifText      `json:"fullDescription"`
	Help             sarifText      `json:"help"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string          `json:"ruleId"`
	Level      string          `json:"level"`
	Message    sarifText       `json:"message"`
	Locations  []sarifLocation `json:"locations"`
	Properties map[string]any  `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
	LogicalLocations []sarifLogical        `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifLogical struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool                `json:"executionSuccessful"`
	Notifications       []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string    `json:"level"`
	Message sarifText `json:"message"`
}

// WriteSARIF renders the report as SARIF 2.1.0.
func (d Data) WriteSARIF(w io.Writer) error {
	results := make([]sarifResult, 0, len(d.Findings))
	for _, v := range d.Findings {
		results = append(results, resultFor(v.Finding))
	}

	log := sarifLog{
		Schema:  sarifSchema,
		Version: sarifVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           toolName,
				InformationURI: "https://github.com/JonasBorgesLM/security-scanner",
				Rules:          rulesFor(d.Findings),
			}},
			Results: results,
			Invocations: []sarifInvocation{{
				// The run itself succeeded whenever the pipeline produced a
				// file at all; what it could not examine is in the
				// notifications, not in this flag.
				ExecutionSuccessful: true,
				Notifications:       coverageNotifications(d.Coverage),
			}},
			Properties: map[string]any{
				"endpointsTotal": d.Coverage.EndpointsTotal,
				"checksRun":      d.Coverage.ChecksRun,
				"examined":       len(d.Coverage.Examined),
				"notExamined":    len(d.Coverage.Skipped),
				"failed":         len(d.Coverage.Failed),
			},
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(log)
}

func resultFor(f model.Finding) sarifResult {
	uri := f.Request.URL
	if uri == "" {
		uri = f.Endpoint.Path
	}
	return sarifResult{
		RuleID:  f.CheckName,
		Level:   sarifLevel(f.Severity),
		Message: sarifText{Text: f.Evidence.ResponseSnippet},
		Locations: []sarifLocation{{
			PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: sarifArtifact{URI: uri}},
			LogicalLocations: []sarifLogical{{
				FullyQualifiedName: f.Endpoint.Method + " " + f.Endpoint.Path,
				Kind:               "resource",
			}},
		}},
		Properties: map[string]any{
			"severity":  f.Severity,
			"owasp":     f.OWASPCategory,
			"confirmed": f.Confirmed,
		},
	}
}

// rulesFor emits one rule per check that actually produced a finding,
// sorted so the same input yields the same document.
func rulesFor(findings []findingView) []sarifRule {
	seen := map[string]model.Finding{}
	for _, v := range findings {
		if _, ok := seen[v.CheckName]; !ok {
			seen[v.CheckName] = v.Finding
		}
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	slices.Sort(names)

	rules := make([]sarifRule, 0, len(names))
	for _, name := range names {
		f := seen[name]
		rules = append(rules, sarifRule{
			ID:               name,
			Name:             name,
			ShortDescription: sarifText{Text: f.OWASPCategory},
			FullDescription:  sarifText{Text: f.OWASPCategory},
			// The remediation text is the most useful thing this tool has
			// to say, and help is where Code Scanning shows it.
			Help: sarifText{Text: recommendationFor(name)},
			Properties: map[string]any{
				"security-severity": securitySeverity(f.Severity),
				"tags":              []string{"security", f.OWASPCategory},
			},
		})
	}
	return rules
}

// coverageNotifications carries the gaps into the one place SARIF has for
// them. Without this the machine-readable output would be the only one
// where an empty result cannot be told from a clean target.
func coverageNotifications(c model.Coverage) []sarifNotification {
	out := make([]sarifNotification, 0, len(c.Skipped)+len(c.Failed))
	for _, e := range c.Skipped {
		out = append(out, sarifNotification{
			Level:   "note",
			Message: sarifText{Text: fmt.Sprintf("not examined: %s", describeUnexamined(e))},
		})
	}
	for _, e := range c.Failed {
		out = append(out, sarifNotification{
			Level:   "error",
			Message: sarifText{Text: fmt.Sprintf("failed: %s", describeUnexamined(e))},
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func describeUnexamined(e model.Unexamined) string {
	if e.Check == "" {
		return fmt.Sprintf("%s %s: %s", e.Method, e.Path, e.Reason)
	}
	return fmt.Sprintf("%s on %s %s: %s", e.Check, e.Method, e.Path, e.Reason)
}
