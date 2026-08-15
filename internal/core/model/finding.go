package model

import "time"

// CapturedRequest is the complete request that produced a Finding, so the
// attack stage can reproduce it exactly.
type CapturedRequest struct {
	Method        string            `json:"method"`
	URL           string            `json:"url"`
	Headers       map[string]string `json:"headers,omitempty"`
	Body          string            `json:"body,omitempty"`
	InjectedParam string            `json:"injected_param,omitempty"`
	Payload       string            `json:"payload,omitempty"`
}

// Evidence is what a check observed, including the baseline "clean"
// response used to rule out false positives from dynamic content.
type Evidence struct {
	BaselineResponse string        `json:"baseline_response,omitempty"`
	ResponseSnippet  string        `json:"response_snippet,omitempty"`
	ResponseTime     time.Duration `json:"response_time"`
	StatusCode       int           `json:"status_code"`
}

// Finding is a single suspected (scan) or confirmed (attack) vulnerability.
type Finding struct {
	ID            string          `json:"id"`
	CheckName     string          `json:"check_name"`
	Endpoint      Endpoint        `json:"endpoint"`
	Severity      string          `json:"severity"`
	OWASPCategory string          `json:"owasp_category"`
	Request       CapturedRequest `json:"request"`
	Evidence      Evidence        `json:"evidence"`
	Confirmed     bool            `json:"confirmed"`
}

// FindingsFile is the on-disk, versioned JSON contract written by `scan`
// (as findings.json) and `attack` (as confirmed.json), and read back by
// the next stage.
type FindingsFile struct {
	SchemaVersion int       `json:"schema_version"`
	Findings      []Finding `json:"findings"`
}
