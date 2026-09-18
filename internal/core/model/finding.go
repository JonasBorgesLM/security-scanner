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
	BaselineResponse string `json:"baseline_response,omitempty"`
	ResponseSnippet  string `json:"response_snippet,omitempty"`
	// ResponseTime is measurement noise for most checks and must be left
	// zero unless the finding is actually about timing (a time-based
	// injection, say). Wall-clock values differ between runs, and
	// findings.json has to be byte-identical across two scans of an
	// unchanged target for git diff to be a useful review tool.
	ResponseTime time.Duration `json:"response_time,omitempty"`
	StatusCode   int           `json:"status_code"`
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

// Unexamined is one route-and-check pair the scanner could not draw a
// conclusion about, and why.
//
// It is deliberately not a Finding: a route that could not be examined is
// the absence of information, and folding it in among findings would make
// "we looked and found nothing" and "we could not look" the same shape
// again — which is what this type exists to prevent.
//
// Check is empty for something decided before any check ran, such as an
// endpoint held back by the non-destructive gate.
type Unexamined struct {
	Check  string `json:"check,omitempty"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// ExaminedCheck is one check that ran against one route and reached a
// verdict — whether or not that verdict was a finding.
//
// It carries no reason, and that is the whole difference from Unexamined:
// a gap has to explain itself, a completed check has nothing to explain.
// Two small types rather than one with a field that is meaningless in half
// its uses.
type ExaminedCheck struct {
	Check  string `json:"check"`
	Method string `json:"method"`
	Path   string `json:"path"`
}

// Coverage accounts for what a stage actually managed to examine.
//
// Without it a scan that reached nothing and a scan of a clean target
// produce the same file: an empty findings list. That is not a reporting
// nicety — it makes every downstream judgement wrong in the same
// direction, because "no findings" reads as "no problems" and a regression
// guard comparing two such files reports a route that merely went
// unexamined as one that was fixed.
//
// Counts and lists are both present on purpose: the counts answer "was
// this scan meaningful at all?" at a glance, the lists answer "what
// exactly did it miss?" without which the counts are just a worrying
// number.
type Coverage struct {
	// EndpointsTotal is every operation the spec declared, including those
	// no check ever ran against.
	EndpointsTotal int `json:"endpoints_total"`
	// ChecksRun is how many check-against-endpoint pairs were executed,
	// whatever their outcome.
	ChecksRun int `json:"checks_run"`
	// Examined is every check that reached a verdict. Listing the routes
	// that came back clean is what lets a reader answer "what happened to
	// this route?" by looking, instead of subtracting the gaps from
	// EndpointsTotal and hoping the remainder means what they think.
	//
	// The three lists close: len(Examined) + the check-level entries in
	// Skipped + len(Failed) == ChecksRun. Skipped also holds endpoint-level
	// entries, decided before any check was scheduled, which are not check
	// runs and so are not in that sum.
	Examined []ExaminedCheck `json:"examined"`
	// Skipped is everything that could not be concluded: a check that
	// declined, or an endpoint held back before any check ran.
	Skipped []Unexamined `json:"skipped"`
	// Failed is everything that errored. Never evidence of a
	// vulnerability — only of a scan that did not finish its job.
	Failed []Unexamined `json:"failed"`
}

// FindingsFile is the on-disk, versioned JSON contract written by `scan`
// (as findings.json) and `attack` (as confirmed.json), and read back by
// the next stage.
//
// Coverage travels with the findings rather than in a file beside them so
// the two cannot drift apart, and so no stage can be handed findings
// without also being handed the account of what produced them.
type FindingsFile struct {
	SchemaVersion int       `json:"schema_version"`
	Coverage      Coverage  `json:"coverage"`
	Findings      []Finding `json:"findings"`
}
