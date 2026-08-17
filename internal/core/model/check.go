package model

import (
	"context"
	"net/http"
	"time"

	"github.com/JonasBorgesLM/security-scanner/internal/ports"
)

// Check kinds. A passive check draws its conclusions from the baseline
// response the engine already collected and issues no requests of its own;
// an active check sends crafted requests through the client it is given.
const (
	KindPassive = "passive"
	KindActive  = "active"
)

// Response is a captured HTTP response, read fully into memory so several
// checks can inspect the same one without re-fetching it.
//
// It has no JSON tags on purpose: it is in-memory plumbing between the
// engine and its checks, not part of the versioned stage-file contract.
// What reaches disk is the distilled Evidence on a Finding.
type Response struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Duration   time.Duration
}

// Target is what a check is pointed at: the endpoint plus the baseline
// response the engine collected for it up front.
//
// The single collection pass serves two purposes at once. Passive checks
// read it instead of spending a request, and active checks compare their
// crafted response against it rather than against a hardcoded expectation
// — which is what keeps dynamic content (timestamps, CSRF tokens) from
// turning into false positives.
type Target struct {
	Endpoint Endpoint
	// Baseline is nil when collection failed; BaselineErr says why. A check
	// that needs it must treat nil as "cannot conclude" and return no
	// findings, never as evidence of a problem.
	Baseline    *Response
	BaselineErr error
}

// CheckMetadata describes a check for registry lookup and engine
// scheduling — never serialized, so it carries no JSON tags.
type CheckMetadata struct {
	Name          string
	OWASPCategory string
	Severity      string
	Kind          string // KindPassive | KindActive
	RequiresAuth  bool
	AppliesTo     func(Endpoint) bool
}

// Check is implemented by every vulnerability check, self-registered into
// the checks registry via init().
//
// The client passed to Run is the rate-limited, scope-guarded one. A
// passive check receives a client that refuses every request, so "passive
// checks don't hit the network" is enforced rather than merely documented;
// such a check must work from t.Baseline alone.
type Check interface {
	Metadata() CheckMetadata
	Run(ctx context.Context, t Target, c ports.HTTPClient) ([]Finding, error)
}
