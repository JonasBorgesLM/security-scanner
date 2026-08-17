package model

import (
	"context"
	"errors"
	"fmt"
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

// ErrSkipped is returned by a check that could not reach a conclusion —
// most often because the baseline is missing, or because the route's auth
// failed. The engine records it as a skipped result rather than a failure,
// and it never becomes a finding.
//
// This is the machinery behind "auth failure is skipped, not vulnerable":
// a report that shows a route as clean when it was never actually examined
// is worse than one that admits it could not look.
var ErrSkipped = errors.New("check skipped")

// Skippedf builds an ErrSkipped-wrapping error explaining why a check could
// not conclude. Callers test for it with errors.Is(err, ErrSkipped).
func Skippedf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrSkipped}, args...)...)
}

// Response is a captured HTTP response, read fully into memory so several
// checks can inspect the same one without re-fetching it.
//
// It is READ-ONLY for checks. Every check running against one endpoint
// receives the same *Response — the same Headers map and the same Body
// slice — and those checks run concurrently on different workers. Reading
// is safe; writing is a data race that would also corrupt the baseline the
// other checks are comparing against. Copy before modifying.
//
// It has no JSON tags on purpose: it is in-memory plumbing between the
// engine and its checks, not part of the versioned stage-file contract.
// What reaches disk is the distilled Evidence on a Finding.
type Response struct {
	// URL is the absolute URL the baseline was fetched from, so a check can
	// reason about the scheme (HSTS is meaningless over plaintext) and a
	// finding can point at something reproducible.
	URL        string
	StatusCode int
	Headers    http.Header
	Body       []byte
	Duration   time.Duration
	// ProbedMethod is the method actually used to fetch this baseline. It
	// differs from the endpoint's own method whenever that method is not
	// safe: the collector substitutes GET rather than send a request that
	// changes state. A check that cares must consult this rather than
	// assume Endpoint.Method produced the response.
	ProbedMethod string
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
	// that needs it must return Skippedf(...) rather than treat the absence
	// as evidence of anything.
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
	// RequiresAuth marks a check that is only meaningful against an
	// authenticated route (IDOR, for instance, needs a session to abuse).
	// The engine pairs such a check only with endpoints whose own
	// RequiresAuth is set.
	RequiresAuth bool
	AppliesTo    func(Endpoint) bool
}

// Check is implemented by every vulnerability check, self-registered into
// the checks registry via init().
//
// The engine fills in Endpoint, CheckName, Severity and OWASPCategory on
// every returned Finding from the metadata the check already declared, and
// assigns a deterministic ID — so a check should not repeat any of them.
// Set Finding.ID only to distinguish several findings from one check on
// one endpoint (a header name, say); the engine namespaces whatever it is
// given.
//
// The client passed to Run is the rate-limited, scope-guarded one. A
// passive check receives a client that refuses every request, so "passive
// checks don't hit the network" is enforced rather than merely documented;
// such a check must work from t.Baseline alone.
type Check interface {
	Metadata() CheckMetadata
	Run(ctx context.Context, t Target, c ports.HTTPClient) ([]Finding, error)
}
