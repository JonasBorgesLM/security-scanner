package model

import (
	"context"
	"errors"
	"fmt"
	"net/http"

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
//
// Format an underlying cause with %w, not %v. The reason reaches the
// coverage block as text either way, but only %w keeps the cause reachable
// by errors.Is — which is what lets a caller tell "auth is broken" from
// "there was no baseline" without parsing an error message.
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
	// ProbedMethod is the method actually used to fetch this baseline. It
	// differs from the endpoint's own method whenever that method is not
	// safe: the collector substitutes GET rather than send a request that
	// changes state. A check that cares must consult this rather than
	// assume Endpoint.Method produced the response.
	ProbedMethod string
}

// Probes are extra responses the collection phase gathered for one
// endpoint, alongside the baseline.
//
// They exist because Baseline is one response to one request, and some
// questions can only be answered by varying the request: a CORS policy is
// invisible until something asks with an Origin, because a correct
// implementation answers nothing without one. Collecting the variation once,
// during the pass that already runs, keeps such checks passive — the
// alternative is every one of them spending its own request.
//
// Every probe uses a safe method, so collection still creates and destroys
// nothing. A probe is nil when it was not attempted or did not come back,
// and a check that needs one must then skip rather than read the absence as
// an answer.
//
// Like Baseline, they are READ-ONLY and shared by pointer across the checks
// running concurrently on one endpoint.
type Probes struct {
	// Origin is the baseline request repeated with an Origin header, which
	// is what makes a CORS policy observable at all.
	Origin *Response
}

// ProbeOrigin is the Origin header value the origin probe sends.
//
// It is a fixed, obviously foreign origin rather than anything derived from
// the target: the question is what the target does for a site it has no
// reason to trust, and an origin resembling the target's own could be
// allowed for a legitimate reason. Being fixed also keeps whatever a check
// derives from it out of the non-deterministic pile.
//
// It lives here rather than in the engine because it is part of the
// contract between collection and the checks that read the probe — and a
// check reaching into the engine for it would invert the dependency, since
// the engine is what runs checks.
const ProbeOrigin = "https://scanner-probe.invalid"

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
	// Probes are the extra safe responses collection gathered for this
	// endpoint. See Probes for why they exist and what nil means.
	Probes Probes
	// CanCreate is the run's engine.test_creates setting, stamped here so a
	// check can see it. It rides on the Target rather than reaching the
	// check some other way because a check must be able to SAY it was held
	// back — the alternative is declining silently, which is the whole
	// class of failure stage 1 removed.
	//
	// False means: do not send a request body. Body parameters are then not
	// injectable, and a check with nothing else to inject reports a skip
	// naming the setting.
	CanCreate bool
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

// Clients are the identities a check may send requests as.
//
// Until this existed a check was handed exactly one client, and the
// Authenticator below it injected the token into everything — so a check
// had no way to ask "what does this route do for someone who is not logged
// in?". That question is the whole of auth-required, and half of idor.
//
// Both are wrapped by the SAME rate limiter, so acquiring a second identity
// does not acquire a second request budget. Gentle by design is a property
// of the target's experience, not of any one client.
//
// Default is what a check should use for everything that is not
// specifically about identity. Reaching for Anonymous by habit would mean
// scanning a protected route unauthenticated and reporting whatever the
// login wall says, which is the misattribution invariant 5 exists to stop.
type Clients struct {
	// Default is the identity the scan runs as: authenticated when the
	// config has an auth block, plain otherwise.
	Default ports.HTTPClient
	// Secondary is a second authenticated account, when config.yaml supplies
	// one. Nil otherwise, and a check that needs it must skip naming the
	// setting rather than compare a user with itself.
	Secondary ports.HTTPClient
	// SessionToken is the raw credential Default is authenticating with,
	// empty when the target needs no auth. It is here for the one check
	// that must inspect the token rather than just send it — jwt-weak. A
	// check reading it holds a live credential: keep it out of Evidence,
	// the same rule exposed-secrets follows.
	SessionToken string
	// Anonymous carries no credentials, ever. On a target with no auth
	// configured it is the same client as Default — which is harmless,
	// because a check that cares about identity only applies to endpoints
	// the spec declares as protected, and those cannot exist without an
	// auth block (cmd/scanner refuses that combination).
	Anonymous ports.HTTPClient
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
// Every client in Clients is rate-limited and scope-guarded. A passive
// check receives clients that refuse every request, so "passive checks
// don't hit the network" is enforced rather than merely documented; such a
// check must work from t.Baseline alone.
type Check interface {
	Metadata() CheckMetadata
	Run(ctx context.Context, t Target, c Clients) ([]Finding, error)
}
