// Package attack implements the `attack` pipeline stage: it reads the
// suspicions scan produced and, for each one whose check registered a
// Confirmer, replays CapturedRequest with a non-destructive proof of
// concept before marking it Confirmed.
//
// A suspicion is not evidence. findings.json is the output of pattern
// matching and statistical noise comparison — both can be wrong. attack
// exists to close that gap without ever crossing into the thing the whole
// project refuses to do: mutate or destroy state on the target.
package attack

import (
	"context"
	"fmt"
	"sync"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
	"github.com/JonasBorgesLM/security-scanner/internal/ports"
)

// Confirmer attempts a non-destructive proof of concept for one check's
// findings. Confirm returns the Finding as it should be written to
// confirmed.json: Confirmed set according to what the PoC actually showed,
// Evidence and Request updated if the PoC produced something more useful
// than what scan captured.
//
// Confirm must not guess. A PoC that could not be attempted (network
// failure, an injection point that no longer exists) should return the
// Finding unchanged with Confirmed left false and a non-nil error
// explaining why — never Confirmed: true on anything less than an actual,
// reproduced result.
type Confirmer interface {
	// CheckName is the model.Finding.CheckName this Confirmer handles.
	CheckName() string
	Confirm(ctx context.Context, f model.Finding, client ports.HTTPClient) (model.Finding, error)
}

var (
	mu         sync.RWMutex
	confirmers = make(map[string]Confirmer)
)

// Register adds c under its CheckName. Like checks.RegisterCheck, it panics
// on a nil Confirmer, an empty name, or a name already claimed — these are
// programming errors in first-party code, not conditions to recover from at
// runtime.
func Register(c Confirmer) {
	if c == nil {
		panic("attack: Register called with a nil Confirmer")
	}
	name := c.CheckName()
	if name == "" {
		panic("attack: Register called with an empty CheckName")
	}

	mu.Lock()
	defer mu.Unlock()

	if _, exists := confirmers[name]; exists {
		panic(fmt.Sprintf("attack: duplicate confirmer for check %q", name))
	}
	confirmers[name] = c
}

// Outcome is one Finding's result from Run, plus what happened attempting
// it — kept alongside the Finding rather than folded into it, so callers
// can report on skips and failures without inventing a place to put that in
// model.Finding itself.
type Outcome struct {
	Finding model.Finding
	// Skipped explains why no PoC was attempted at all (destructive without
	// opt-in, already confirmed, no registered Confirmer for this check).
	// Empty means a Confirmer ran.
	Skipped string
	// Err is set when a Confirmer ran but could not complete (transport
	// failure, an injection point that no longer parses). It is never set
	// merely because the PoC failed to confirm the finding — that is a
	// legitimate, error-free outcome: Finding.Confirmed stays false.
	Err error
}

// Run attempts to confirm every finding in findings, in order. It does not
// parallelise across findings: attack runs against a curated,
// hand-reviewable list (the pipeline contract's whole point is that
// findings.json is reviewed before this stage runs), not the full spec, and
// each Confirmer already paces its own requests through client.
//
// A finding whose Endpoint.Destructive is true is never attempted unless
// testDestructive is set — the same non-destructive gate the engine applies
// during scan, re-enforced here because attack is a separate process run
// that cannot assume scan's decision still holds.
func Run(ctx context.Context, findings []model.Finding, client ports.HTTPClient, testDestructive bool) []Outcome {
	out := make([]Outcome, len(findings))

	for i, f := range findings {
		switch {
		case ctx.Err() != nil:
			// The caller (runAttack) checks ctx.Err() after Run returns and
			// refuses to write confirmed.json on a truncated run — this just
			// stops spending the target's time on findings that result will
			// discard, the same "gentle by design" reasoning that motivates
			// the rate limiter in the first place.
			out[i] = Outcome{Finding: f, Err: ctx.Err()}
		case f.Confirmed:
			out[i] = Outcome{Finding: f, Skipped: "already confirmed"}
		case f.Endpoint.Destructive && !testDestructive:
			out[i] = Outcome{Finding: f, Skipped: "endpoint is destructive; engine.test_destructive is not set"}
		default:
			out[i] = attemptOne(ctx, f, client)
		}
	}
	return out
}

func attemptOne(ctx context.Context, f model.Finding, client ports.HTTPClient) Outcome {
	mu.RLock()
	c, ok := confirmers[f.CheckName]
	mu.RUnlock()

	if !ok {
		return Outcome{Finding: f, Skipped: fmt.Sprintf("no PoC available for check %q", f.CheckName)}
	}

	confirmed, err := c.Confirm(ctx, f, client)
	if err != nil {
		return Outcome{Finding: f, Err: fmt.Errorf("attack: confirming %s on %s %s: %w",
			f.CheckName, f.Endpoint.Method, f.Endpoint.Path, err)}
	}
	return Outcome{Finding: confirmed}
}
