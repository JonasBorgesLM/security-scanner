// Package diff compares two pipeline stage files and says what changed.
//
// It is what turns the scanner from a point-in-time audit into a regression
// guard, and the reason it can exist at all is that a Finding's identity is
// deterministic (see CLAUDE.md invariant 8): the same issue on the same
// route produces the same ID on every run, while the evidence around it
// moves with the target.
//
// # The comparison this package refuses to make
//
// The obvious implementation compares two findings lists and calls anything
// missing from the newer one "resolved". That is wrong, and wrong in the
// direction that matters: a finding also disappears when the route stopped
// being examined at all — auth broke, the parameter became unprobeable, a
// gate held the route back — and reporting that as a fix tells someone a
// problem went away when nobody looked at it.
//
// So a disappearance is only "resolved" when the newer run actually reached
// a verdict on that route and check. Everything else is reported as what it
// is, which is the whole point of the coverage block existing.
package diff

import (
	"fmt"
	"slices"
	"strings"

	"github.com/JonasBorgesLM/warden/internal/core/model"
)

// Report is what changed between two runs.
type Report struct {
	// New appeared in the newer run.
	New []model.Finding
	// Resolved was in the older run, is gone from the newer one, and the
	// newer run reached a verdict on that route and check. This is the only
	// category that means someone fixed something.
	Resolved []model.Finding
	// Unverified was in the older run and is gone from the newer one, but
	// the newer run could not examine that route and check. Not a fix: an
	// absence of information where there used to be information.
	Unverified []model.Finding
	// Dropped was in the older run, and the newer run has no account of
	// that route and check at all — the route left the spec, or the check
	// was switched off. Also not a fix.
	Dropped []model.Finding
	// Unchanged is present in both.
	Unchanged []model.Finding
	// CoverageLost reached a verdict in the older run and did not in the
	// newer one, whether or not a finding was attached. A scan that quietly
	// stops examining things is the failure this whole project is built
	// around, so it is reported even when nothing else changed.
	CoverageLost []model.ExaminedCheck
}

// routeCheck identifies a check running against a route, which is the unit
// coverage accounts for.
type routeCheck struct {
	check, method, path string
}

func (r routeCheck) String() string {
	return fmt.Sprintf("%s on %s %s", r.check, r.method, r.path)
}

// Compare reports what changed from before to after.
func Compare(before, after model.FindingsFile) Report {
	var r Report

	afterByID := byID(after.Findings)
	examinedAfter := examinedSet(after.Coverage)
	accountedAfter := accountedSet(after.Coverage)

	for _, f := range before.Findings {
		if _, still := afterByID[f.ID]; still {
			r.Unchanged = append(r.Unchanged, f)
			continue
		}

		rc := routeCheck{f.CheckName, f.Endpoint.Method, f.Endpoint.Path}
		switch {
		case examinedAfter[rc]:
			r.Resolved = append(r.Resolved, f)
		case accountedAfter[rc]:
			r.Unverified = append(r.Unverified, f)
		default:
			r.Dropped = append(r.Dropped, f)
		}
	}

	beforeByID := byID(before.Findings)
	for _, f := range after.Findings {
		if _, had := beforeByID[f.ID]; !had {
			r.New = append(r.New, f)
		}
	}

	for _, e := range before.Coverage.Examined {
		rc := routeCheck{e.Check, e.Method, e.Path}
		if !examinedAfter[rc] {
			r.CoverageLost = append(r.CoverageLost, e)
		}
	}

	return r
}

// Regressed reports whether anything got worse, which is what a CI gate
// should act on.
//
// Two things count, and the second is the one an ordinary diff tool would
// miss: a new finding at or above threshold, and coverage that used to
// exist and no longer does. A run that examines less than the one before it
// has regressed even when its findings list is shorter — especially then.
func (r Report) Regressed(threshold string) bool {
	for _, f := range r.New {
		if severityRank(f.Severity) <= severityRank(threshold) {
			return true
		}
	}
	return len(r.CoverageLost) > 0
}

// severityOrder mirrors the report package's ordering. It is duplicated
// rather than shared because the two answer different questions — one sorts
// a report for a human, this one decides whether a build fails — and a
// single table serving both would tie a CI policy to a presentation choice.
var severityOrder = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

func severityRank(s string) int {
	if n, ok := severityOrder[strings.ToLower(s)]; ok {
		return n
	}
	return len(severityOrder)
}

func byID(findings []model.Finding) map[string]model.Finding {
	out := make(map[string]model.Finding, len(findings))
	for _, f := range findings {
		out[f.ID] = f
	}
	return out
}

func examinedSet(c model.Coverage) map[routeCheck]bool {
	out := make(map[routeCheck]bool, len(c.Examined))
	for _, e := range c.Examined {
		out[routeCheck{e.Check, e.Method, e.Path}] = true
	}
	return out
}

// accountedSet is every route/check the run has anything to say about,
// verdict or gap. Membership means "we know what happened here"; absence
// means the pair left the scan entirely.
func accountedSet(c model.Coverage) map[routeCheck]bool {
	out := make(map[routeCheck]bool)
	for _, e := range c.Examined {
		out[routeCheck{e.Check, e.Method, e.Path}] = true
	}
	for _, e := range append(slices.Clone(c.Skipped), c.Failed...) {
		out[routeCheck{e.Check, e.Method, e.Path}] = true
	}
	return out
}
