package diff

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

// Write renders the report for a human reading a terminal or a CI log.
//
// The ordering is deliberate: what got worse comes first, what got better
// second, and what stayed the same last and only as a count. A regression
// guard whose bad news is below the fold is a regression guard nobody reads.
func (r Report) Write(w io.Writer, threshold string) error {
	// Rendered into a buffer and emitted once, so a writer that fails
	// partway cannot leave half a regression report behind — and so the
	// error that matters is the one from the single write that can fail.
	var b strings.Builder
	r.render(&b, threshold)
	_, err := io.WriteString(w, b.String())
	return err
}

func (r Report) render(w *strings.Builder, threshold string) {
	sections := []struct {
		marker  string
		title   string
		note    string
		entries []model.Finding
	}{
		{"+", "new", "", r.New},
		{"?", "no longer examined", "the newer run could not look at these, so nothing about them was fixed", r.Unverified},
		{"?", "dropped from the scan", "the route left the spec, or the check was switched off", r.Dropped},
		{"-", "resolved", "gone, and the newer run did reach a verdict on that route", r.Resolved},
	}

	for _, s := range sections {
		if len(s.entries) == 0 {
			continue
		}
		fmt.Fprintf(w, "%s %d %s", s.marker, len(s.entries), s.title)
		if s.note != "" {
			fmt.Fprintf(w, " — %s", s.note)
		}
		fmt.Fprintln(w)
		for _, f := range sortFindings(s.entries) {
			fmt.Fprintf(w, "    %-8s %-24s %s %s\n", f.Severity, f.CheckName, f.Endpoint.Method, f.Endpoint.Path)
		}
		fmt.Fprintln(w)
	}

	if len(r.CoverageLost) > 0 {
		fmt.Fprintf(w, "! %d check(s) reached a verdict before and did not this time\n", len(r.CoverageLost))
		for _, e := range sortExamined(r.CoverageLost) {
			fmt.Fprintf(w, "    %-24s %s %s\n", e.Check, e.Method, e.Path)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "= %d unchanged\n", len(r.Unchanged))

	if r.Regressed(threshold) {
		fmt.Fprintf(w, "\nregressed: a new finding at %s or above, or coverage that used to exist\n", threshold)
		return
	}
	fmt.Fprintln(w, "\nno regression")
}

func sortFindings(in []model.Finding) []model.Finding {
	out := slices.Clone(in)
	slices.SortStableFunc(out, func(a, b model.Finding) int {
		return cmp.Or(
			severityRank(a.Severity)-severityRank(b.Severity),
			strings.Compare(a.Endpoint.Path, b.Endpoint.Path),
			strings.Compare(a.ID, b.ID),
		)
	})
	return out
}

func sortExamined(in []model.ExaminedCheck) []model.ExaminedCheck {
	out := slices.Clone(in)
	slices.SortStableFunc(out, func(a, b model.ExaminedCheck) int {
		return cmp.Or(
			strings.Compare(a.Path, b.Path),
			strings.Compare(a.Method, b.Method),
			strings.Compare(a.Check, b.Check),
		)
	})
	return out
}
