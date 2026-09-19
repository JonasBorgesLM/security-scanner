package diff

import (
	"bytes"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

func finding(id, check, severity, method, path string) model.Finding {
	return model.Finding{
		ID: id, CheckName: check, Severity: severity,
		Endpoint: model.Endpoint{Method: method, Path: path},
	}
}

func examined(check, method, path string) model.ExaminedCheck {
	return model.ExaminedCheck{Check: check, Method: method, Path: path}
}

func unexamined(check, method, path, reason string) model.Unexamined {
	return model.Unexamined{Check: check, Method: method, Path: path, Reason: reason}
}

func file(findings []model.Finding, cov model.Coverage) model.FindingsFile {
	return model.FindingsFile{SchemaVersion: model.SchemaVersion, Coverage: cov, Findings: findings}
}

// TestCompare_ADisappearanceIsOnlyAFixIfSomeoneLooked is the comparison
// this package exists to get right, and the one an ordinary diff gets
// wrong.
//
// Both findings are gone from the newer run. One route was examined and
// came back clean — that is a fix. The other could not be examined at all,
// so its finding did not go away; the information about it did. Calling
// both "resolved" tells someone a problem was solved when nobody looked.
func TestCompare_ADisappearanceIsOnlyAFixIfSomeoneLooked(t *testing.T) {
	before := file([]model.Finding{
		finding("sqli:GET:/a:q", "sqli-boolean", "high", "GET", "/a"),
		finding("sqli:GET:/b:q", "sqli-boolean", "high", "GET", "/b"),
	}, model.Coverage{
		Examined: []model.ExaminedCheck{examined("sqli-boolean", "GET", "/a"), examined("sqli-boolean", "GET", "/b")},
	})

	after := file(nil, model.Coverage{
		Examined: []model.ExaminedCheck{examined("sqli-boolean", "GET", "/a")},
		Skipped:  []model.Unexamined{unexamined("sqli-boolean", "GET", "/b", "auth failed after re-auth")},
	})

	r := Compare(before, after)

	if len(r.Resolved) != 1 || r.Resolved[0].Endpoint.Path != "/a" {
		t.Errorf("Resolved = %v, want only /a — the route that was actually looked at", paths(r.Resolved))
	}
	if len(r.Unverified) != 1 || r.Unverified[0].Endpoint.Path != "/b" {
		t.Errorf("Unverified = %v, want /b — its finding did not go away, the information did", paths(r.Unverified))
	}
}

// TestCompare_ACheckThatLeftTheScanIsNotAFix covers the third way a finding
// vanishes: the route left the spec, or the check was switched off. Neither
// is someone fixing anything.
func TestCompare_ACheckThatLeftTheScanIsNotAFix(t *testing.T) {
	before := file([]model.Finding{finding("x:GET:/gone:1", "xss-reflected", "high", "GET", "/gone")},
		model.Coverage{Examined: []model.ExaminedCheck{examined("xss-reflected", "GET", "/gone")}})
	after := file(nil, model.Coverage{})

	r := Compare(before, after)

	if len(r.Resolved) != 0 {
		t.Errorf("Resolved = %v, want none", paths(r.Resolved))
	}
	if len(r.Dropped) != 1 {
		t.Fatalf("Dropped = %v, want the one finding whose route the newer run says nothing about", paths(r.Dropped))
	}
}

// TestCompare_NewAndUnchanged covers the ordinary halves.
func TestCompare_NewAndUnchanged(t *testing.T) {
	old := finding("a:GET:/x:1", "missing-headers", "medium", "GET", "/x")
	fresh := finding("b:GET:/y:1", "auth-required", "critical", "GET", "/y")

	r := Compare(
		file([]model.Finding{old}, model.Coverage{}),
		file([]model.Finding{old, fresh}, model.Coverage{}),
	)

	if len(r.Unchanged) != 1 || r.Unchanged[0].ID != old.ID {
		t.Errorf("Unchanged = %v, want the finding present in both", paths(r.Unchanged))
	}
	if len(r.New) != 1 || r.New[0].ID != fresh.ID {
		t.Errorf("New = %v, want the finding only the newer run has", paths(r.New))
	}
}

// TestReport_CoverageLostIsARegressionOnItsOwn is the half a findings-only
// diff cannot see. Nothing was found and nothing disappeared; the scan
// simply stopped examining something. A guard that passes on that is a
// guard that can be silenced by breaking the scanner.
func TestReport_CoverageLostIsARegressionOnItsOwn(t *testing.T) {
	before := file(nil, model.Coverage{
		Examined: []model.ExaminedCheck{examined("sqli-boolean", "GET", "/a")},
	})
	after := file(nil, model.Coverage{
		Skipped: []model.Unexamined{unexamined("sqli-boolean", "GET", "/a", "parameter was never exercised")},
	})

	r := Compare(before, after)
	if len(r.CoverageLost) != 1 {
		t.Fatalf("CoverageLost = %d, want 1", len(r.CoverageLost))
	}
	if !r.Regressed("high") {
		t.Error("Regressed = false; a run that examines less than the one before it has regressed")
	}
}

// TestReport_RegressedHonoursTheThreshold keeps the gate from failing on
// everything. A new low-severity finding is news, not a build break.
func TestReport_RegressedHonoursTheThreshold(t *testing.T) {
	r := Report{New: []model.Finding{finding("a", "c", "low", "GET", "/x")}}
	if r.Regressed("high") {
		t.Error("Regressed = true for a new low finding with the threshold at high")
	}
	if !r.Regressed("low") {
		t.Error("Regressed = false for a new low finding with the threshold at low")
	}

	critical := Report{New: []model.Finding{finding("a", "c", "critical", "GET", "/x")}}
	if !critical.Regressed("high") {
		t.Error("Regressed = false for a new critical finding — critical outranks high")
	}
}

// TestReport_WritePutsTheBadNewsFirst pins the ordering. A regression guard
// whose bad news is below the fold is a regression guard nobody reads.
func TestReport_WritePutsTheBadNewsFirst(t *testing.T) {
	r := Report{
		New:        []model.Finding{finding("n", "auth-required", "critical", "GET", "/new")},
		Resolved:   []model.Finding{finding("r", "sqli-boolean", "high", "GET", "/fixed")},
		Unverified: []model.Finding{finding("u", "xss-reflected", "high", "GET", "/blind")},
		Unchanged:  []model.Finding{finding("s", "missing-headers", "low", "GET", "/same")},
	}

	var buf bytes.Buffer
	if err := r.Write(&buf, "high"); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	out := buf.String()

	iNew := strings.Index(out, "new")
	iUnverified := strings.Index(out, "no longer examined")
	iResolved := strings.Index(out, "resolved")
	if !(iNew < iUnverified && iUnverified < iResolved) {
		t.Errorf("sections are ordered wrong:\n%s", out)
	}
	if !strings.Contains(out, "could not look at these") {
		t.Error("the unverified section does not explain what it means")
	}
	if !strings.Contains(out, "regressed") {
		t.Error("a report with a new critical finding does not say it regressed")
	}
}

func paths(in []model.Finding) []string {
	out := make([]string, len(in))
	for i, f := range in {
		out[i] = f.Endpoint.Path
	}
	return out
}
