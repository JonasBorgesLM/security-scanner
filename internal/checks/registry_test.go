package checks

import (
	"context"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
	"github.com/JonasBorgesLM/security-scanner/internal/ports"
)

// fakeCheck is a minimal model.Check for exercising the registry.
type fakeCheck struct {
	meta model.CheckMetadata
}

var _ model.Check = (*fakeCheck)(nil)

func (f *fakeCheck) Metadata() model.CheckMetadata { return f.meta }

func (f *fakeCheck) Run(context.Context, model.Target, ports.HTTPClient) ([]model.Finding, error) {
	return nil, nil
}

func newFake(name, kind string) *fakeCheck {
	return &fakeCheck{meta: model.CheckMetadata{Name: name, Kind: kind}}
}

// isolate swaps in an empty registry for the duration of a test, so tests
// neither see each other's registrations nor whatever real checks the
// package registers from init().
func isolate(t *testing.T) {
	t.Helper()

	mu.Lock()
	saved := registry
	registry = make(map[string]model.Check)
	mu.Unlock()

	t.Cleanup(func() {
		mu.Lock()
		registry = saved
		mu.Unlock()
	})
}

// wantPanic asserts fn panics with a message containing substr.
func wantPanic(t *testing.T, substr string, fn func()) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("did not panic, want a panic mentioning %q", substr)
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("panicked with %T (%v), want a string message", r, r)
		}
		if !strings.Contains(msg, substr) {
			t.Errorf("panic = %q, want it to mention %q", msg, substr)
		}
	}()
	fn()
}

func TestRegisterCheck_RegistersAndLooksUp(t *testing.T) {
	isolate(t)

	headers := newFake("missing-headers", model.KindPassive)
	RegisterCheck(headers)

	got, ok := Get("missing-headers")
	if !ok {
		t.Fatal("Get() ok = false, want the registered check")
	}
	if got != model.Check(headers) {
		t.Error("Get() returned a different check than the one registered")
	}

	if _, ok := Get("never-registered"); ok {
		t.Error("Get() ok = true for a name that was never registered")
	}
}

func TestRegisterCheck_RejectsDuplicateName(t *testing.T) {
	isolate(t)

	RegisterCheck(newFake("sqli-boolean", model.KindActive))

	// Two checks answering to one name would make checks.enabled ambiguous
	// and silently drop one of them.
	wantPanic(t, "duplicate check name", func() {
		RegisterCheck(newFake("sqli-boolean", model.KindActive))
	})
}

func TestRegisterCheck_RejectsInvalidChecks(t *testing.T) {
	tests := []struct {
		name   string
		substr string
		check  model.Check
	}{
		{"empty name", "empty", newFake("", model.KindPassive)},
		{"unknown kind", "Kind", newFake("weird", "sideways")},
		{"missing kind", "Kind", newFake("weird", "")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolate(t)
			wantPanic(t, tt.substr, func() { RegisterCheck(tt.check) })
		})
	}
}

func TestRegisterCheck_RejectsNil(t *testing.T) {
	isolate(t)
	wantPanic(t, "nil Check", func() { RegisterCheck(nil) })
}

func TestNamesAndAll_AreSortedByName(t *testing.T) {
	isolate(t)

	// Registered out of order on purpose.
	RegisterCheck(newFake("xss-reflected", model.KindActive))
	RegisterCheck(newFake("exposed-secrets", model.KindPassive))
	RegisterCheck(newFake("missing-headers", model.KindPassive))

	want := []string{"exposed-secrets", "missing-headers", "xss-reflected"}

	names := Names()
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("Names() = %v, want %v", names, want)
	}

	all := All()
	if len(all) != len(want) {
		t.Fatalf("All() returned %d checks, want %d", len(all), len(want))
	}
	for i, name := range want {
		if got := all[i].Metadata().Name; got != name {
			t.Errorf("All()[%d] = %q, want %q", i, got, name)
		}
	}
}

func TestNamesAndAll_EmptyRegistry(t *testing.T) {
	isolate(t)

	if got := Names(); len(got) != 0 {
		t.Errorf("Names() = %v, want empty", got)
	}
	if got := All(); len(got) != 0 {
		t.Errorf("All() returned %d checks, want 0", len(got))
	}
}

func TestEnabled_ResolvesOnlyTheNamedChecks(t *testing.T) {
	isolate(t)

	RegisterCheck(newFake("missing-headers", model.KindPassive))
	RegisterCheck(newFake("exposed-secrets", model.KindPassive))
	RegisterCheck(newFake("sqli-boolean", model.KindActive))

	got, err := Enabled([]string{"sqli-boolean", "missing-headers"})
	if err != nil {
		t.Fatalf("Enabled() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("Enabled() returned %d checks, want 2", len(got))
	}

	// Name order, not the order they were listed in config.
	want := []string{"missing-headers", "sqli-boolean"}
	for i, name := range want {
		if n := got[i].Metadata().Name; n != name {
			t.Errorf("Enabled()[%d] = %q, want %q", i, n, name)
		}
	}
}

func TestEnabled_UnknownNameIsAnError(t *testing.T) {
	isolate(t)

	RegisterCheck(newFake("missing-headers", model.KindPassive))

	// A typo in config.yaml must not quietly disable a check and yield a
	// clean-looking report that simply never ran it.
	_, err := Enabled([]string{"missing-headers", "missing-headerz"})
	if err == nil {
		t.Fatal("Enabled() error = nil, want an error naming the unknown check")
	}
	if !strings.Contains(err.Error(), "missing-headerz") {
		t.Errorf("error = %q, want it to name the unknown check", err)
	}
	// The message should also help the user find the right spelling.
	if !strings.Contains(err.Error(), "missing-headers") {
		t.Errorf("error = %q, want it to list the registered checks", err)
	}
}

func TestEnabled_ReportsEveryUnknownNameAtOnce(t *testing.T) {
	isolate(t)

	RegisterCheck(newFake("missing-headers", model.KindPassive))

	_, err := Enabled([]string{"nope-one", "nope-two"})
	if err == nil {
		t.Fatal("Enabled() error = nil, want an error")
	}
	for _, name := range []string{"nope-one", "nope-two"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error = %q, want it to mention %q", err, name)
		}
	}
}

func TestEnabled_EmptyRegistrySaysSo(t *testing.T) {
	isolate(t)

	_, err := Enabled([]string{"missing-headers"})
	if err == nil {
		t.Fatal("Enabled() error = nil, want an error")
	}
	if !strings.Contains(err.Error(), "no checks are registered") {
		t.Errorf("error = %q, want it to say the registry is empty", err)
	}
}

func TestEnabled_NoNamesSelectsNothing(t *testing.T) {
	isolate(t)

	RegisterCheck(newFake("missing-headers", model.KindPassive))

	got, err := Enabled(nil)
	if err != nil {
		t.Fatalf("Enabled(nil) error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Enabled(nil) returned %d checks, want 0 — enabling nothing is not the same as enabling everything", len(got))
	}
}

func TestEnabled_DeduplicatesRepeatedNames(t *testing.T) {
	isolate(t)

	RegisterCheck(newFake("missing-headers", model.KindPassive))

	got, err := Enabled([]string{"missing-headers", "missing-headers"})
	if err != nil {
		t.Fatalf("Enabled() error = %v", err)
	}
	if len(got) != 1 {
		t.Errorf("Enabled() returned %d checks, want 1 — a name listed twice must not run the check twice", len(got))
	}
}

func TestEnabled_IsDeterministic(t *testing.T) {
	isolate(t)

	for _, name := range []string{"zulu", "alpha", "mike", "bravo"} {
		RegisterCheck(newFake(name, model.KindPassive))
	}
	names := []string{"zulu", "mike", "alpha", "bravo"}

	var first []string
	for run := range 20 {
		got, err := Enabled(names)
		if err != nil {
			t.Fatalf("Enabled() error = %v", err)
		}
		order := make([]string, len(got))
		for i, c := range got {
			order[i] = c.Metadata().Name
		}
		if run == 0 {
			first = order
			continue
		}
		if strings.Join(order, ",") != strings.Join(first, ",") {
			t.Fatalf("run %d order = %v, differs from %v", run, order, first)
		}
	}
	if strings.Join(first, ",") != "alpha,bravo,mike,zulu" {
		t.Errorf("order = %v, want alphabetical", first)
	}
}
