package attack

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
	"github.com/JonasBorgesLM/security-scanner/internal/ports"
)

// fakeConfirmer is a minimal Confirmer for exercising Run/Register without
// depending on the real sqli/xss confirmers.
type fakeConfirmer struct {
	name string
	fn   func(ctx context.Context, f model.Finding, c ports.HTTPClient) (model.Finding, error)
}

func (f fakeConfirmer) CheckName() string { return f.name }

func (f fakeConfirmer) Confirm(ctx context.Context, finding model.Finding, c ports.HTTPClient) (model.Finding, error) {
	return f.fn(ctx, finding, c)
}

// isolate swaps in an empty confirmer registry for the duration of a test,
// mirroring internal/checks' registry_test.go isolate helper.
func isolate(t *testing.T) {
	t.Helper()
	mu.Lock()
	saved := confirmers
	confirmers = make(map[string]Confirmer)
	mu.Unlock()

	t.Cleanup(func() {
		mu.Lock()
		confirmers = saved
		mu.Unlock()
	})
}

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

func TestRegister_RejectsInvalid(t *testing.T) {
	isolate(t)
	wantPanic(t, "nil Confirmer", func() { Register(nil) })
}

func TestRegister_RejectsEmptyName(t *testing.T) {
	isolate(t)
	wantPanic(t, "empty CheckName", func() {
		Register(fakeConfirmer{name: ""})
	})
}

func TestRegister_RejectsDuplicateName(t *testing.T) {
	isolate(t)
	Register(fakeConfirmer{name: "dup", fn: noopConfirm})
	wantPanic(t, `duplicate confirmer for check "dup"`, func() {
		Register(fakeConfirmer{name: "dup", fn: noopConfirm})
	})
}

func noopConfirm(_ context.Context, f model.Finding, _ ports.HTTPClient) (model.Finding, error) {
	return f, nil
}

func TestRun_DispatchesByCheckName(t *testing.T) {
	isolate(t)

	var got model.Finding
	Register(fakeConfirmer{
		name: "widget-check",
		fn: func(_ context.Context, f model.Finding, _ ports.HTTPClient) (model.Finding, error) {
			got = f
			f.Confirmed = true
			return f, nil
		},
	})

	findings := []model.Finding{{ID: "f1", CheckName: "widget-check", Endpoint: model.Endpoint{Path: "/x"}}}
	outcomes := Run(t.Context(), findings, http.DefaultClient, false)

	if len(outcomes) != 1 {
		t.Fatalf("got %d outcomes, want 1", len(outcomes))
	}
	if got.ID != "f1" {
		t.Errorf("confirmer received ID %q, want f1", got.ID)
	}
	if !outcomes[0].Finding.Confirmed {
		t.Error("Finding.Confirmed = false, want true")
	}
	if outcomes[0].Skipped != "" || outcomes[0].Err != nil {
		t.Errorf("Outcome = %+v, want no skip and no error", outcomes[0])
	}
}

func TestRun_NoConfirmerIsSkippedNotError(t *testing.T) {
	isolate(t)

	findings := []model.Finding{{ID: "f1", CheckName: "missing-headers"}}
	outcomes := Run(t.Context(), findings, http.DefaultClient, false)

	if outcomes[0].Err != nil {
		t.Errorf("Err = %v, want nil — an unhandled check is not a failure", outcomes[0].Err)
	}
	if !strings.Contains(outcomes[0].Skipped, "missing-headers") {
		t.Errorf("Skipped = %q, want it to name the check", outcomes[0].Skipped)
	}
	if outcomes[0].Finding.Confirmed {
		t.Error("Confirmed = true, want false — nothing was actually verified")
	}
}

func TestRun_AlreadyConfirmedIsSkipped(t *testing.T) {
	isolate(t)

	called := false
	Register(fakeConfirmer{
		name: "widget-check",
		fn: func(_ context.Context, f model.Finding, _ ports.HTTPClient) (model.Finding, error) {
			called = true
			return f, nil
		},
	})

	findings := []model.Finding{{ID: "f1", CheckName: "widget-check", Confirmed: true}}
	outcomes := Run(t.Context(), findings, http.DefaultClient, false)

	if called {
		t.Error("confirmer was called for an already-confirmed finding")
	}
	if outcomes[0].Skipped == "" {
		t.Error("Skipped is empty, want an explanation")
	}
}

func TestRun_DestructiveEndpointIsSkippedWithoutOptIn(t *testing.T) {
	isolate(t)

	called := false
	Register(fakeConfirmer{
		name: "widget-check",
		fn: func(_ context.Context, f model.Finding, _ ports.HTTPClient) (model.Finding, error) {
			called = true
			return f, nil
		},
	})

	findings := []model.Finding{{
		ID:        "f1",
		CheckName: "widget-check",
		Endpoint:  model.Endpoint{Method: "DELETE", Path: "/items/{id}", Destructive: true},
	}}

	outcomes := Run(t.Context(), findings, http.DefaultClient, false)
	if called {
		t.Fatal("confirmer was called for a destructive endpoint without opt-in")
	}
	if !strings.Contains(outcomes[0].Skipped, "destructive") {
		t.Errorf("Skipped = %q, want it to say why", outcomes[0].Skipped)
	}
	if outcomes[0].Finding.Confirmed {
		t.Error("Confirmed = true, want false")
	}
}

func TestRun_DestructiveEndpointIsAttemptedWithOptIn(t *testing.T) {
	isolate(t)

	called := false
	Register(fakeConfirmer{
		name: "widget-check",
		fn: func(_ context.Context, f model.Finding, _ ports.HTTPClient) (model.Finding, error) {
			called = true
			f.Confirmed = true
			return f, nil
		},
	})

	findings := []model.Finding{{
		ID:        "f1",
		CheckName: "widget-check",
		Endpoint:  model.Endpoint{Method: "DELETE", Destructive: true},
	}}

	outcomes := Run(t.Context(), findings, http.DefaultClient, true)
	if !called {
		t.Fatal("confirmer was not called despite test_destructive opt-in")
	}
	if !outcomes[0].Finding.Confirmed {
		t.Error("Confirmed = false, want true")
	}
}

func TestRun_ConfirmerErrorIsWrappedAndNamesTheRoute(t *testing.T) {
	isolate(t)

	boom := errors.New("boom")
	Register(fakeConfirmer{
		name: "widget-check",
		fn: func(_ context.Context, f model.Finding, _ ports.HTTPClient) (model.Finding, error) {
			return f, boom
		},
	})

	findings := []model.Finding{{
		ID:        "f1",
		CheckName: "widget-check",
		Endpoint:  model.Endpoint{Method: "GET", Path: "/items"},
	}}
	outcomes := Run(t.Context(), findings, http.DefaultClient, false)

	if !errors.Is(outcomes[0].Err, boom) {
		t.Fatalf("Err = %v, want it to wrap the confirmer's error", outcomes[0].Err)
	}
	if !strings.Contains(outcomes[0].Err.Error(), "widget-check") || !strings.Contains(outcomes[0].Err.Error(), "/items") {
		t.Errorf("Err = %q, want it to name the check and the route", outcomes[0].Err)
	}
}

func TestRun_PreservesOrder(t *testing.T) {
	isolate(t)

	Register(fakeConfirmer{name: "widget-check", fn: noopConfirm})

	findings := []model.Finding{
		{ID: "a", CheckName: "widget-check"},
		{ID: "b", CheckName: "unregistered-check"},
		{ID: "c", CheckName: "widget-check", Confirmed: true},
	}
	outcomes := Run(t.Context(), findings, http.DefaultClient, false)

	if len(outcomes) != 3 {
		t.Fatalf("got %d outcomes, want 3", len(outcomes))
	}
	for i, want := range []string{"a", "b", "c"} {
		if got := outcomes[i].Finding.ID; got != want {
			t.Errorf("outcomes[%d].Finding.ID = %q, want %q", i, got, want)
		}
	}
}

func TestRun_StopsAttemptingOnceContextIsCancelled(t *testing.T) {
	isolate(t)

	called := 0
	Register(fakeConfirmer{
		name: "widget-check",
		fn: func(_ context.Context, f model.Finding, _ ports.HTTPClient) (model.Finding, error) {
			called++
			return f, nil
		},
	})

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	findings := []model.Finding{
		{ID: "a", CheckName: "widget-check"},
		{ID: "b", CheckName: "widget-check"},
	}
	outcomes := Run(ctx, findings, http.DefaultClient, false)

	if called != 0 {
		t.Errorf("confirmer was called %d time(s) after the context was already cancelled, want 0", called)
	}
	for i, o := range outcomes {
		if !errors.Is(o.Err, context.Canceled) {
			t.Errorf("outcomes[%d].Err = %v, want context.Canceled", i, o.Err)
		}
	}
}

func TestRun_EmptyInput(t *testing.T) {
	isolate(t)
	if got := Run(t.Context(), nil, http.DefaultClient, false); len(got) != 0 {
		t.Errorf("got %d outcomes, want 0", len(got))
	}
}
