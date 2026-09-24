package checks

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/warden/internal/core/model"
)

func cacheTarget(cacheControl string) model.Target {
	h := http.Header{}
	if cacheControl != "" {
		h.Set("Cache-Control", cacheControl)
	}
	return model.Target{
		Endpoint: model.Endpoint{Method: http.MethodGet, Path: "/me", RequiresAuth: true},
		Baseline: &model.Response{URL: "http://lab.test/me", StatusCode: 200, ProbedMethod: http.MethodGet, Headers: h},
	}
}

func runCache(t *testing.T, target model.Target) ([]model.Finding, error) {
	t.Helper()
	// The zero Clients is deliberate: a passive check must never reach for
	// one, and a nil dereference here would be the loudest proof it did.
	return (&cacheOnAuthenticated{}).Run(t.Context(), target, model.Clients{})
}

// TestCacheOnAuthenticated_Tiers is the whole judgement. The middle two
// rows are findings; the first is the only directive that actually keeps a
// body out of storage, and the last is the exposure people miss — no-cache
// means "revalidate before reuse", not "do not keep it".
func TestCacheOnAuthenticated_Tiers(t *testing.T) {
	tests := []struct {
		name         string
		cacheControl string
		wantSeverity string
		wantReason   string
	}{
		{"no-store is the only clean answer", "no-store", "", ""},
		{"no-store among others still clean", "private, no-cache, no-store", "", ""},
		{"public invites shared caches", "public, max-age=60", "medium", "SHARED caches"},
		{"absent leaves it to heuristics", "", "medium", "no Cache-Control at all"},
		{"private without no-store still hits disk", "private, no-cache", "low", "not out of storage"},
		{"no-cache alone", "no-cache", "low", "not out of storage"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := runCache(t, cacheTarget(tt.cacheControl))
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}

			if tt.wantSeverity == "" {
				if len(findings) != 0 {
					t.Fatalf("got %d findings for %q, want none", len(findings), tt.cacheControl)
				}
				return
			}

			if len(findings) != 1 {
				t.Fatalf("got %d findings for %q, want 1", len(findings), tt.cacheControl)
			}
			if findings[0].Severity != tt.wantSeverity {
				t.Errorf("Severity = %q, want %q", findings[0].Severity, tt.wantSeverity)
			}
			if !strings.Contains(findings[0].Evidence.ResponseSnippet, tt.wantReason) {
				t.Errorf("evidence = %q, want it to mention %q", findings[0].Evidence.ResponseSnippet, tt.wantReason)
			}
		})
	}
}

// TestCacheOnAuthenticated_DirectivesAreCaseInsensitive guards a header
// that servers write however they like. Reading "No-Store" as a missing
// no-store would report a route that is doing exactly the right thing.
func TestCacheOnAuthenticated_DirectivesAreCaseInsensitive(t *testing.T) {
	for _, value := range []string{"NO-STORE", "No-Store", "  no-store  "} {
		t.Run(value, func(t *testing.T) {
			findings, err := runCache(t, cacheTarget(value))
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if len(findings) != 0 {
				t.Errorf("got %d findings for %q, want none", len(findings), value)
			}
		})
	}
}

// TestCacheOnAuthenticated_OnlyProtectedRoutes pins where the applicability
// decision lives. The Authenticator attaches a token to every request,
// public ones included, so asking what the scanner sent would flag routes
// whose responses are meant to be cacheable. The spec decides instead.
func TestCacheOnAuthenticated_OnlyProtectedRoutes(t *testing.T) {
	if !(&cacheOnAuthenticated{}).Metadata().RequiresAuth {
		t.Error("RequiresAuth = false; the engine would pair this with public routes")
	}
}

// TestCacheOnAuthenticated_IsPassive keeps it in the family that costs no
// request: everything it needs is already in the collected baseline.
func TestCacheOnAuthenticated_IsPassive(t *testing.T) {
	meta := (&cacheOnAuthenticated{}).Metadata()
	if meta.Kind != model.KindPassive {
		t.Errorf("Kind = %q, want passive", meta.Kind)
	}
	if meta.Name != "cache-on-authenticated" {
		t.Errorf("Name = %q", meta.Name)
	}
}

// TestCacheOnAuthenticated_NoBaselineIsASkip keeps invariant 6: a response
// nobody collected cannot be judged, and saying nothing would read as
// saying it is fine.
func TestCacheOnAuthenticated_NoBaselineIsASkip(t *testing.T) {
	_, err := runCache(t, model.Target{
		Endpoint:    model.Endpoint{Method: http.MethodGet, Path: "/me", RequiresAuth: true},
		BaselineErr: errors.New("connection refused"),
	})
	if !errors.Is(err, model.ErrSkipped) {
		t.Errorf("err = %v, want a skip", err)
	}
}

// TestCacheOnAuthenticated_AnErrorPageIsNotTheRoutesResponse is the defect
// the scanner's first real findings exposed.
//
// Collection fills a path parameter with a placeholder, so /{code} is
// observed as the 404 for a code that does not exist. The check reported
// that as "a response only this user should see" — it is neither that nor
// anything a cache keeping it would expose, and the route's actual response
// may well set Cache-Control.
func TestCacheOnAuthenticated_AnErrorPageIsNotTheRoutesResponse(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusBadRequest, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			target := cacheTarget("")
			target.Baseline.StatusCode = status

			findings, err := runCache(t, target)
			if len(findings) != 0 {
				t.Errorf("got %d findings from a %d, want none", len(findings), status)
			}
			if !errors.Is(err, model.ErrSkipped) {
				t.Fatalf("err = %v, want a skip — an error page is not the route's response", err)
			}
			if !strings.Contains(err.Error(), "error page") {
				t.Errorf("reason = %q, want it to say what was wrong with the subject", err)
			}
		})
	}
}

// TestCacheOnAuthenticated_A2xxIsStillJudged is the control that keeps the
// narrowing from swallowing the check. The finding against /debug/vars —
// 200 OK with no Cache-Control at all — is a true positive and must survive.
func TestCacheOnAuthenticated_A2xxIsStillJudged(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusCreated, http.StatusNoContent} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			target := cacheTarget("")
			target.Baseline.StatusCode = status

			findings, err := runCache(t, target)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}
			if len(findings) != 1 {
				t.Errorf("got %d findings from a %d with no Cache-Control, want 1", len(findings), status)
			}
		})
	}
}
