package checks

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

// newGatedServer answers 200 to a request carrying a token and `unauth` to
// one that does not — the shape of a route behind working authentication.
// bodySeen records whether any request arrived with a body.
func newGatedServer(t *testing.T, unauth int) (srv *httptest.Server, bodySeen func() bool) {
	t.Helper()
	var mu sync.Mutex
	sawBody := false

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > 0 {
			mu.Lock()
			sawBody = true
			mu.Unlock()
		}
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(unauth)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
			return
		}
		fmt.Fprint(w, `{"items":[{"id":1,"secret":"only for the logged in"}]}`)
	}))
	t.Cleanup(srv.Close)

	return srv, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return sawBody
	}
}

// tokenClient is the Default identity: it adds a credential, the way the
// Authenticator does.
type tokenClient struct{}

func (tokenClient) Do(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer real-token")
	return http.DefaultTransport.RoundTrip(clone)
}

func authTarget(srv *httptest.Server, path string) model.Target {
	return model.Target{
		Endpoint: model.Endpoint{Method: http.MethodGet, Path: path, RequiresAuth: true},
		Baseline: &model.Response{URL: srv.URL + path, StatusCode: 200, ProbedMethod: http.MethodGet},
	}
}

// TestAuthRequired_AsksTheQuestionWithoutCredentials is the test that makes
// the whole check meaningful, and the one that would have been impossible
// before checks were handed a second identity.
//
// The server here is correctly protected. A check that reached for Default
// by habit would get a 200, conclude the route is open, and report a
// critical finding about a control that is working — the worst possible
// false positive, because it sends someone to "fix" something that is fine.
func TestAuthRequired_AsksTheQuestionWithoutCredentials(t *testing.T) {
	srv, _ := newGatedServer(t, http.StatusUnauthorized)

	findings, err := (&authRequired{}).Run(t.Context(), authTarget(srv, "/items"), model.Clients{
		Default:   tokenClient{},
		Anonymous: http.DefaultClient,
	})

	if err != nil {
		t.Fatalf("Run() error = %v, want a clean verdict", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings against a properly protected route, want 0: %+v", len(findings), findings)
	}
}

// TestAuthRequired_AnOpenRouteIsCritical is the finding itself.
func TestAuthRequired_AnOpenRouteIsCritical(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"items":[{"id":1,"secret":"should have needed a token"}]}`)
	}))
	t.Cleanup(srv.Close)

	findings, err := (&authRequired{}).Run(t.Context(), authTarget(srv, "/items"), model.Clients{
		Default:   tokenClient{},
		Anonymous: http.DefaultClient,
	})

	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Evidence.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", f.Evidence.StatusCode)
	}
	for _, want := range []string{"no credentials", "200"} {
		if !strings.Contains(f.Evidence.ResponseSnippet, want) {
			t.Errorf("evidence %q does not mention %q", f.Evidence.ResponseSnippet, want)
		}
	}
}

// TestAuthRequired_AnythingButAcceptOrRejectIsInconclusive keeps the check
// inside the project's own standard. A 400 is suggestive — validation
// normally runs after authentication, so reaching it without credentials
// hints the control did not run — but suggestive is not proof, and the
// report says so instead of guessing.
func TestAuthRequired_AnythingButAcceptOrRejectIsInconclusive(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			srv, _ := newGatedServer(t, status)

			findings, err := (&authRequired{}).Run(t.Context(), authTarget(srv, "/items"), model.Clients{
				Default:   tokenClient{},
				Anonymous: http.DefaultClient,
			})

			if len(findings) != 0 {
				t.Errorf("got %d findings, want 0", len(findings))
			}
			if !errors.Is(err, model.ErrSkipped) {
				t.Fatalf("err = %v, want a skip — %d is neither an acceptance nor a rejection", err, status)
			}
			if !strings.Contains(err.Error(), fmt.Sprint(status)) {
				t.Errorf("reason %q does not name the status the target answered", err)
			}
		})
	}
}

// TestAuthRequired_SendsNoBody guards the promise that keeps this check
// from writing to the target. Without a body an unprotected POST answers
// 400 at validation, which the check reports as inconclusive — a worse
// verdict, deliberately traded for never creating anything.
func TestAuthRequired_SendsNoBody(t *testing.T) {
	srv, bodySeen := newGatedServer(t, http.StatusUnauthorized)

	target := model.Target{
		Endpoint: model.Endpoint{Method: http.MethodPost, Path: "/items", RequiresAuth: true},
		Baseline: &model.Response{URL: srv.URL + "/items", StatusCode: 405, ProbedMethod: http.MethodGet},
	}
	if _, err := (&authRequired{}).Run(t.Context(), target, model.Clients{
		Default:   tokenClient{},
		Anonymous: http.DefaultClient,
	}); err != nil && !errors.Is(err, model.ErrSkipped) {
		t.Fatalf("Run() error = %v", err)
	}

	if bodySeen() {
		t.Error("a request arrived carrying a body; this check must never write to the target")
	}
}

// TestAuthRequired_NoBaselineIsASkip keeps it inside invariant 6: the
// baseline is where the target's scheme and host come from, and guessing
// them is not an option.
func TestAuthRequired_NoBaselineIsASkip(t *testing.T) {
	target := model.Target{
		Endpoint:    model.Endpoint{Method: http.MethodGet, Path: "/items", RequiresAuth: true},
		BaselineErr: errors.New("connection refused"),
	}
	_, err := (&authRequired{}).Run(t.Context(), target, model.Clients{Anonymous: http.DefaultClient})
	if !errors.Is(err, model.ErrSkipped) {
		t.Errorf("err = %v, want a skip", err)
	}
}

// TestAuthRequired_Metadata pins the two fields that decide which endpoints
// it ever sees. RequiresAuth is what keeps it off public routes, where
// answering without credentials is the route working as designed.
func TestAuthRequired_Metadata(t *testing.T) {
	meta := (&authRequired{}).Metadata()

	if meta.Name != "auth-required" {
		t.Errorf("Name = %q", meta.Name)
	}
	if !meta.RequiresAuth {
		t.Error("RequiresAuth = false; a public route answering anonymously is not a finding")
	}
	if meta.Kind != model.KindActive {
		t.Errorf("Kind = %q, want active — it sends a request of its own", meta.Kind)
	}
	if meta.Severity != "critical" {
		t.Errorf("Severity = %q, want critical", meta.Severity)
	}
}
