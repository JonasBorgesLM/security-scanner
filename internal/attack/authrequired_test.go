package attack

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/warden/internal/core/model"
)

// tokenClient stands in for the Default identity: it adds a credential the
// way the Authenticator does.
type tokenClient struct{}

func (tokenClient) Do(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer real-token")
	return http.DefaultTransport.RoundTrip(clone)
}

func authFinding(url string) model.Finding {
	return model.Finding{
		CheckName: "auth-required",
		Endpoint:  model.Endpoint{Method: http.MethodGet, Path: "/items", RequiresAuth: true},
		Request:   model.CapturedRequest{Method: http.MethodGet, URL: url},
	}
}

// TestAuthRequiredConfirmer_ReproducesAnOpenRoute is the proof of concept:
// the same request, no credentials, answered again.
func TestAuthRequiredConfirmer_ReproducesAnOpenRoute(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"items":[{"id":1}]}`)
	}))
	t.Cleanup(srv.Close)

	got, err := authRequiredConfirmer{}.Confirm(t.Context(), authFinding(srv.URL+"/items"),
		model.Clients{Default: tokenClient{}, Anonymous: http.DefaultClient})
	if err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}

	if !got.Confirmed {
		t.Error("Confirmed = false, want the open route reproduced")
	}
	if !strings.Contains(got.Evidence.ResponseSnippet, "no credentials at all") {
		t.Errorf("evidence = %q, want it to say what made the reproduction meaningful", got.Evidence.ResponseSnippet)
	}
}

// TestAuthRequiredConfirmer_UsesTheAnonymousIdentity is the one that
// matters. A Confirmer holding only the authenticated client would replay
// the URL, get a 200 because the credentials work, and confirm every
// finding it was ever handed — including the wrong ones.
//
// The server here is properly protected, so the only way to reach a 200 is
// to send a token the proof of concept must not be sending.
func TestAuthRequiredConfirmer_UsesTheAnonymousIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
			return
		}
		fmt.Fprint(w, `{"items":[{"id":1}]}`)
	}))
	t.Cleanup(srv.Close)

	got, err := authRequiredConfirmer{}.Confirm(t.Context(), authFinding(srv.URL+"/items"),
		model.Clients{Default: tokenClient{}, Anonymous: http.DefaultClient})
	if err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}

	if got.Confirmed {
		t.Fatal("Confirmed = true against a protected route; the proof of concept sent credentials it must not send")
	}
	if !strings.Contains(got.Evidence.ResponseSnippet, "did not reproduce") {
		t.Errorf("evidence = %q, want it to say the finding did not hold", got.Evidence.ResponseSnippet)
	}
	if got.Evidence.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want the 401 it actually got", got.Evidence.StatusCode)
	}
}

// TestAuthRequiredConfirmer_IsRegistered keeps the pipeline honest: without
// registration every auth-required finding would pass through attack as
// "no PoC available", which is a skip, not a confirmation.
func TestAuthRequiredConfirmer_IsRegistered(t *testing.T) {
	mu.RLock()
	defer mu.RUnlock()
	if _, ok := confirmers["auth-required"]; !ok {
		t.Error("no Confirmer registered for auth-required")
	}
}
