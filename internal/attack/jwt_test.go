package attack

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/warden/internal/core/model"
)

func jwtWith(alg string, claims map[string]any) string {
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]any{"alg": alg, "typ": "JWT"})
	c, _ := json.Marshal(claims)
	return enc.EncodeToString(h) + "." + enc.EncodeToString(c) + ".sig"
}

// TestJWTConfirmer_StructuralFindingsHaveNoPoC pins the sentinel: no-exp
// and long-exp are facts read off the token, and marking them "not
// confirmed" would read as suspected-and-unproven. They come back as
// skipped instead.
func TestJWTConfirmer_StructuralFindingsHaveNoPoC(t *testing.T) {
	for _, id := range []string{"no-exp", "long-exp"} {
		t.Run(id, func(t *testing.T) {
			f := model.Finding{ID: id, CheckName: "jwt-weak", Severity: "low"}
			_, err := jwtConfirmer{}.Confirm(t.Context(), f, model.Clients{})
			if !errors.Is(err, ErrNoProofOfConcept) {
				t.Errorf("err = %v, want ErrNoProofOfConcept", err)
			}
		})
	}
}

// TestJWTConfirmer_ReforgesAndReproduces is the provable half: a freshly
// minted alg:none token, honoured now.
func TestJWTConfirmer_ReforgesAndReproduces(t *testing.T) {
	var sawAlgNone bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		hdr, _ := base64.RawURLEncoding.DecodeString(strings.Split(raw, ".")[0])
		var h map[string]any
		json.Unmarshal(hdr, &h)
		if h["alg"] == "none" {
			sawAlgNone = true
		}
		fmt.Fprint(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)

	f := model.Finding{
		ID: "alg-none-accepted", CheckName: "jwt-weak", Severity: "critical",
		Request: model.CapturedRequest{Method: http.MethodGet, URL: srv.URL + "/me"},
	}
	clients := model.Clients{
		Anonymous:    http.DefaultClient,
		SessionToken: jwtWith("HS256", map[string]any{"sub": "1"}),
	}

	got, err := jwtConfirmer{}.Confirm(t.Context(), f, clients)
	if err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	if !got.Confirmed {
		t.Error("Confirmed = false, want the forgery reproduced")
	}
	if !sawAlgNone {
		t.Error("the confirmer did not actually send an alg:none token")
	}
}

// TestJWTConfirmer_ReforgesRatherThanReplaying is the reason it re-mints:
// the token it forges must be built fresh from the current session token,
// not carried in the finding. The finding here holds no token at all, and
// confirmation still works.
func TestJWTConfirmer_ReforgesRatherThanReplaying(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)

	f := model.Finding{ID: "alg-none-accepted", CheckName: "jwt-weak",
		Request: model.CapturedRequest{Method: http.MethodGet, URL: srv.URL + "/me"}}

	clients := model.Clients{Anonymous: http.DefaultClient, SessionToken: jwtWith("RS256", map[string]any{"sub": "x"})}
	_, err := jwtConfirmer{}.Confirm(t.Context(), f, clients)
	if err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
}

// TestJWTConfirmer_RejectedForgeryDoesNotConfirm is the control.
func TestJWTConfirmer_RejectedForgeryDoesNotConfirm(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	f := model.Finding{ID: "alg-none-accepted", CheckName: "jwt-weak",
		Request: model.CapturedRequest{Method: http.MethodGet, URL: srv.URL + "/me"}}

	got, err := jwtConfirmer{}.Confirm(t.Context(), f,
		model.Clients{Anonymous: http.DefaultClient, SessionToken: jwtWith("HS256", map[string]any{"sub": "1"})})
	if err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	if got.Confirmed {
		t.Error("Confirmed = true against a target that rejected the forgery")
	}
	if !strings.Contains(got.Evidence.ResponseSnippet, "did not reproduce") {
		t.Errorf("evidence = %q, want it to say so", got.Evidence.ResponseSnippet)
	}
}
