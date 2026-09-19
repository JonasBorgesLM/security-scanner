package checks

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

// makeJWT builds a compact token with the given alg and claims. The
// signature is a fixed opaque blob — nothing here verifies it, and the
// point is the shape, not the crypto.
func makeJWT(alg string, claims map[string]any) string {
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]any{"alg": alg, "typ": "JWT"})
	c, _ := json.Marshal(claims)
	return enc.EncodeToString(h) + "." + enc.EncodeToString(c) + ".c2ln"
}

func jwtTarget(srv *httptest.Server, token string) (model.Target, model.Clients) {
	t := model.Target{
		Endpoint: model.Endpoint{Method: http.MethodGet, Path: "/me", RequiresAuth: true},
		Baseline: &model.Response{URL: srv.URL + "/me", StatusCode: 200, ProbedMethod: http.MethodGet},
	}
	c := model.Clients{Default: http.DefaultClient, Anonymous: http.DefaultClient, SessionToken: token}
	return t, c
}

// newJWTServer accepts the caller's token according to how it decides to
// verify: when honourNone is true it treats any well-formed token as valid
// (the bug), otherwise it requires an alg other than none.
func newJWTServer(t *testing.T, honourNone bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		parts := strings.Split(raw, ".")
		if len(parts) != 3 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		hdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
		var h map[string]any
		json.Unmarshal(hdr, &h)
		if h["alg"] == "none" && !honourNone {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"me":true}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestJWTWeak_AlgNoneAcceptedIsCritical is the provable half: the target
// honours a forged unsigned token, so it is not verifying signatures.
func TestJWTWeak_AlgNoneAcceptedIsCritical(t *testing.T) {
	srv := newJWTServer(t, true)
	token := makeJWT("HS256", map[string]any{"sub": "1", "exp": float64(time.Now().Add(time.Hour).Unix())})
	target, clients := jwtTarget(srv, token)

	findings, err := (&jwtWeak{}).Run(t.Context(), target, clients)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	var found *model.Finding
	for i := range findings {
		if findings[i].ID == "alg-none-accepted" {
			found = &findings[i]
		}
	}
	if found == nil {
		t.Fatalf("no alg-none-accepted finding among %d findings", len(findings))
	}
	if found.Severity != "critical" {
		t.Errorf("Severity = %q, want critical", found.Severity)
	}
	if !strings.Contains(found.Evidence.ResponseSnippet, "anyone can mint") {
		t.Errorf("evidence = %q, want it to state the consequence", found.Evidence.ResponseSnippet)
	}
}

// TestJWTWeak_AlgNoneRejectedIsClean is the control: a target that refuses
// the forged token gets no alg:none finding.
func TestJWTWeak_AlgNoneRejectedIsClean(t *testing.T) {
	srv := newJWTServer(t, false)
	token := makeJWT("HS256", map[string]any{"sub": "1", "exp": float64(time.Now().Add(time.Hour).Unix())})
	target, clients := jwtTarget(srv, token)

	findings, err := (&jwtWeak{}).Run(t.Context(), target, clients)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	for _, f := range findings {
		if f.ID == "alg-none-accepted" {
			t.Error("reported alg:none accepted against a target that rejected the forgery")
		}
	}
}

// TestJWTWeak_ForgeryCarriesTheOriginalClaims guards a false negative: a
// server that skips signature checking but still validates the subject
// would reject a forgery with empty claims, hiding the bug. The forged
// token must carry the real claims.
func TestJWTWeak_ForgeryCarriesTheOriginalClaims(t *testing.T) {
	claims := map[string]any{"sub": "alice", "role": "admin"}
	forged, err := forgeAlgNone(claims)
	if err != nil {
		t.Fatalf("forgeAlgNone() error = %v", err)
	}

	parts := strings.Split(forged, ".")
	if len(parts) != 3 || parts[2] != "" {
		t.Fatalf("forged token = %q, want three parts with an empty signature", forged)
	}
	h, _ := decodeJWTSegment(parts[0])
	if h["alg"] != "none" {
		t.Errorf("forged alg = %v, want none", h["alg"])
	}
	c, _ := decodeJWTSegment(parts[1])
	if c["sub"] != "alice" || c["role"] != "admin" {
		t.Errorf("forged claims = %v, want the originals preserved", c)
	}
}

// TestJWTWeak_ExpiryTiers covers the judgement half.
func TestJWTWeak_ExpiryTiers(t *testing.T) {
	srv := newJWTServer(t, false) // rejects the forgery, so only exp can fire

	tests := []struct {
		name   string
		claims map[string]any
		wantID string
	}{
		{"no exp", map[string]any{"sub": "1"}, "no-exp"},
		{"exp far out", map[string]any{"sub": "1", "exp": float64(time.Now().Add(72 * time.Hour).Unix())}, "long-exp"},
		{"exp within a day", map[string]any{"sub": "1", "exp": float64(time.Now().Add(time.Hour).Unix())}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, clients := jwtTarget(srv, makeJWT("HS256", tt.claims))
			findings, err := (&jwtWeak{}).Run(t.Context(), target, clients)
			if err != nil {
				t.Fatalf("Run() error = %v", err)
			}

			var ids []string
			for _, f := range findings {
				ids = append(ids, f.ID)
				if f.ID == "no-exp" || f.ID == "long-exp" {
					if f.Severity != "low" {
						t.Errorf("%s severity = %q, want low", f.ID, f.Severity)
					}
				}
			}
			if tt.wantID == "" {
				for _, id := range ids {
					if id == "no-exp" || id == "long-exp" {
						t.Errorf("got exp finding %q for a token within a day, want none", id)
					}
				}
				return
			}
			found := false
			for _, id := range ids {
				if id == tt.wantID {
					found = true
				}
			}
			if !found {
				t.Errorf("findings = %v, want one with id %q", ids, tt.wantID)
			}
		})
	}
}

// TestJWTWeak_OpaqueTokenIsASkip keeps it from opining on a target that
// does not use JWTs at all.
func TestJWTWeak_OpaqueTokenIsASkip(t *testing.T) {
	srv := newJWTServer(t, false)
	target, clients := jwtTarget(srv, "453e04c65f83b3ff8be2b30fa5d7a91064f588822e12bec1")

	_, err := (&jwtWeak{}).Run(t.Context(), target, clients)
	if !errors.Is(err, model.ErrSkipped) {
		t.Fatalf("err = %v, want a skip for a non-JWT token", err)
	}
	if !strings.Contains(err.Error(), "not a JWT") {
		t.Errorf("reason = %q, want it to say the token is not a JWT", err)
	}
}

// TestJWTWeak_NoTokenIsASkip covers a target with no auth at all.
func TestJWTWeak_NoTokenIsASkip(t *testing.T) {
	target := model.Target{
		Endpoint: model.Endpoint{Method: http.MethodGet, Path: "/me", RequiresAuth: true},
		Baseline: &model.Response{URL: "http://lab.test/me", StatusCode: 200, ProbedMethod: http.MethodGet},
	}
	_, err := (&jwtWeak{}).Run(t.Context(), target, model.Clients{Anonymous: http.DefaultClient})
	if !errors.Is(err, model.ErrSkipped) {
		t.Errorf("err = %v, want a skip when no token is available", err)
	}
}

// TestJWTWeak_ExpiryVerdictDoesNotDependOnScanTime is the determinism fix.
// A token's designed lifetime (iat to exp) is a property of the token, so
// the same token must yield the same verdict whenever it is scanned — not
// flip between long-exp and clean as the wall clock moves toward exp.
func TestJWTWeak_ExpiryVerdictDoesNotDependOnScanTime(t *testing.T) {
	srv := newJWTServer(t, false) // rejects forgery, so only exp can fire

	// Issued 2h ago, expires in 2h: a 4h designed lifetime. That is short,
	// so it is clean — and stays clean no matter that only 2h remain.
	now := time.Now().Unix()
	claims := map[string]any{"sub": "1", "iat": float64(now - 2*3600), "exp": float64(now + 2*3600)}
	target, clients := jwtTarget(srv, makeJWT("HS256", claims))

	findings, err := (&jwtWeak{}).Run(t.Context(), target, clients)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	for _, f := range findings {
		if f.ID == "long-exp" {
			t.Error("a 4h token flagged long-exp because only 2h remain; the verdict must rest on iat-to-exp, not time-until-exp")
		}
	}

	// A genuinely long-lived token: 48h from iat to exp. long-exp, and its
	// evidence names the designed lifetime, not a from-now countdown.
	claims["exp"] = float64(now - 2*3600 + 48*3600)
	target, clients = jwtTarget(srv, makeJWT("HS256", claims))
	findings, _ = (&jwtWeak{}).Run(t.Context(), target, clients)

	var long *model.Finding
	for i := range findings {
		if findings[i].ID == "long-exp" {
			long = &findings[i]
		}
	}
	if long == nil {
		t.Fatal("a 48h-lifetime token was not flagged long-exp")
	}
	if !strings.Contains(long.Evidence.ResponseSnippet, "lifetime of about 48 hours") {
		t.Errorf("evidence = %q, want the designed lifetime, which is stable across runs", long.Evidence.ResponseSnippet)
	}
}
