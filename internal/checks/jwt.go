package checks

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

func init() {
	RegisterCheck(&jwtWeak{})
}

// maxExpSeconds is the longest lifetime this check lets a token have before
// it says so. A day is generous: past it, a leaked token stays useful long
// enough that the length is itself the finding. It is a threshold, so it is
// a low-severity, judgement finding rather than a proof of a broken control.
const maxExpSeconds = 24 * 60 * 60

// jwtWeak inspects the token the scanner itself was issued and, on a
// protected route, tries to forge one the target should never accept.
//
// It reads Clients.SessionToken, the one place a check is handed the
// credential's value rather than a client that injects it. If that token is
// not a JWT — an opaque session id, say — there is nothing here to weigh in
// on, and the check skips.
//
// # Two findings of very different weight
//
// alg:none acceptance is proof. The check forges an unsigned token carrying
// the real one's claims, sends it to a protected route via the anonymous
// client (so nothing else attaches the valid token), and if the target
// answers as though it were logged in, signature verification is being
// skipped entirely. Critical, and confirmed by a PoC in internal/attack.
//
// A long or absent exp is a judgement, not a proof. Nothing is exploited;
// the token simply outlives what it should. Reported low, and structural —
// there is no PoC to run, so it passes through attack untouched like a
// passive finding.
type jwtWeak struct{}

var _ model.Check = (*jwtWeak)(nil)

func (c *jwtWeak) Metadata() model.CheckMetadata {
	return model.CheckMetadata{
		Name:          "jwt-weak",
		OWASPCategory: "A02:2021-Cryptographic Failures",
		Severity:      "high",
		Kind:          model.KindActive,
		RequiresAuth:  true,
		AppliesTo: func(ep model.Endpoint) bool {
			// A safe method is enough to tell whether a forged token is
			// accepted, and it is all this check is willing to send.
			return ep.Method == http.MethodGet
		},
	}
}

func (c *jwtWeak) Run(ctx context.Context, t model.Target, clients model.Clients) ([]model.Finding, error) {
	if clients.SessionToken == "" {
		return nil, model.Skippedf(
			"%s %s: no session token is available to inspect (the target authenticated with none, or none was configured)",
			t.Endpoint.Method, t.Endpoint.Path)
	}

	header, claims, ok := decodeJWT(clients.SessionToken)
	if !ok {
		return nil, model.Skippedf(
			"the session token for %s %s is not a JWT, so there is nothing here about JWT handling to weigh in on",
			t.Endpoint.Method, t.Endpoint.Path)
	}

	var findings []model.Finding

	if f := c.checkExpiry(claims); f != nil {
		findings = append(findings, *f)
	}

	if t.Baseline == nil {
		// exp was decided from the token alone; alg:none needs a route to
		// try the forgery against, and there is no baseline URL for one.
		if len(findings) > 0 {
			return findings, model.Skippedf("could not test alg:none against %s %s: no baseline route: %v",
				t.Endpoint.Method, t.Endpoint.Path, t.BaselineErr)
		}
		return nil, model.Skippedf("no baseline response for %s %s, so alg:none cannot be tried here: %v",
			t.Endpoint.Method, t.Endpoint.Path, t.BaselineErr)
	}

	f, err := c.checkAlgNone(ctx, t, clients, header, claims)
	if err != nil {
		// A transport failure on the forgery attempt is not a verdict on
		// exp, which was already decided. Keep what was concluded and
		// report the rest as unfinished.
		if len(findings) > 0 {
			return findings, model.Skippedf("could not test alg:none against %s %s: %v", t.Endpoint.Method, t.Endpoint.Path, err)
		}
		return nil, model.Skippedf("could not test alg:none against %s %s: %v", t.Endpoint.Method, t.Endpoint.Path, err)
	}
	if f != nil {
		findings = append(findings, *f)
	}

	return findings, nil
}

// checkExpiry weighs the exp claim. Absent or too far out is a low finding,
// not a proof.
func (c *jwtWeak) checkExpiry(claims map[string]any) *model.Finding {
	exp, present := claims["exp"].(float64)
	if !present {
		return &model.Finding{
			ID:       "no-exp",
			Severity: "low",
			Evidence: model.Evidence{ResponseSnippet: "the session token carries no exp claim, so it never expires on its own — a leaked copy stays valid until something else revokes it"},
		}
	}

	expiry := time.Unix(int64(exp), 0).UTC()

	// Prefer the token's DESIGNED lifetime, exp - iat, which is a property
	// of the token and the same on every scan. Falling back to time-until-
	// expiry would make the same token flip between long-exp and clean
	// depending on the hour it was scanned — a finding that appears and
	// disappears with the wall clock, which is exactly what invariant 8
	// bans. When iat is absent that flip is unavoidable, so the decision
	// then rests on remaining lifetime and the evidence says which basis it
	// used.
	if iat, ok := claims["iat"].(float64); ok {
		lifetime := time.Duration(int64(exp)-int64(iat)) * time.Second
		if lifetime > maxExpSeconds*time.Second {
			return &model.Finding{
				ID:       "long-exp",
				Severity: "low",
				Evidence: model.Evidence{ResponseSnippet: fmt.Sprintf(
					"the token is issued with a lifetime of about %d hours (iat to exp); past a day, a leaked copy stays useful long enough that the lifetime is itself the exposure",
					int(lifetime.Hours()))},
			}
		}
		return nil
	}

	if time.Until(expiry) > maxExpSeconds*time.Second {
		return &model.Finding{
			ID:       "long-exp",
			Severity: "low",
			Evidence: model.Evidence{ResponseSnippet: fmt.Sprintf(
				"the token expires at %s, more than a day out, and carries no iat to bound when it was issued; a leaked copy stays useful long enough that the lifetime is itself the exposure",
				expiry.Format(time.RFC3339))},
		}
	}
	return nil
}

// checkAlgNone forges an unsigned token and sees whether the target honours
// it on a route that needs authentication. This is the provable half.
func (c *jwtWeak) checkAlgNone(ctx context.Context, t model.Target, clients model.Clients, header, claims map[string]any) (*model.Finding, error) {
	forged, err := forgeAlgNone(claims)
	if err != nil {
		return nil, err
	}

	base, err := url.Parse(t.Baseline.URL)
	if err != nil {
		return nil, fmt.Errorf("baseline URL %q not parseable: %w", t.Baseline.URL, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return nil, err
	}
	// The anonymous client attaches no managed token, so the Authorization
	// the target sees is the forged one and nothing else.
	req.Header.Set("Authorization", "Bearer "+forged)

	resp, err := clients.Anonymous.Do(req)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Rejected, which is correct. No finding.
		return nil, nil
	}

	origAlg, _ := header["alg"].(string)
	return &model.Finding{
		ID:       "alg-none-accepted",
		Severity: "critical",
		Request: model.CapturedRequest{
			Method:  http.MethodGet,
			URL:     base.String(),
			Payload: "alg:none",
		},
		Evidence: model.Evidence{
			StatusCode: resp.StatusCode,
			ResponseSnippet: fmt.Sprintf(
				"the target issued a token signed with %q but accepted a forged token with \"alg\":\"none\" and no signature, answering %d on a route that requires authentication. Signature verification is not being performed — anyone can mint a valid session.",
				origAlg, resp.StatusCode),
		},
	}, nil
}

// decodeJWT splits a compact JWT and decodes its header and claims. It
// returns ok=false for anything that is not a three-part token whose first
// two parts are base64url JSON objects — which is how an opaque session
// token, or any non-JWT, is recognised and left alone.
func decodeJWT(token string) (header, claims map[string]any, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, false
	}
	header, ok = decodeJWTSegment(parts[0])
	if !ok {
		return nil, nil, false
	}
	claims, ok = decodeJWTSegment(parts[1])
	if !ok {
		return nil, nil, false
	}
	return header, claims, true
}

func decodeJWTSegment(seg string) (map[string]any, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil, false
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, false
	}
	return out, true
}

// forgeAlgNone builds an unsigned token: header {"alg":"none","typ":"JWT"},
// the original claims verbatim, and an empty signature. Preserving the
// claims matters — a server that skips verification but still checks the
// subject would otherwise reject it, hiding a real vulnerability.
func forgeAlgNone(claims map[string]any) (string, error) {
	headerJSON, err := json.Marshal(map[string]any{"alg": "none", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(headerJSON) + "." + enc.EncodeToString(claimsJSON) + ".", nil
}
