package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

func init() {
	RegisterCheck(&cacheOnAuthenticated{})
}

// cacheOnAuthenticated reports authenticated responses a cache is allowed
// to keep.
//
// The exposure is mundane and real: a response only this user should see,
// written to a shared proxy or to the disk of a machine several people use.
// Nothing is exploited to find it — the answer is already in the headers of
// the baseline the engine collected, which is why this is passive.
//
// # Why the spec decides, not the request
//
// It applies to endpoints the SPEC declares as protected, via
// CheckMetadata.RequiresAuth, not to "responses we happened to send a token
// with". The Authenticator attaches the token to every request including
// public ones, so asking what the scanner sent would flag public routes
// whose responses are meant to be cacheable.
//
// # The tiers, and why the mildest one is still reported
//
// no-store is the only directive that keeps a response out of storage
// entirely. no-cache does not: it means "revalidate before reuse", and the
// body is written to disk in the meantime. private keeps it out of shared
// caches but not off the client's own disk.
//
// So a route with `private, no-cache` and no `no-store` is a real, minor
// exposure, reported at low. Suppressing it would make its absence from the
// report mean either "this is handled" or "we decided not to look" — the
// ambiguity the coverage block exists to prevent, and the same reasoning
// that keeps missing-headers reporting on JSON routes at a lower severity
// rather than going quiet.
type cacheOnAuthenticated struct{}

var _ model.Check = (*cacheOnAuthenticated)(nil)

func (c *cacheOnAuthenticated) Metadata() model.CheckMetadata {
	return model.CheckMetadata{
		Name:          "cache-on-authenticated",
		OWASPCategory: "A05:2021-Security Misconfiguration",
		Severity:      "medium",
		Kind:          model.KindPassive,
		RequiresAuth:  true,
	}
}

func (c *cacheOnAuthenticated) Run(_ context.Context, t model.Target, _ model.Clients) ([]model.Finding, error) {
	if t.Baseline == nil {
		return nil, model.Skippedf("no baseline response for %s %s: %v",
			t.Endpoint.Method, t.Endpoint.Path, t.BaselineErr)
	}

	raw := t.Baseline.Headers.Get("Cache-Control")
	directives := parseCacheControl(raw)

	severity, why := cacheVerdict(raw, directives)
	if severity == "" {
		return nil, nil
	}

	return []model.Finding{{
		ID:       "Cache-Control",
		Severity: severity,
		Request: model.CapturedRequest{
			Method: t.Baseline.ProbedMethod,
			URL:    t.Baseline.URL,
		},
		Evidence: model.Evidence{
			StatusCode:      t.Baseline.StatusCode,
			ResponseSnippet: why,
		},
	}}, nil
}

// cacheVerdict grades what the response allows a cache to do. An empty
// severity means there is nothing to report.
func cacheVerdict(raw string, directives map[string]bool) (severity, why string) {
	switch {
	case directives["no-store"]:
		// The only directive that keeps the body out of storage.
		return "", ""

	case directives["public"]:
		return "medium", fmt.Sprintf(
			"this route requires authentication, and its response is marked %q — `public` invites SHARED caches "+
				"to keep a response only this user should see, and to hand it to the next person who asks", raw)

	case raw == "":
		return "medium", "this route requires authentication and its response sets no Cache-Control at all, " +
			"so caches fall back to their own heuristics to decide how long to keep a response only this user should see"

	default:
		return "low", fmt.Sprintf(
			"this route requires authentication and its response sets %q, which keeps it out of shared caches "+
				"but not out of storage — only `no-store` does that, and without it the body is written to the client's disk", raw)
	}
}

// parseCacheControl reduces the header to the set of directive names
// present, lower-cased. Values (max-age=0 and friends) are dropped: the
// judgement here is about which directives appear, not what they are set to.
func parseCacheControl(raw string) map[string]bool {
	out := map[string]bool{}
	for part := range strings.SplitSeq(raw, ",") {
		name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
		if name != "" {
			out[strings.ToLower(name)] = true
		}
	}
	return out
}
