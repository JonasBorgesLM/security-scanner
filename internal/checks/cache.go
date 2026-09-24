package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/JonasBorgesLM/warden/internal/core/model"
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

	// An error page is not this route's response. The check's whole claim is
	// about "a response only this user should see", and a 404 or a 500 is
	// neither that nor anything a cache keeping it would expose.
	//
	// This matters in practice, not in theory: collection fills a path
	// parameter with a placeholder, so a route like /{code} is observed as
	// the 404 for a code that does not exist. Judging that produced a real
	// over-claimed finding against the task-api — the response it described
	// as private was an error page, and the route's actual response may well
	// set Cache-Control.
	//
	// The narrowing stops here rather than applying to every passive check,
	// because the checks differ in whether an error page is a valid subject.
	// missing-headers asks whether a header is set, and security headers
	// normally come from middleware that covers the error page too.
	// exposed-secrets asks whether a credential is in the body, and one
	// leaking from a 500 is leaking. Only this check's question is
	// specifically about a response that does not exist here.
	if code := t.Baseline.StatusCode; code < 200 || code >= 300 {
		return nil, model.Skippedf(
			"the collected response for %s %s is a %d, which is an error page rather than the route's own response; "+
				"what it allows a cache to do says nothing about what the route returns when it succeeds",
			t.Endpoint.Method, t.Endpoint.Path, code)
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
