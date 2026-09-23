package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/JonasBorgesLM/warden/internal/core/model"
)

func init() {
	RegisterCheck(&corsMisconfigured{})
}

// corsMisconfigured reports a cross-origin policy that hands the response
// to sites that should not have it.
//
// # The logic here runs opposite to every other check
//
// The absence of CORS headers is the SECURE state, not a finding. A route
// that says nothing about cross-origin access is one the browser's same-origin
// policy protects on its own. Only a response that grants something can be
// wrong, so this check reports on what it finds rather than on what it misses
// — the reverse of missing-headers, and worth stating because writing it the
// familiar way would flag every correctly configured route on the target.
//
// # Why a probe rather than the baseline
//
// A spec-compliant CORS implementation answers nothing at all when the
// request carries no Origin, so the baseline cannot see a policy even when
// one exists. The origin probe (model.ProbeOrigin) asks with an origin the
// target has no reason to trust, which is what makes the policy observable.
//
// # The tiers
//
// Reflecting the probe's origin is the serious one: the target echoed back
// a domain it has never heard of, so it will echo back any domain. Paired
// with credentials, that lets any site on the internet read this response
// with the victim's session attached.
//
// A wildcard with credentials is a different thing and graded lower on
// purpose: browsers REFUSE that combination outright, so it is not
// exploitable. It is reported because it means the policy was written
// without being understood, not because someone can use it.
type corsMisconfigured struct{}

var _ model.Check = (*corsMisconfigured)(nil)

func (c *corsMisconfigured) Metadata() model.CheckMetadata {
	return model.CheckMetadata{
		Name:          "cors-misconfigured",
		OWASPCategory: "A05:2021-Security Misconfiguration",
		Severity:      "medium",
		Kind:          model.KindPassive,
	}
}

func (c *corsMisconfigured) Run(_ context.Context, t model.Target, _ model.Clients) ([]model.Finding, error) {
	probe := t.Probes.Origin
	if probe == nil {
		return nil, model.Skippedf(
			"no origin probe for %s %s, so this route's cross-origin policy was never observed: %v",
			t.Endpoint.Method, t.Endpoint.Path, t.BaselineErr)
	}

	allowOrigin := strings.TrimSpace(probe.Headers.Get("Access-Control-Allow-Origin"))
	if allowOrigin == "" {
		// No grant, nothing to report. The same-origin policy is doing its
		// job and silence here is the correct answer, not an omission.
		return nil, nil
	}

	credentials := strings.EqualFold(strings.TrimSpace(probe.Headers.Get("Access-Control-Allow-Credentials")), "true")
	varies := headerListContains(probe.Headers.Get("Vary"), "origin")

	severity, why := corsVerdict(allowOrigin, credentials, varies)
	if severity == "" {
		return nil, nil
	}

	return []model.Finding{{
		ID:       "Access-Control-Allow-Origin",
		Severity: severity,
		Request: model.CapturedRequest{
			Method:  probe.ProbedMethod,
			URL:     probe.URL,
			Headers: map[string]string{"Origin": model.ProbeOrigin},
		},
		Evidence: model.Evidence{
			StatusCode:      probe.StatusCode,
			ResponseSnippet: why,
		},
	}}, nil
}

// corsVerdict grades the grant. An empty severity means nothing to report.
func corsVerdict(allowOrigin string, credentials, varies bool) (severity, why string) {
	reflected := allowOrigin == model.ProbeOrigin

	switch {
	case reflected && credentials:
		return "high", fmt.Sprintf(
			"the response echoed back %q — an origin this target has never heard of — and set "+
				"Access-Control-Allow-Credentials: true. Any site a victim visits can therefore read this "+
				"response with the victim's session attached%s",
			model.ProbeOrigin, varyNote(varies))

	case reflected:
		return "medium", fmt.Sprintf(
			"the response echoed back %q — an origin this target has never heard of — so it reflects whatever "+
				"origin asks. Credentials are not allowed, so a session cannot be borrowed, but anything this "+
				"route returns without one is readable by any site%s",
			model.ProbeOrigin, varyNote(varies))

	case allowOrigin == "*" && credentials:
		return "low", "the response allows any origin (*) and also sets Access-Control-Allow-Credentials: true. " +
			"Browsers refuse that combination outright, so it cannot be used as it stands — it is reported because " +
			"a policy written this way was not understood, and the next edit may make it work"

	default:
		// A wildcard on its own, or a fixed allow-list that did not include
		// the probe. Both are deliberate answers, not mistakes.
		return "", ""
	}
}

// varyNote flags the cache half of a reflected origin. Without Vary: Origin
// a shared cache can store the response together with the header naming one
// origin, and then hand both to a different one.
func varyNote(varies bool) string {
	if varies {
		return ""
	}
	return "; the response also omits Vary: Origin, so a shared cache may store this answer and serve it to a different origin"
}

// headerListContains reports whether a comma-separated header value lists
// item, case-insensitively.
func headerListContains(raw, item string) bool {
	for part := range strings.SplitSeq(raw, ",") {
		if strings.EqualFold(strings.TrimSpace(part), item) {
			return true
		}
	}
	return false
}
