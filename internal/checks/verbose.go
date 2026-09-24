package checks

import (
	"context"
	"fmt"
	"net/url"
	"regexp"

	"github.com/JonasBorgesLM/warden/internal/ports"

	"github.com/JonasBorgesLM/warden/internal/core/model"
)

func init() {
	RegisterCheck(&verboseErrors{})
}

// verboseProbe is the malformed value: a type-confusing, delimiter-heavy
// string meant to push a handler off its happy path and into an error it
// did not format carefully. It is inert — it neither injects nor escapes,
// it just is not what the endpoint expected.
const verboseProbe = `']["{{%00`

// leak is a signature of internal detail escaping into a response, with a
// name for the evidence. The patterns are deliberately specific: a check
// that flags the word "error" would fire on every well-formed error
// envelope, which is the opposite of the point.
type leak struct {
	name string
	re   *regexp.Regexp
}

var leaks = []leak{
	{"a Go stack trace", regexp.MustCompile(`goroutine \d+ \[|\.go:\d+ \+0x`)},
	{"a Python traceback", regexp.MustCompile(`Traceback \(most recent call last\)|File ".*", line \d+`)},
	{"a Java/JVM stack trace", regexp.MustCompile(`\bat [a-z0-9_.]+\.[A-Za-z0-9_$]+\([A-Za-z0-9_]+\.java:\d+\)`)},
	{"a Node.js stack trace", regexp.MustCompile(`\bat .+ \(.*:\d+:\d+\)`)},
	{"raw SQL or a database error", regexp.MustCompile(`(?i)SQLSTATE|syntax error at or near|SQL syntax.*MySQL|ORA-\d{5}|pq: `)},
	{"a filesystem path", regexp.MustCompile(`(?:/(?:home|usr|var|opt|root|app)/[^\s"']+|[A-Za-z]:\\[^\s"']+)`)},
}

// verboseErrors sends one malformed request per parameter and reports any
// response that answers with internal implementation detail — a stack
// trace, a raw SQL error, a filesystem path.
//
// # Why the baseline is the discriminator
//
// The signatures fire on things that also appear legitimately: a JSON body
// can mention a path, an API can return the string "error". So a match only
// counts when it is ABSENT from the endpoint's baseline. What the check
// reports is not "this looks like a stack trace" but "malformed input
// produced a stack trace the normal response did not have". That difference
// is the finding.
//
// It sends no body: a malformed query or path value is enough to trip a
// handler, and a body would drag it under the test_creates gate for no
// gain here.
type verboseErrors struct{}

var _ model.Check = (*verboseErrors)(nil)

func (c *verboseErrors) Metadata() model.CheckMetadata {
	return model.CheckMetadata{
		Name:          "verbose-errors",
		OWASPCategory: "A05:2021-Security Misconfiguration",
		Severity:      "medium",
		Kind:          model.KindActive,
		AppliesTo: func(ep model.Endpoint) bool {
			return len(injectableParameters(ep)) > 0
		},
	}
}

func (c *verboseErrors) Run(ctx context.Context, t model.Target, clients model.Clients) ([]model.Finding, error) {
	params, heldBack := usableParameters(t)
	if len(params) == 0 && heldBack > 0 {
		return nil, heldBackByCreates(t.Endpoint, heldBack)
	}
	if len(params) == 0 {
		return nil, nil
	}
	if t.Baseline == nil {
		return nil, model.Skippedf("no baseline response for %s %s, so a leak cannot be told from the route's normal output: %v",
			t.Endpoint.Method, t.Endpoint.Path, t.BaselineErr)
	}
	base, err := url.Parse(t.Baseline.URL)
	if err != nil {
		return nil, model.Skippedf("baseline URL %q is not parseable: %v", t.Baseline.URL, err)
	}
	origin := &url.URL{Scheme: base.Scheme, Host: base.Host}
	baselineBody := string(t.Baseline.Body)

	res := runPerParameter(params, func(p model.Parameter) (*model.Finding, error) {
		return c.testParameter(ctx, clients.Default, t.Endpoint, origin, params, p, baselineBody)
	})
	return res.outcome(t.Endpoint, params, heldBack)
}

func (c *verboseErrors) testParameter(
	ctx context.Context,
	client ports.HTTPClient,
	ep model.Endpoint,
	origin *url.URL,
	all []model.Parameter,
	target model.Parameter,
	baselineBody string,
) (*model.Finding, error) {
	probe, err := sendProbe(ctx, client, "verbose-errors", ep, origin, all, target, verboseProbe)
	if err != nil {
		return nil, err
	}
	body := string(probe.body)

	name, leaked := LooksLikeErrorLeak(body)
	if leaked {
		// Already present without malformed input — this is the route's
		// normal output, not a leak the probe caused.
		if _, inBaseline := LooksLikeErrorLeak(baselineBody); inBaseline {
			leaked = false
		}
	}
	if leaked {
		return &model.Finding{
			ID: target.Name,
			Request: model.CapturedRequest{
				Method:        ep.Method,
				URL:           probe.url,
				InjectedParam: target.Name,
				Payload:       verboseProbe,
			},
			Evidence: model.Evidence{
				StatusCode: probe.status,
				ResponseSnippet: fmt.Sprintf(
					"malformed input to %q produced %s that the normal response does not contain — internal implementation detail is leaking into error output: %s",
					target.Name, name, snippetOfN(probe.body, sqliSnippetLimit)),
			},
		}, nil
	}
	return nil, nil
}

// LooksLikeErrorLeak reports whether body contains a signature of internal
// implementation detail — a stack trace, a raw database error, a filesystem
// path — and names the first one it finds. Exported so the attack stage's
// confirmer recognises the same leaks the check does, from one definition.
func LooksLikeErrorLeak(body string) (name string, found bool) {
	for _, l := range leaks {
		if l.re.MatchString(body) {
			return l.name, true
		}
	}
	return "", false
}
