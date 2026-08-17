package checks

import (
	"bufio"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
	"github.com/JonasBorgesLM/security-scanner/internal/ports"
)

func init() {
	RegisterCheck(&xssReflected{templates: xssMarkerTemplates})
}

//go:embed payloads/xss.txt
var xssPayloadsFile string

// xssMarkerTemplates is parsed once at package init rather than per call —
// the same reasoning as sqliPairs in sqli.go.
var xssMarkerTemplates = mustParseMarkerTemplates(xssPayloadsFile)

// xssProbeFiller is the benign value used for every parameter that is not
// currently under test, and for the baseline request. Kept separate from
// sqli.go's sqliProbeFiller (even though both are just "1") so this file
// does not read as silently depending on another check's constant.
const xssProbeFiller = "1"

// xssMarkerHexLen is how many hex characters of the derived digest go into
// a marker. 16 (8 bytes) is plenty to make an accidental collision with
// existing page content vanishingly unlikely, and matches the width of the
// attack stage's own re-verification marker.
const xssMarkerHexLen = 16

// xssMarkerTemplate is one candidate marker shape from payloads/xss.txt.
type xssMarkerTemplate struct {
	name   string
	prefix string
	suffix string
}

// mustParseMarkerTemplates reads the embedded template list. It panics on a
// malformed line, the same rationale as sqli.go's mustParsePayloadPairs:
// this file ships inside the binary, so a problem here is a build-time
// mistake in first-party data, not a runtime condition.
func mustParseMarkerTemplates(contents string) []xssMarkerTemplate {
	var templates []xssMarkerTemplate
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(strings.NewReader(contents))
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}

		fields := strings.SplitN(text, "|||", 3)
		if len(fields) != 3 {
			panic(fmt.Sprintf("checks: xss.txt line %d: expected '<name> ||| <prefix> ||| <suffix>'", line))
		}
		name := strings.TrimSpace(fields[0])
		prefix := strings.TrimSpace(fields[1])
		suffix := strings.TrimSpace(fields[2])

		if name == "" {
			panic(fmt.Sprintf("checks: xss.txt line %d: name must not be empty", line))
		}
		if prefix == "" && suffix == "" {
			panic(fmt.Sprintf("checks: xss.txt line %d: prefix and suffix must not both be empty — an unbracketed random value proves nothing about escaping", line))
		}
		if seen[name] {
			panic(fmt.Sprintf("checks: xss.txt line %d: duplicate pattern name %q", line, name))
		}

		seen[name] = true
		templates = append(templates, xssMarkerTemplate{name: name, prefix: prefix, suffix: suffix})
	}
	if err := scanner.Err(); err != nil {
		panic(fmt.Sprintf("checks: reading xss.txt: %v", err))
	}
	if len(templates) == 0 {
		panic("checks: xss.txt defines no marker templates")
	}
	return templates
}

// xssReflected looks for reflected XSS in query and path parameters: for
// each one, it fetches a clean baseline with an inert value, then injects a
// marker unique to this probe and checks whether that exact marker comes
// back unescaped — present in the response body as literal '<'/'>', not as
// '&lt;'/'&gt;'.
//
// It is active — the technique only works by sending crafted requests, so
// unlike the passive checks it is given the real, rate-limited client. Like
// sqli.go, it does not read Target.Baseline's body (that baseline was
// fetched with no parameters filled in, so it cannot answer "does this
// parameter reflect unescaped"); it only reuses Target.Baseline.URL for the
// target's scheme and host.
type xssReflected struct {
	templates []xssMarkerTemplate
}

var _ model.Check = (*xssReflected)(nil)

func (c *xssReflected) Metadata() model.CheckMetadata {
	return model.CheckMetadata{
		Name:          "xss-reflected",
		OWASPCategory: "A03:2021-Injection",
		Severity:      "high",
		Kind:          model.KindActive,
		AppliesTo: func(ep model.Endpoint) bool {
			return len(injectableParameters(ep)) > 0
		},
	}
}

func (c *xssReflected) Run(ctx context.Context, t model.Target, client ports.HTTPClient) ([]model.Finding, error) {
	params := injectableParameters(t.Endpoint)
	if len(params) == 0 {
		// AppliesTo should already have kept this job from being created;
		// staying correct here too costs nothing.
		return nil, nil
	}
	if t.Baseline == nil {
		return nil, model.Skippedf("no baseline response for %s %s, so the target's origin is unknown: %v",
			t.Endpoint.Method, t.Endpoint.Path, t.BaselineErr)
	}
	base, err := url.Parse(t.Baseline.URL)
	if err != nil {
		return nil, model.Skippedf("baseline URL %q is not parseable: %v", t.Baseline.URL, err)
	}
	origin := &url.URL{Scheme: base.Scheme, Host: base.Host}

	var findings []model.Finding
	tested := 0
	var lastErr error
	for _, target := range params {
		f, err := c.testParameter(ctx, client, t.Endpoint, origin, params, target)
		if err != nil {
			lastErr = err
			continue
		}
		tested++
		if f != nil {
			findings = append(findings, *f)
		}
	}

	if tested == 0 {
		return nil, model.Skippedf("could not test any parameter of %s %s: %v",
			t.Endpoint.Method, t.Endpoint.Path, lastErr)
	}
	return findings, nil
}

// testParameter fetches one clean baseline for target (every parameter,
// including target itself, set to the inert filler — no marker anywhere
// yet), then tries each marker template in turn against target alone,
// stopping at the first one that reflects unescaped.
//
// A marker only counts if it clears two conditions, not one: reflected raw
// in the probe response, AND absent from the baseline response. The second
// half is what stands between this and a false positive — a page that
// happens to already contain unescaped markup near this parameter
// regardless of input (a neighbouring field, static page furniture) would
// otherwise look identical to a genuine reflection. In practice a freshly
// random marker can only appear in the baseline by matching this exact
// check twice in a row, which does not happen — but the comparison is
// cheap and the invariant it protects (never flag something the baseline
// already shows was there before injection) is the same discipline
// sqli.go's noise floor exists for.
func (c *xssReflected) testParameter(
	ctx context.Context,
	client ports.HTTPClient,
	ep model.Endpoint,
	origin *url.URL,
	all []model.Parameter,
	target model.Parameter,
) (*model.Finding, error) {
	baseline, err := sendProbe(ctx, client, "xss", ep, origin, all, target, xssProbeFiller)
	if err != nil {
		return nil, fmt.Errorf("fetching baseline for %q: %w", target.Name, err)
	}
	baselineBody := string(baseline.body)

	for _, tmpl := range c.templates {
		// The marker's variable segment is derived deterministically from
		// the injection point, NOT random: findings.json is committed and
		// diffed by hand, so two scans of an unchanged target must produce
		// byte-identical output (invariant #8). A random marker here would
		// make every re-scan show a spurious diff. Freshness only matters
		// at attack time (proving current, un-cached exploitability), which
		// is why internal/attack's confirmer generates its own random
		// marker instead of reusing this one.
		marker := markerValue(ep, target, tmpl)
		// This exact string is what goes into the request AND into
		// CapturedRequest.Payload below — internal/attack's confirmer
		// reconstructs the request later by finding Payload as a literal
		// substring, so the two must never diverge.
		payload := tmpl.prefix + marker + tmpl.suffix

		probeRes, err := sendProbe(ctx, client, "xss", ep, origin, all, target, payload)
		if err != nil {
			continue // this template is untestable; the next one might not be
		}
		probeBody := string(probeRes.body)

		if !strings.Contains(probeBody, payload) {
			// Not reflected raw at all — either HTML-escaped (safe) or not
			// reflected in this response in any form.
			continue
		}
		if strings.Contains(baselineBody, payload) {
			// The marker is random per probe, so this should be
			// unreachable in practice; treated as "not this parameter"
			// rather than trusted, per the doc comment above.
			continue
		}

		return &model.Finding{
			// Discriminator only: the engine namespaces this with the
			// check name and endpoint to build the final, stable ID.
			ID: target.Name,
			Request: model.CapturedRequest{
				Method: ep.Method,
				URL:    probeRes.url,
				// No custom headers or body: this check only injects into
				// query and path parameters, so the request that produced
				// the finding carries neither.
				InjectedParam: target.Name,
				Payload:       payload,
			},
			Evidence: model.Evidence{
				BaselineResponse: snippetOf(baseline.body),
				ResponseSnippet: fmt.Sprintf(
					"marker %q (template %q) reflected unescaped in the response body", payload, tmpl.name),
				StatusCode: probeRes.status,
				// ResponseTime deliberately left zero: this finding is
				// about literal reflection, not timing, and wall-clock
				// here would make two identical scans produce different
				// files.
			},
		}, nil
	}
	return nil, nil
}

// markerValue derives the variable segment of a probe's marker from the
// injection point (method, path, parameter, template name), so it is stable
// across runs but distinct per injection point — a reflection found on
// ?q= must not carry the same marker as one on ?name=, or the two findings
// would be indistinguishable. It is deliberately NOT random: see the call
// site for why scan-time determinism matters and attack-time freshness does
// not live here. SHA-256 is used only as a fixed-length, collision-resistant
// mixer of the key; there is nothing secret about a marker.
func markerValue(ep model.Endpoint, target model.Parameter, tmpl xssMarkerTemplate) string {
	key := strings.Join([]string{ep.Method, ep.Path, target.In, target.Name, tmpl.name}, "\x00")
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])[:xssMarkerHexLen]
}
