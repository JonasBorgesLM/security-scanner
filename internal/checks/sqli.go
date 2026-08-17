package checks

import (
	"bufio"
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
	"github.com/JonasBorgesLM/security-scanner/internal/ports"
)

//go:embed payloads/sqli.txt
var sqliPayloadsFile string

// sqliPairs is parsed once at package init rather than per call, since both
// the check itself and FalsePayloadFor (used by the attack stage) need it.
var sqliPairs = mustParsePayloadPairs(sqliPayloadsFile)

func init() {
	RegisterCheck(&sqliBoolean{pairs: sqliPairs})
}

// FalsePayloadFor returns the false-condition payload paired with a
// true-condition one in payloads/sqli.txt, so a later pipeline stage (the
// attack command) can reconstruct the same true/false comparison this check
// made without re-parsing the payload file or duplicating the pairing.
func FalsePayloadFor(truePayload string) (string, bool) {
	for _, p := range sqliPairs {
		if p.truePayload == truePayload {
			return p.falsePayload, true
		}
	}
	return "", false
}

// sqliNoiseSamples is how many times the check probes each parameter with a
// benign, unchanging value before injecting anything. Dynamic content
// (timestamps, request IDs, CSRF tokens) makes even an unmodified response
// vary run to run; this measures how much, so that variance is never
// mistaken for a signal (invariant #4).
//
// Three is a compromise: enough to see repeat-to-repeat noise at all,
// without spending five requests per parameter just to establish a
// baseline — this check already costs samples+2 requests per candidate
// pair, and being gentle to the target is a design goal.
const sqliNoiseSamples = 3

// sqliProbeFiller is the benign value used for every parameter that is not
// currently under test, and for the noise-measurement samples. It is
// deliberately inert: this check must never itself be the reason a route
// misbehaves.
const sqliProbeFiller = "1"

// sqliSnippetLimit bounds how much response text lands in a Finding's
// evidence, so findings.json stays reviewable rather than embedding whole
// bodies.
const sqliSnippetLimit = 200

// payloadPair is one true/false probe from payloads/sqli.txt.
type payloadPair struct {
	name         string
	truePayload  string
	falsePayload string
}

// mustParsePayloadPairs reads the embedded payload file. It panics on a
// malformed line: the file ships inside the binary, so a problem here is a
// build-time mistake in first-party data, and failing at startup beats a
// check that silently has no payloads.
func mustParsePayloadPairs(contents string) []payloadPair {
	var pairs []payloadPair
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(strings.NewReader(contents))
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}

		fields := strings.SplitN(text, "|||", 3)
		if len(fields) != 3 {
			panic(fmt.Sprintf("checks: sqli.txt line %d: expected '<name> ||| <true-payload> ||| <false-payload>'", line))
		}
		name := strings.TrimSpace(fields[0])
		truePayload := strings.TrimSpace(fields[1])
		falsePayload := strings.TrimSpace(fields[2])

		if name == "" || truePayload == "" || falsePayload == "" {
			panic(fmt.Sprintf("checks: sqli.txt line %d: name, true-payload and false-payload must all be non-empty", line))
		}
		if truePayload == falsePayload {
			panic(fmt.Sprintf("checks: sqli.txt line %d: pattern %q has identical true/false payloads, so it could never show a difference", line, name))
		}
		if seen[name] {
			panic(fmt.Sprintf("checks: sqli.txt line %d: duplicate pattern name %q", line, name))
		}

		seen[name] = true
		pairs = append(pairs, payloadPair{name: name, truePayload: truePayload, falsePayload: falsePayload})
	}
	if err := scanner.Err(); err != nil {
		panic(fmt.Sprintf("checks: reading sqli.txt: %v", err))
	}
	if len(pairs) == 0 {
		panic("checks: sqli.txt defines no payload pairs")
	}
	return pairs
}

// sqliBoolean looks for boolean-based SQL injection in query and path
// parameters: it injects an "always true" and an "always false" variant of
// the same condition into one parameter at a time and compares the two
// responses.
//
// It is active — the technique only works by sending crafted requests, so
// unlike the passive checks it is given the real, rate-limited client. It
// deliberately does not read Target.Baseline's body: that baseline was
// fetched without any parameters filled in, which is useless for a check
// whose entire method is "does changing this one parameter change the
// response". It does reuse Target.Baseline.URL for the target's scheme and
// host, since nothing else in the Check contract carries that.
//
// Probes are sent with the endpoint's own method, not forced to GET. This
// follows the project's own stated scope ("só testa métodos seguros: GET,
// POST de teste" — doc §1): DELETE/PUT/PATCH never reach this check at all
// (the engine's non-destructive gate filters Destructive endpoints out of
// every job, this one included), but POST is deliberately in scope. The
// tradeoff worth knowing: a POST endpoint that turns out NOT to be
// vulnerable still absorbs up to sqliNoiseSamples+2*len(pairs) requests per
// parameter while this check rules it out — and if that route creates a
// resource on every call, that is real (if modest, rate-limited) test data
// left behind, not just load. Forcing GET instead would avoid that, but a
// server routing strictly by method would then 404 every probe and the
// check would silently clear a route it never actually exercised — a worse
// failure mode than some junk rows in the operator's own lab.
type sqliBoolean struct {
	pairs []payloadPair
}

var _ model.Check = (*sqliBoolean)(nil)

func (c *sqliBoolean) Metadata() model.CheckMetadata {
	return model.CheckMetadata{
		Name:          "sqli-boolean",
		OWASPCategory: "A03:2021-Injection",
		Severity:      "high",
		Kind:          model.KindActive,
		AppliesTo: func(ep model.Endpoint) bool {
			return len(injectableParameters(ep)) > 0
		},
	}
}

// injectableParameters returns the query and path parameters of an
// endpoint. Header and body injection are out of scope for this check —
// query/path covers the common case, and body injection needs to know the
// shape of the payload, not just a string to substitute.
func injectableParameters(ep model.Endpoint) []model.Parameter {
	var out []model.Parameter
	for _, p := range ep.Parameters {
		if p.In == "query" || p.In == "path" {
			out = append(out, p)
		}
	}
	return out
}

func (c *sqliBoolean) Run(ctx context.Context, t model.Target, client ports.HTTPClient) ([]model.Finding, error) {
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
		// Every parameter failed even the noise-measurement stage — there
		// is nothing to conclude, not even "clean".
		return nil, model.Skippedf("could not test any parameter of %s %s: %v",
			t.Endpoint.Method, t.Endpoint.Path, lastErr)
	}
	return findings, nil
}

// testParameter measures the noise floor for one parameter and then tries
// each payload pair in turn, stopping at the first one whose true/false
// difference clears that floor. Trying pairs in a fixed order rather than
// all of them keeps the request cost bounded on an endpoint that turns out
// to be vulnerable, while still trying every pair on one that is not.
func (c *sqliBoolean) testParameter(
	ctx context.Context,
	client ports.HTTPClient,
	ep model.Endpoint,
	origin *url.URL,
	all []model.Parameter,
	target model.Parameter,
) (*model.Finding, error) {
	noise, sample, err := c.measureNoise(ctx, client, ep, origin, all, target)
	if err != nil {
		return nil, fmt.Errorf("measuring baseline noise for %q: %w", target.Name, err)
	}

	for _, pair := range c.pairs {
		trueResp, err := sendProbe(ctx, client, "sqli", ep, origin, all, target, pair.truePayload)
		if err != nil {
			continue // this pair is untestable; the next one might not be
		}
		falseResp, err := sendProbe(ctx, client, "sqli", ep, origin, all, target, pair.falsePayload)
		if err != nil {
			continue
		}

		diff := absInt(len(trueResp.body) - len(falseResp.body))
		if diff <= noise {
			// Within the range already observed from three identical
			// requests — indistinguishable from ordinary churn.
			continue
		}

		return &model.Finding{
			// Discriminator only: the engine namespaces this with the check
			// name and endpoint to build the final, stable ID.
			ID: target.Name,
			Request: model.CapturedRequest{
				Method: ep.Method,
				URL:    trueResp.url,
				// No custom headers or body: this check only injects into
				// query and path parameters, so the request that produced
				// the finding carries neither.
				InjectedParam: target.Name,
				Payload:       pair.truePayload,
			},
			Evidence: model.Evidence{
				BaselineResponse: snippetOf(sample),
				ResponseSnippet: fmt.Sprintf(
					"%q vs %q differ by %d bytes (noise from %d repeats was %d); true-payload response: %s",
					pair.truePayload, pair.falsePayload, diff, sqliNoiseSamples, noise, snippetOf(trueResp.body)),
				StatusCode: trueResp.status,
				// ResponseTime deliberately left zero: this is a
				// content-length signal, not a timing one, and wall-clock
				// here would make two identical scans produce different
				// files.
			},
		}, nil
	}
	return nil, nil
}

// measureNoise sends the same benign request sqliNoiseSamples times and
// returns the largest difference in body length seen between any two of
// them — the amount of pure run-to-run variation this endpoint has before
// anything is injected. The last sample is kept as evidence.
func (c *sqliBoolean) measureNoise(
	ctx context.Context,
	client ports.HTTPClient,
	ep model.Endpoint,
	origin *url.URL,
	all []model.Parameter,
	target model.Parameter,
) (noise int, lastSample []byte, err error) {
	minLen, maxLen := -1, -1

	for range sqliNoiseSamples {
		res, err := sendProbe(ctx, client, "sqli", ep, origin, all, target, sqliProbeFiller)
		if err != nil {
			return 0, nil, err
		}
		n := len(res.body)
		if minLen == -1 || n < minLen {
			minLen = n
		}
		if n > maxLen {
			maxLen = n
		}
		lastSample = res.body
	}
	return maxLen - minLen, lastSample, nil
}

// probeResult is one HTTP response boiled down to what an active check
// compares. Shared with xss-reflected; see sendProbe in probe.go.
type probeResult struct {
	url    string
	status int
	body   []byte
}

// buildProbeRequest fills every injectable parameter with the inert filler
// except target, which gets value, and returns the resulting request. Path
// parameters are substituted into the path template; query parameters are
// URL-encoded normally. Neither is left to net/http to escape ad hoc, so
// the same payload always produces the same URL.
func buildProbeRequest(
	ctx context.Context,
	ep model.Endpoint,
	origin *url.URL,
	all []model.Parameter,
	target model.Parameter,
	value string,
) (*http.Request, error) {
	path := ep.Path
	query := url.Values{}

	for _, p := range all {
		v := sqliProbeFiller
		if p.Name == target.Name && p.In == target.In {
			v = value
		}
		switch p.In {
		case "path":
			path = strings.Replace(path, "{"+p.Name+"}", url.PathEscape(v), 1)
		case "query":
			query.Set(p.Name, v)
		}
	}

	full := origin.String() + path
	if q := query.Encode(); q != "" {
		full += "?" + q
	}

	req, err := http.NewRequestWithContext(ctx, ep.Method, full, nil)
	if err != nil {
		return nil, fmt.Errorf("checks: sqli: building request for %s %s: %w", ep.Method, ep.Path, err)
	}
	return req, nil
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// snippetOf renders a short, single-line excerpt of a response body for
// evidence — collapsing whitespace so a formatted JSON body doesn't blow up
// the line count of a reviewed findings.json.
func snippetOf(body []byte) string {
	s := strings.Join(strings.Fields(string(body)), " ")
	if s == "" {
		return "<empty body>"
	}
	r := []rune(s)
	if len(r) > sqliSnippetLimit {
		return string(r[:sqliSnippetLimit]) + "…"
	}
	return s
}
