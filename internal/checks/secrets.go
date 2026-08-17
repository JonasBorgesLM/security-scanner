package checks

import (
	"bufio"
	"context"
	_ "embed"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
	"github.com/JonasBorgesLM/security-scanner/internal/ports"
)

//go:embed patterns/secrets.txt
var secretPatternsFile string

func init() {
	RegisterCheck(&exposedSecrets{patterns: mustParsePatterns(secretPatternsFile)})
}

// Confidence levels a pattern can declare. See patterns/secrets.txt.
const (
	confidenceHigh = "high"
	confidenceLow  = "low"
)

// maxFindingsPerPattern caps how many distinct values one pattern reports on
// a single endpoint. A response that leaks a thousand tokens is one finding
// worth acting on, not a thousand entries drowning the report.
const maxFindingsPerPattern = 5

// secretPattern is one line of the embedded pattern file.
type secretPattern struct {
	name       string
	confidence string
	re         *regexp.Regexp
}

// mustParsePatterns reads the embedded pattern list. It panics on a malformed
// line or a bad expression: the file ships inside the binary, so a problem
// here is a build-time mistake in first-party data, and failing at startup
// beats a check that silently stops matching.
func mustParsePatterns(contents string) []secretPattern {
	var patterns []secretPattern
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(strings.NewReader(contents))
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}

		name, rest, ok := strings.Cut(text, " ")
		if !ok {
			panic(fmt.Sprintf("checks: secrets.txt line %d: expected '<name> <confidence> <regexp>'", line))
		}
		confidence, expr, ok := strings.Cut(strings.TrimLeft(rest, " \t"), " ")
		if !ok {
			panic(fmt.Sprintf("checks: secrets.txt line %d: expected '<name> <confidence> <regexp>'", line))
		}
		expr = strings.TrimSpace(expr)

		if confidence != confidenceHigh && confidence != confidenceLow {
			panic(fmt.Sprintf("checks: secrets.txt line %d: pattern %q has confidence %q, want %q or %q",
				line, name, confidence, confidenceHigh, confidenceLow))
		}
		if seen[name] {
			panic(fmt.Sprintf("checks: secrets.txt line %d: duplicate pattern name %q", line, name))
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			panic(fmt.Sprintf("checks: secrets.txt line %d: pattern %q: %v", line, name, err))
		}

		seen[name] = true
		patterns = append(patterns, secretPattern{name: name, confidence: confidence, re: re})
	}
	if err := scanner.Err(); err != nil {
		panic(fmt.Sprintf("checks: reading secrets.txt: %v", err))
	}
	if len(patterns) == 0 {
		panic("checks: secrets.txt defines no patterns")
	}
	return patterns
}

// exposedSecrets looks for credentials left in a response body — including
// inside HTML and JavaScript comments, where debugging leftovers tend to
// survive review.
//
// It is passive: it reads the baseline the engine already collected, so it
// costs no request of its own.
type exposedSecrets struct {
	patterns []secretPattern
}

var _ model.Check = (*exposedSecrets)(nil)

func (c *exposedSecrets) Metadata() model.CheckMetadata {
	return model.CheckMetadata{
		Name:          "exposed-secrets",
		OWASPCategory: "A02:2021-Cryptographic Failures",
		Severity:      "high",
		Kind:          model.KindPassive,
	}
}

func (c *exposedSecrets) Run(_ context.Context, t model.Target, _ ports.HTTPClient) ([]model.Finding, error) {
	if t.Baseline == nil {
		return nil, model.Skippedf("no baseline response for %s %s: %v",
			t.Endpoint.Method, t.Endpoint.Path, t.BaselineErr)
	}

	body := t.Baseline.Body
	// A binary payload produces byte soup that matches nothing meaningful,
	// so scanning it can only generate noise.
	if len(body) == 0 || !utf8.Valid(body) {
		return nil, nil
	}
	text := string(body)
	comments := commentSpans(text)

	var findings []model.Finding
	for _, p := range c.patterns {
		findings = append(findings, c.scan(p, text, comments, t)...)
	}
	return findings, nil
}

// scan applies one pattern and turns surviving matches into findings.
func (c *exposedSecrets) scan(p secretPattern, text string, comments []span, t model.Target) []model.Finding {
	matches := p.re.FindAllStringSubmatchIndex(text, -1)
	if matches == nil {
		return nil
	}

	var findings []model.Finding
	reported := make(map[string]bool)

	for _, m := range matches {
		start, end := secretBounds(m)
		secret := text[start:end]

		// A low-confidence pattern matched an assignment, not a credential
		// shape. Documentation full of "password": "changeme" is not a leak,
		// and a check that reports it is one people learn to ignore.
		if p.confidence == confidenceLow && isPlaceholder(secret) {
			continue
		}
		// The same token repeated through a response is one problem.
		if reported[secret] {
			continue
		}
		reported[secret] = true

		if len(findings) >= maxFindingsPerPattern {
			break
		}

		findings = append(findings, model.Finding{
			ID:       findingDiscriminator(p.name, len(findings)),
			Severity: severityFor(p.confidence),
			Request: model.CapturedRequest{
				Method: t.Baseline.ProbedMethod,
				URL:    t.Baseline.URL,
			},
			Evidence: model.Evidence{
				ResponseSnippet: describe(p, secret, inSpan(comments, start)),
				StatusCode:      t.Baseline.StatusCode,
			},
		})
	}
	return findings
}

// secretBounds picks the span holding the secret: capture group 1 when the
// pattern defines one, the whole match otherwise. That is what lets a
// pattern anchor on the surrounding assignment while reporting only the
// value.
func secretBounds(match []int) (start, end int) {
	if len(match) >= 4 && match[2] >= 0 {
		return match[2], match[3]
	}
	return match[0], match[1]
}

func findingDiscriminator(name string, index int) string {
	if index == 0 {
		return name
	}
	return fmt.Sprintf("%s#%d", name, index)
}

func severityFor(confidence string) string {
	if confidence == confidenceHigh {
		return "high"
	}
	// A filtered generic match is still worth a look, but it has not proven
	// itself the way an AKIA prefix has.
	return "medium"
}

// describe renders the evidence line. The secret is redacted: findings.json
// is committed and diffed by hand, and a secrets scanner that writes secrets
// into a tracked file has moved the leak rather than found it.
func describe(p secretPattern, secret string, inComment bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s matched %s (%d chars)", p.name, redact(secret), utf8.RuneCountInString(secret))
	if inComment {
		b.WriteString(", inside a comment")
	}
	if p.confidence == confidenceLow {
		b.WriteString("; generic pattern, confirm before acting")
	}
	return b.String()
}

// redact keeps just enough of a value to locate it in the response without
// reproducing anything usable.
func redact(secret string) string {
	const keep = 4
	const maxMask = 16

	r := []rune(secret)
	if len(r) <= keep+2 {
		return strings.Repeat("*", len(r))
	}
	return string(r[:keep]) + strings.Repeat("*", min(len(r)-keep, maxMask))
}

// placeholderValues are the stand-ins that show up in examples, fixtures and
// redacted logs. A value equal to one of them is documentation, not a leak.
var placeholderValues = map[string]bool{
	"changeme": true, "example": true, "password": true, "placeholder": true,
	"redacted": true, "secret": true, "string": true, "test": true,
	"todo": true, "value": true, "yourpassword": true, "dummy": true,
	"none": true, "null": true, "undefined": true, "hidden": true,
}

// placeholderShapes catch the templated forms: ${VAR}, <your-token>,
// {{ token }}, your-api-key-here, xxxxxxxx, ********.
var placeholderShapes = regexp.MustCompile(`(?i)^(?:\$\{.*\}|<.*>|\{\{.*\}\}|%[sv]|your[_\-].*|.*[_\-]here|x+|\*+|\.+|-+|0+)$`)

// isPlaceholder reports whether a value is obviously not a real credential.
// This is where a generic-pattern check earns or loses its credibility: too
// permissive and the report is noise, too strict and it misses the leak.
func isPlaceholder(value string) bool {
	trimmed := strings.Trim(value, `"'`)
	if trimmed == "" {
		return true
	}

	normalised := strings.ToLower(strings.NewReplacer("_", "", "-", "", " ", "").Replace(trimmed))
	if placeholderValues[normalised] {
		return true
	}
	if placeholderShapes.MatchString(trimmed) {
		return true
	}

	// A real credential has variety. "aaaaaaaa" and "12341234" do not.
	distinct := make(map[rune]struct{}, len(trimmed))
	for _, r := range trimmed {
		distinct[r] = struct{}{}
	}
	return len(distinct) < 5
}

// span is a half-open byte range within the scanned text.
type span struct{ start, end int }

func inSpan(spans []span, offset int) bool {
	for _, s := range spans {
		if offset >= s.start && offset < s.end {
			return true
		}
	}
	return false
}

// blockComment covers HTML and C-style block comments. Line comments are
// handled separately because `//` also appears in every URL scheme.
var blockComment = regexp.MustCompile(`(?s)<!--.*?-->|/\*.*?\*/`)

// commentSpans locates the comment regions of a response, so a secret found
// in one can be called out: a credential in a leftover debug comment is a
// different kind of mistake from one in a JSON field, and usually a more
// embarrassing one.
func commentSpans(text string) []span {
	spans := blockComment.FindAllStringIndex(text, -1)

	out := make([]span, 0, len(spans))
	for _, s := range spans {
		out = append(out, span{start: s[0], end: s[1]})
	}
	out = append(out, lineCommentSpans(text)...)
	return out
}

// lineCommentSpans finds `//` comments, skipping two shapes that are not
// comments at all: the `://` of an absolute URL, and a protocol-relative
// URL ("//cdn.example.com/x") sitting as a bare JSON string value —
// preceded immediately by the opening quote, with nothing in between. A
// single-line JSON body has no newlines, so misreading either as a comment
// opener would mislabel the rest of the body — everything after it — as
// "inside a comment", including any secret that happens to follow.
func lineCommentSpans(text string) []span {
	var out []span

	for offset := 0; ; {
		i := strings.Index(text[offset:], "//")
		if i < 0 {
			return out
		}
		at := offset + i

		if at > 0 && (text[at-1] == ':' || text[at-1] == '"' || text[at-1] == '\'') {
			offset = at + 2
			continue
		}

		end := strings.IndexByte(text[at:], '\n')
		if end < 0 {
			return append(out, span{start: at, end: len(text)})
		}
		out = append(out, span{start: at, end: at + end})
		offset = at + end
	}
}
