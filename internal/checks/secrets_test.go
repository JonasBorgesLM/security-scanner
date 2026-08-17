package checks

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

func secretsCheck() *exposedSecrets {
	return &exposedSecrets{patterns: mustParsePatterns(secretPatternsFile)}
}

// bodyTarget wraps a raw response body as a Target.
func bodyTarget(body string) model.Target {
	return model.Target{
		Endpoint: model.Endpoint{Method: "GET", Path: "/items"},
		Baseline: &model.Response{
			URL:          "http://lab.invalid:8080/items",
			StatusCode:   http.StatusOK,
			Headers:      http.Header{},
			Body:         []byte(body),
			ProbedMethod: "GET",
		},
	}
}

// fixtureTarget loads one of the testdata bodies.
func fixtureTarget(t *testing.T, name string) model.Target {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "secrets", name))
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", name, err)
	}
	return bodyTarget(string(body))
}

func runSecrets(t *testing.T, target model.Target) []model.Finding {
	t.Helper()
	// nil client on purpose: a passive check must never reach for it.
	findings, err := secretsCheck().Run(t.Context(), target, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	return findings
}

// patternsHit lists which patterns fired, stripped of the #N suffix that
// distinguishes repeated hits.
func patternsHit(findings []model.Finding) []string {
	var out []string
	for _, f := range findings {
		name, _, _ := strings.Cut(f.ID, "#")
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

func evidence(findings []model.Finding) string {
	var b strings.Builder
	for _, f := range findings {
		b.WriteString(f.Evidence.ResponseSnippet)
		b.WriteString("\n")
	}
	return b.String()
}

// ------------------------------------------------------------------ metadata

func TestExposedSecrets_Metadata(t *testing.T) {
	meta := secretsCheck().Metadata()

	if meta.Name != "exposed-secrets" {
		t.Errorf("Name = %q", meta.Name)
	}
	if meta.Kind != model.KindPassive {
		t.Errorf("Kind = %q, want passive", meta.Kind)
	}
	if meta.Severity != "high" {
		t.Errorf("Severity = %q, want high", meta.Severity)
	}
	if !strings.HasPrefix(meta.OWASPCategory, "A02") {
		t.Errorf("OWASPCategory = %q, want an A02 category", meta.OWASPCategory)
	}
}

func TestExposedSecrets_RegisteredByInit(t *testing.T) {
	if names := Names(); !slices.Contains(names, "exposed-secrets") {
		t.Errorf("registered checks = %v, want exposed-secrets among them", names)
	}
}

// ------------------------------------------------------- fixtures WITH secrets

func TestExposedSecrets_FindsSecretsInFixtures(t *testing.T) {
	tests := []struct {
		fixture string
		want    []string
	}{
		{
			"leaky-config.json",
			[]string{"aws-access-key-id", "connection-string"},
		},
		{
			"leaky-comments.html",
			[]string{"generic-api-key", "github-token"},
		},
		{"leaky-jwt.json", []string{"json-web-token"}},
		{"leaky-private-key.txt", []string{"private-key-block"}},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			findings := runSecrets(t, fixtureTarget(t, tt.fixture))
			if got := patternsHit(findings); !slices.Equal(got, tt.want) {
				t.Errorf("patterns hit = %v, want %v\nevidence:\n%s", got, tt.want, evidence(findings))
			}
		})
	}
}

// The Stripe secret-key pattern is exercised here, built at runtime from
// fragments, rather than in a testdata fixture: a contiguous string shaped
// like a real Stripe key trips GitHub's push protection even in a file that
// exists only to prove a detector rejects/accepts it, live or test mode.
func TestExposedSecrets_StripeSecretKeyShape(t *testing.T) {
	key := "sk" + "_" + "test" + "_" + "4eC39HqLyjWDarjtT1zdp7dc"
	body := `{"stripe":{"secret":"` + key + `"}}`

	findings := runSecrets(t, bodyTarget(body))
	if got := patternsHit(findings); !slices.Equal(got, []string{"stripe-secret-key"}) {
		t.Fatalf("patterns hit = %v, want stripe-secret-key\n%s", got, evidence(findings))
	}
}

// A secret sitting in a leftover debug comment is a different, usually more
// embarrassing, mistake — the report should say so. The fixture puts one in
// an HTML block comment and one in a JavaScript line comment.
func TestExposedSecrets_NotesSecretsInsideComments(t *testing.T) {
	findings := runSecrets(t, fixtureTarget(t, "leaky-comments.html"))

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2\n%s", len(findings), evidence(findings))
	}
	for _, f := range findings {
		if !strings.Contains(f.Evidence.ResponseSnippet, "inside a comment") {
			t.Errorf("%s: evidence = %q, want it flagged as in-comment", f.ID, f.Evidence.ResponseSnippet)
		}
	}
}

// The flag has to discriminate: the same token in ordinary JSON is still a
// finding, but not a comment one.
func TestExposedSecrets_DoesNotClaimCommentForPlainContent(t *testing.T) {
	findings := runSecrets(t, fixtureTarget(t, "leaky-outside-comment.json"))

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1\n%s", len(findings), evidence(findings))
	}
	if strings.Contains(findings[0].Evidence.ResponseSnippet, "inside a comment") {
		t.Errorf("evidence = %q, want no comment claim", findings[0].Evidence.ResponseSnippet)
	}
}

// The `//` of a URL scheme is not a comment; treating it as one would mark
// half of every JSON body as commented out.
func TestExposedSecrets_URLSchemeIsNotAComment(t *testing.T) {
	findings := runSecrets(t, bodyTarget(
		`{"docs":"https://example.com/x","aws":"AKIAIOSFODNN7EXAMPLE"}`))

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if strings.Contains(findings[0].Evidence.ResponseSnippet, "inside a comment") {
		t.Errorf("evidence = %q, want no comment claim — `//` there is a URL scheme",
			findings[0].Evidence.ResponseSnippet)
	}
}

// --------------------------------------------------- fixtures WITHOUT secrets

func TestExposedSecrets_QuietOnCleanFixtures(t *testing.T) {
	for _, fixture := range []string{"clean-api.json", "clean-placeholders.json", "clean-docs.html"} {
		t.Run(fixture, func(t *testing.T) {
			findings := runSecrets(t, fixtureTarget(t, fixture))
			if len(findings) != 0 {
				t.Errorf("got %d findings, want none\n%s", len(findings), evidence(findings))
			}
		})
	}
}

// The generic patterns are where a secrets check earns or loses its
// credibility. Every one of these is an assignment that *looks* like a
// credential and is not.
func TestExposedSecrets_IgnoresObviousPlaceholders(t *testing.T) {
	placeholders := []string{
		`{"api_key": "your-api-key-here"}`,
		`{"api_key": "YOUR_API_KEY_HERE"}`,
		`{"password": "changeme"}`,
		`{"password": "password"}`,
		`{"access_token": "<YOUR_TOKEN>"}`,
		`{"client_secret": "${CLIENT_SECRET}"}`,
		`{"auth_token": "{{ token }}"}`,
		`{"secret_key": "xxxxxxxxxxxxxxxx"}`,
		`{"secret_key": "****************"}`,
		`{"api_key": "aaaaaaaaaaaa"}`,
		`{"password": "------------"}`,
		`{"password": "REDACTED"}`,
		`{"api_key": "example"}`,
		`api_key = "TODO"`,
		`Authorization: Bearer <your-token-goes-here>`,
	}
	for _, body := range placeholders {
		t.Run(body, func(t *testing.T) {
			if findings := runSecrets(t, bodyTarget(body)); len(findings) != 0 {
				t.Errorf("reported %v for a placeholder\n%s", patternsHit(findings), evidence(findings))
			}
		})
	}
}

// Ordinary API content that happens to contain long opaque strings must not
// be mistaken for credentials.
func TestExposedSecrets_IgnoresOrdinaryIdentifiers(t *testing.T) {
	bodies := []string{
		`{"request_id": "8f14e45fceea167a5a36dedd4bea2543"}`,
		`{"id": "550e8400-e29b-41d4-a716-446655440000"}`,
		`{"etag": "W/\"686897696a7c876b7e\""}`,
		`{"sha": "e83c5163316f89bfbde7d9ab23ca2e25604af290"}`,
		`{"next": "https://api.example.com/items?cursor=Y3Vyc29yOjEwMA"}`,
		`{"content": "the password field is required"}`,
	}
	for _, body := range bodies {
		t.Run(body, func(t *testing.T) {
			if findings := runSecrets(t, bodyTarget(body)); len(findings) != 0 {
				t.Errorf("reported %v for ordinary content\n%s", patternsHit(findings), evidence(findings))
			}
		})
	}
}

// A real-looking value must still get through the placeholder filter.
func TestExposedSecrets_StillReportsRealLookingGenericValues(t *testing.T) {
	findings := runSecrets(t, bodyTarget(`{"api_key": "a7Fq93Ldm2Xp01Zc"}`))

	if got := patternsHit(findings); !slices.Equal(got, []string{"generic-api-key"}) {
		t.Fatalf("patterns hit = %v, want generic-api-key", got)
	}
	if findings[0].Severity != "medium" {
		t.Errorf("Severity = %q, want medium — a generic match is not proof", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Evidence.ResponseSnippet, "confirm before acting") {
		t.Errorf("evidence = %q, want it to flag the match as unconfirmed", findings[0].Evidence.ResponseSnippet)
	}
}

// ----------------------------------------------------------------- redaction

// A secrets scanner that writes secrets into a committed findings.json has
// moved the leak, not found it.
func TestExposedSecrets_RedactsTheSecret(t *testing.T) {
	const key = "AKIAIOSFODNN7EXAMPLE"
	findings := runSecrets(t, bodyTarget(`{"aws_access_key_id": "`+key+`"}`))

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	snippet := findings[0].Evidence.ResponseSnippet

	if strings.Contains(snippet, key) {
		t.Errorf("evidence contains the secret verbatim: %q", snippet)
	}
	if !strings.Contains(snippet, "AKIA") {
		t.Errorf("evidence = %q, want a short prefix so the value can be located", snippet)
	}
	if !strings.Contains(snippet, "*") {
		t.Errorf("evidence = %q, want the remainder masked", snippet)
	}
	if !strings.Contains(snippet, "20 chars") {
		t.Errorf("evidence = %q, want the length reported", snippet)
	}
}

func TestRedact(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"abc", "***"},
		{"abcdef", "******"},
		{"abcdefg", "abcd***"},
		{strings.Repeat("z", 40), "zzzz" + strings.Repeat("*", 16)},
	}
	for _, tt := range tests {
		if got := redact(tt.in); got != tt.want {
			t.Errorf("redact(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// ------------------------------------------------------------------ behaviour

func TestExposedSecrets_DeduplicatesRepeatedValues(t *testing.T) {
	const key = "AKIAIOSFODNN7EXAMPLE"
	body := strings.Repeat(`{"k":"`+key+`"}`+"\n", 20)

	if findings := runSecrets(t, bodyTarget(body)); len(findings) != 1 {
		t.Errorf("got %d findings, want 1 — the same token repeated is one problem", len(findings))
	}
}

func TestExposedSecrets_CapsFindingsPerPattern(t *testing.T) {
	var b strings.Builder
	for i := range 40 {
		// AKIA plus exactly sixteen characters, so each line is a distinct
		// well-formed key.
		fmt.Fprintf(&b, "{\"k\":\"AKIA%016d\"}\n", i)
	}

	findings := runSecrets(t, bodyTarget(b.String()))
	if len(findings) > maxFindingsPerPattern {
		t.Errorf("got %d findings, want at most %d — a flood must not drown the report",
			len(findings), maxFindingsPerPattern)
	}
	if len(findings) == 0 {
		t.Error("got 0 findings, want the cap reached")
	}
}

func TestExposedSecrets_SkipsWithoutABaseline(t *testing.T) {
	failed := model.Target{
		Endpoint:    model.Endpoint{Method: "GET", Path: "/items"},
		BaselineErr: errors.New("connection refused"),
	}

	_, err := secretsCheck().Run(t.Context(), failed, nil)
	if !errors.Is(err, model.ErrSkipped) {
		t.Fatalf("error = %v, want it to wrap model.ErrSkipped", err)
	}
}

func TestExposedSecrets_IgnoresEmptyAndBinaryBodies(t *testing.T) {
	if findings := runSecrets(t, bodyTarget("")); len(findings) != 0 {
		t.Errorf("got %d findings for an empty body", len(findings))
	}

	binary := bodyTarget("")
	binary.Baseline.Body = []byte{0xff, 0xfe, 0x00, 0x01, 0x80, 0x90}
	if findings := runSecrets(t, binary); len(findings) != 0 {
		t.Errorf("got %d findings for a binary body — byte soup can only be noise", len(findings))
	}
}

func TestExposedSecrets_IsDeterministic(t *testing.T) {
	target := fixtureTarget(t, "leaky-config.json")

	var first []string
	for run := range 20 {
		var ids []string
		for _, f := range runSecrets(t, target) {
			ids = append(ids, f.ID)
		}
		if run == 0 {
			first = ids
			continue
		}
		if !slices.Equal(ids, first) {
			t.Fatalf("run %d = %v, differs from first run %v", run, ids, first)
		}
	}
}

// ----------------------------------------------------------- pattern file

func TestPatternFileIsWellFormed(t *testing.T) {
	patterns := mustParsePatterns(secretPatternsFile)

	if len(patterns) < 5 {
		t.Errorf("parsed %d patterns, want the embedded file to carry a useful set", len(patterns))
	}

	seen := map[string]bool{}
	for _, p := range patterns {
		if seen[p.name] {
			t.Errorf("duplicate pattern name %q", p.name)
		}
		seen[p.name] = true

		if p.confidence != confidenceHigh && p.confidence != confidenceLow {
			t.Errorf("%s: confidence = %q", p.name, p.confidence)
		}
		if p.re.NumSubexp() > 1 {
			t.Errorf("%s: %d capture groups — only group 1 is read, so extra groups mislead",
				p.name, p.re.NumSubexp())
		}
		// A pattern that matches the empty string would fire on every body.
		if p.re.MatchString("") {
			t.Errorf("%s: matches the empty string", p.name)
		}
	}
}

func TestMustParsePatterns_RejectsMalformedLines(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"missing fields", "only-a-name\n"},
		{"missing regexp", "name high\n"},
		{"unknown confidence", "name maybe \\d+\n"},
		{"bad regexp", "name high [unclosed\n"},
		{"duplicate name", "dup high \\d+\ndup low \\w+\n"},
		{"no patterns at all", "# just a comment\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("did not panic — a malformed embedded pattern file is a build-time mistake")
				}
			}()
			mustParsePatterns(tt.in)
		})
	}
}

func TestMustParsePatterns_SkipsCommentsAndBlankLines(t *testing.T) {
	patterns := mustParsePatterns("# a comment\n\n   \nname high \\bAKIA[0-9A-Z]{16}\\b\n")

	if len(patterns) != 1 {
		t.Fatalf("parsed %d patterns, want 1", len(patterns))
	}
	if patterns[0].name != "name" || patterns[0].confidence != confidenceHigh {
		t.Errorf("parsed %+v", patterns[0])
	}
}

// A protocol-relative URL ("//cdn.example.com/x") as a bare JSON string
// value is not a comment. Misreading it as one would, in a single-line
// body with no newlines, mislabel everything after it — including any
// secret that happens to follow — as "inside a comment".
func TestExposedSecrets_ProtocolRelativeURLIsNotAComment(t *testing.T) {
	findings := runSecrets(t, bodyTarget(
		`{"cdn":"//static.example.com/lib.js","aws_access_key_id":"AKIAIOSFODNN7EXAMPLE"}`))

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1\n%s", len(findings), evidence(findings))
	}
	if strings.Contains(findings[0].Evidence.ResponseSnippet, "inside a comment") {
		t.Errorf("evidence = %q, want no comment claim — a protocol-relative URL is not a comment opener",
			findings[0].Evidence.ResponseSnippet)
	}
}
