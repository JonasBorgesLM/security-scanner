package attack

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

// vulnerableSQLiServer simulates a backend that concatenates the `id` query
// parameter unsanitised into `SELECT * FROM items WHERE id = '<id>'`, and
// additionally understands a MySQL/PostgreSQL-flavoured UNION SELECT well
// enough to answer the CONCAT-wrapped marker technique the confirmer uses.
// It is deliberately a simulation, not a real SQL engine: it recognises the
// exact shapes this attack package produces, which is what lets the test
// prove the technique end to end without standing up a real database.
func vulnerableSQLiServer(t *testing.T, wantColumns int) *httptest.Server {
	t.Helper()
	const dbName = "labdb_billing"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "application/json")

		switch {
		case isSQLiUnionAttempt(id):
			cols := sqliUnionColumnCount(id)
			if cols != wantColumns {
				// Wrong column count: a real engine would error out here.
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, `{"error":"column count mismatch"}`)
				return
			}
			last := sqliLastUnionColumn(id)
			marker := evaluateMarkerExpression(last, dbName)
			fmt.Fprintf(w, `{"items":[{"id":1,"name":"item-1"},{"id":%q}]}`, marker)
		case strings.Contains(id, "1'='1") || strings.Contains(id, "1=1"):
			fmt.Fprint(w, `{"items":[`+strings.TrimSuffix(strings.Repeat(`{"id":1},`, 25), ",")+`]}`)
		case strings.Contains(id, "1'='2") || strings.Contains(id, "1=2"):
			fmt.Fprint(w, `{"items":[]}`)
		default:
			fmt.Fprint(w, `{"items":[{"id":1,"name":"item-1"}]}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func isSQLiUnionAttempt(id string) bool {
	return strings.Contains(strings.ToUpper(id), "UNION SELECT")
}

// sqliUnionColumnCount counts the columns in a "... UNION SELECT a,b,c-- -"
// value by counting commas at the top level after "UNION SELECT ".
func sqliUnionColumnCount(id string) int {
	upper := strings.ToUpper(id)
	i := strings.Index(upper, "UNION SELECT")
	if i < 0 {
		return 0
	}
	rest := id[i+len("UNION SELECT"):]
	if j := strings.Index(rest, "-- -"); j >= 0 {
		rest = rest[:j]
	}
	return len(splitTopLevelArgs(strings.TrimSpace(rest)))
}

func sqliLastUnionColumn(id string) string {
	upper := strings.ToUpper(id)
	i := strings.Index(upper, "UNION SELECT")
	rest := id[i+len("UNION SELECT"):]
	if j := strings.Index(rest, "-- -"); j >= 0 {
		rest = rest[:j]
	}
	args := splitTopLevelArgs(strings.TrimSpace(rest))
	return args[len(args)-1]
}

// splitTopLevelArgs splits a comma list without splitting inside a CONCAT(...).
func splitTopLevelArgs(s string) []string {
	var args []string
	depth := 0
	start := 0
	for i, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				args = append(args, s[start:i])
				start = i + 1
			}
		}
	}
	args = append(args, s[start:])
	return args
}

// evaluateMarkerExpression is the test double's tiny "SQL engine": it
// understands NULL, a quoted constant, CONCAT('a', expr, 'b') and the
// candidate functions the confirmer tries.
func evaluateMarkerExpression(expr, dbName string) string {
	expr = strings.TrimSpace(expr)
	if !strings.HasPrefix(strings.ToUpper(expr), "CONCAT(") {
		return ""
	}
	inner := expr[len("CONCAT(") : len(expr)-1]
	args := splitTopLevelArgs(inner)
	var b strings.Builder
	for _, a := range args {
		a = strings.TrimSpace(a)
		switch {
		case strings.HasPrefix(a, "'") && strings.HasSuffix(a, "'"):
			b.WriteString(strings.Trim(a, "'"))
		case strings.EqualFold(a, "database()"), strings.EqualFold(a, "current_database()"), strings.EqualFold(a, "DB_NAME()"):
			b.WriteString(dbName)
		case strings.EqualFold(a, "sqlite_version()"):
			// Not the "database name" candidate this test targets.
			return ""
		default:
			return ""
		}
	}
	return b.String()
}

func sqliFinding(srv *httptest.Server, injectedParam, payload string) model.Finding {
	return model.Finding{
		ID:        "id",
		CheckName: "sqli-boolean",
		Endpoint:  model.Endpoint{Method: "GET", Path: "/items"},
		Request: model.CapturedRequest{
			Method:        "GET",
			URL:           srv.URL + "/items?id=" + urlEscape(payload),
			InjectedParam: injectedParam,
			Payload:       payload,
		},
	}
}

// urlEscape mirrors what the scan-time check would have produced with
// url.Values.Encode(), used here only to build a realistic test fixture.
func urlEscape(s string) string {
	return strings.NewReplacer(" ", "+", "'", "%27", "\"", "%22").Replace(s)
}

func TestSQLiConfirmer_CheckName(t *testing.T) {
	if got := (sqliConfirmer{}).CheckName(); got != "sqli-boolean" {
		t.Errorf("CheckName() = %q, want sqli-boolean", got)
	}
}

func TestSQLiConfirmer_ReproducesAndExtractsDatabaseName(t *testing.T) {
	srv := vulnerableSQLiServer(t, 2)
	f := sqliFinding(srv, "id", "' OR '1'='1")

	got, err := (sqliConfirmer{}).Confirm(t.Context(), f, http.DefaultClient)
	if err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	if !got.Confirmed {
		t.Fatalf("Confirmed = false, want true; evidence: %s", got.Evidence.ResponseSnippet)
	}
	if !strings.Contains(got.Evidence.ResponseSnippet, `"labdb_billing"`) {
		t.Errorf("Evidence = %q, want it to name the extracted database", got.Evidence.ResponseSnippet)
	}
	if got.Request.URL == f.Request.URL {
		t.Error("Request.URL was not updated to the UNION request that produced the extraction")
	}
	if !strings.Contains(strings.ToUpper(got.Request.Payload), "UNION SELECT") {
		t.Errorf("Request.Payload = %q, want the UNION payload used", got.Request.Payload)
	}
}

func TestSQLiConfirmer_FindsWithDifferentColumnCounts(t *testing.T) {
	for _, n := range []int{1, 3, sqliMaxColumns} {
		t.Run(fmt.Sprintf("%d_columns", n), func(t *testing.T) {
			srv := vulnerableSQLiServer(t, n)
			f := sqliFinding(srv, "id", "' OR '1'='1")

			got, err := (sqliConfirmer{}).Confirm(t.Context(), f, http.DefaultClient)
			if err != nil {
				t.Fatalf("Confirm() error = %v", err)
			}
			if !got.Confirmed {
				t.Fatalf("Confirmed = false for %d columns; evidence: %s", n, got.Evidence.ResponseSnippet)
			}
			if !strings.Contains(got.Evidence.ResponseSnippet, "labdb_billing") {
				t.Errorf("did not extract the database name at %d columns: %s", n, got.Evidence.ResponseSnippet)
			}
		})
	}
}

func TestSQLiConfirmer_ColumnCountBeyondMaxIsNotFound(t *testing.T) {
	srv := vulnerableSQLiServer(t, sqliMaxColumns+1)
	f := sqliFinding(srv, "id", "' OR '1'='1")

	got, err := (sqliConfirmer{}).Confirm(t.Context(), f, http.DefaultClient)
	if err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	// The boolean re-verification still holds (this server also answers the
	// plain OR-based payloads), so Confirmed is true -- extraction is what
	// fails, and it must say so rather than silently omitting the attempt.
	if !got.Confirmed {
		t.Fatal("Confirmed = false, want true — the boolean comparison alone should still reproduce")
	}
	if !strings.Contains(got.Evidence.ResponseSnippet, "no working column count") {
		t.Errorf("Evidence = %q, want it to say extraction failed", got.Evidence.ResponseSnippet)
	}
}

func TestSQLiConfirmer_DoesNotReproduceOnAPatchedTarget(t *testing.T) {
	// The endpoint always returns the same single item regardless of the
	// payload: whatever scan saw, it no longer holds.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"items":[{"id":1,"name":"item-1"}]}`)
	}))
	t.Cleanup(srv.Close)

	f := sqliFinding(srv, "id", "' OR '1'='1")
	got, err := (sqliConfirmer{}).Confirm(t.Context(), f, http.DefaultClient)
	if err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	if got.Confirmed {
		t.Error("Confirmed = true, want false — the target no longer shows a difference")
	}
	if !strings.Contains(got.Evidence.ResponseSnippet, "did not reproduce") {
		t.Errorf("Evidence = %q, want it to say so", got.Evidence.ResponseSnippet)
	}
}

// A stable-but-dynamic target (the false-positive trap invariant #4 exists
// for) must not get re-confirmed just because attack's own fresh noise
// measurement happens to land differently than scan's did.
func TestSQLiConfirmer_DynamicButUnaffectedTargetStaysUnconfirmed(t *testing.T) {
	paddings := []string{"", "abc", "a"}
	var call int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := paddings[call%len(paddings)]
		call++
		fmt.Fprintf(w, `{"items":[{"id":1,"name":"item-1"}],"nonce":%q}`, p)
	}))
	t.Cleanup(srv.Close)

	f := sqliFinding(srv, "id", "' OR '1'='1")
	got, err := (sqliConfirmer{}).Confirm(t.Context(), f, http.DefaultClient)
	if err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	if got.Confirmed {
		t.Errorf("Confirmed = true, want false — the endpoint's own churn must not read as a vulnerability; evidence: %s", got.Evidence.ResponseSnippet)
	}
}

func TestSQLiConfirmer_UnknownPayloadHasNoPairing(t *testing.T) {
	srv := vulnerableSQLiServer(t, 2)
	f := sqliFinding(srv, "id", "not a real payload from the pairs file")

	_, err := (sqliConfirmer{}).Confirm(t.Context(), f, http.DefaultClient)
	if err == nil {
		t.Fatal("Confirm() error = nil, want an error — there is no false-condition payload to pair with")
	}
}

func TestSQLiConfirmer_UnreachableTargetIsAnError(t *testing.T) {
	f := sqliFinding(&httptest.Server{URL: "http://127.0.0.1:1"}, "id", "' OR '1'='1")

	_, err := (sqliConfirmer{}).Confirm(t.Context(), f, http.DefaultClient)
	if err == nil {
		t.Fatal("Confirm() error = nil, want an error for an unreachable target")
	}
}

func TestSQLiConfirmer_PathParameterInjection(t *testing.T) {
	const dbName = "labdb_billing"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/items/")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case isSQLiUnionAttempt(id):
			if sqliUnionColumnCount(id) != 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			marker := evaluateMarkerExpression(sqliLastUnionColumn(id), dbName)
			fmt.Fprintf(w, `{"marker":%q}`, marker)
		case strings.Contains(id, "1'='1"):
			fmt.Fprint(w, strings.Repeat("x", 500))
		case strings.Contains(id, "1'='2"):
			fmt.Fprint(w, "x")
		default:
			fmt.Fprint(w, "xx")
		}
	}))
	t.Cleanup(srv.Close)

	payload := "' OR '1'='1"
	f := model.Finding{
		CheckName: "sqli-boolean",
		Endpoint:  model.Endpoint{Method: "GET", Path: "/items/{id}"},
		Request: model.CapturedRequest{
			Method:        "GET",
			URL:           srv.URL + "/items/" + urlPathEscape(payload),
			InjectedParam: "id",
			Payload:       payload,
		},
	}

	got, err := (sqliConfirmer{}).Confirm(t.Context(), f, http.DefaultClient)
	if err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	if !got.Confirmed {
		t.Fatalf("Confirmed = false, want true; evidence: %s", got.Evidence.ResponseSnippet)
	}
	if !strings.Contains(got.Evidence.ResponseSnippet, dbName) {
		t.Errorf("Evidence = %q, want the extracted name", got.Evidence.ResponseSnippet)
	}
}

func urlPathEscape(s string) string {
	return strings.NewReplacer("'", "%27", " ", "%20").Replace(s)
}

func TestQuoteStyleOf(t *testing.T) {
	tests := []struct{ payload, want string }{
		{"' OR '1'='1", "'"},
		{`" OR "1"="1`, `"`},
		{"1 OR 1=1", ""},
	}
	for _, tt := range tests {
		if got := quoteStyleOf(tt.payload); got != tt.want {
			t.Errorf("quoteStyleOf(%q) = %q, want %q", tt.payload, got, tt.want)
		}
	}
}

func TestNullColumns(t *testing.T) {
	if got := strings.Join(nullColumns(3), ","); got != "NULL,NULL,NULL" {
		t.Errorf("nullColumns(3) = %q", got)
	}
}

func TestSqliUnionValue(t *testing.T) {
	got := sqliUnionValue("'", []string{"NULL", "database()"})
	want := "' UNION SELECT NULL,database()-- -"
	if got != want {
		t.Errorf("sqliUnionValue() = %q, want %q", got, want)
	}

	// Numeric context: no quote to close, so no leading space either.
	got = sqliUnionValue("", []string{"NULL"})
	want = "UNION SELECT NULL-- -"
	if got != want {
		t.Errorf("sqliUnionValue() = %q, want %q", got, want)
	}
}

// Ensures findSQLiColumnCount does not loop forever and correctly gives up
// against a server that never accepts any UNION shape.
func TestFindSQLiColumnCount_GivesUpCleanly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	n, err := findSQLiColumnCount(context.Background(), http.DefaultClient, "GET",
		srv.URL+"/items?id=%27", "id", "'", "'")
	if err != nil {
		t.Fatalf("error = %v, want nil", err)
	}
	if n != 0 {
		t.Errorf("n = %d, want 0", n)
	}
}

// The column count is found (the constant-marker check succeeds), but no
// candidate function returns a value -- e.g. every candidate errors or
// returns something the server doesn't recognise. Confirmed must still be
// true from the boolean comparison; only the extraction note changes.
func TestSQLiConfirmer_ColumnCountFoundButNoCandidateExtracts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case isSQLiUnionAttempt(id):
			if sqliUnionColumnCount(id) != 1 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			last := sqliLastUnionColumn(id)
			// Only answer the constant-marker probe ("OK"); every real
			// candidate function is treated as unknown and yields nothing.
			if strings.Contains(last, "'OK'") {
				fmt.Fprintf(w, `{"v":"%sOK%s"}`, sqliMarkerPrefix, sqliMarkerSuffix)
				return
			}
			fmt.Fprint(w, `{"v":null}`)
		case strings.Contains(id, "1'='1"):
			fmt.Fprint(w, `{"items":[`+strings.TrimSuffix(strings.Repeat(`{"id":1},`, 25), ",")+`]}`)
		case strings.Contains(id, "1'='2"):
			fmt.Fprint(w, `{"items":[]}`)
		default:
			fmt.Fprint(w, `{"items":[{"id":1}]}`)
		}
	}))
	t.Cleanup(srv.Close)

	f := sqliFinding(srv, "id", "' OR '1'='1")
	got, err := (sqliConfirmer{}).Confirm(t.Context(), f, http.DefaultClient)
	if err != nil {
		t.Fatalf("Confirm() error = %v", err)
	}
	if !got.Confirmed {
		t.Fatal("Confirmed = false, want true — the boolean comparison alone should still reproduce")
	}
	if !strings.Contains(got.Evidence.ResponseSnippet, "no candidate function returned a value") {
		t.Errorf("Evidence = %q, want it to say extraction found no value", got.Evidence.ResponseSnippet)
	}
}
