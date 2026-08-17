package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/JonasBorgesLM/security-scanner/internal/adapters/config"
	"github.com/JonasBorgesLM/security-scanner/internal/checks"
	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

// This is the test the unit suites cannot give: every layer assembled the
// way runScan assembles it — ScopeGuard, Authenticator, rate limiter,
// baseline collection, registry and the real missing-headers check —
// against a server that actually answers over TCP. Fakes prove the parts;
// only this proves they fit.

// labServer stands in for the operator's lab API.
type labServer struct {
	logins   atomic.Int32
	requests atomic.Int32
	mu       sync.Mutex
	methods  []string
}

func newLabServer(t *testing.T) (*httptest.Server, *labServer) {
	t.Helper()
	lab := &labServer{}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		lab.logins.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"access_token": "tok-integration"},
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		lab.requests.Add(1)
		lab.mu.Lock()
		lab.methods = append(lab.methods, r.Method+" "+r.URL.Path)
		lab.mu.Unlock()

		// /secure answers with the full set the check looks for, so the
		// run proves the check discriminates rather than flagging blindly.
		if strings.HasPrefix(r.URL.Path, "/secure") {
			w.Header().Set("Content-Security-Policy", "default-src 'none'")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-Content-Type-Options", "nosniff")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, lab
}

func (l *labServer) seenMethods() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.methods...)
}

// writeSpec renders a minimal OpenAPI 3 document exercising a public route,
// an authenticated route, a route that already sets its headers, and a
// destructive one.
func writeSpec(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "openapi.yaml")
	spec := `openapi: 3.0.3
info: {title: Lab, version: "1.0"}
security:
  - bearerAuth: []
paths:
  /public:
    get:
      security: []
      responses: {"200": {description: OK}}
  /items:
    get:
      responses: {"200": {description: OK}}
    post:
      responses: {"201": {description: Created}}
  /secure:
    get:
      responses: {"200": {description: OK}}
  /items/{id}:
    parameters:
      - {name: id, in: path, required: true, schema: {type: string}}
    delete:
      responses: {"204": {description: No Content}}
components:
  securitySchemes:
    bearerAuth: {type: http, scheme: bearer}
`
	if err := os.WriteFile(path, []byte(spec), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func writeConfig(t *testing.T, dir, baseURL string) string {
	t.Helper()
	host := strings.TrimPrefix(baseURL, "http://")
	path := filepath.Join(dir, "config.yaml")
	cfg := fmt.Sprintf(`schema_version: 1
target:
  base_url: %s
scope:
  allowed_hosts: ["%s"]
auth:
  login_endpoint: /login
  credentials:
    username: admin
    password: ${SCANNER_IT_PASSWORD}
  token_path: data.access_token
  token_prefix: "Bearer "
engine:
  max_concurrency: 4
  requests_per_second: 500
  timeout: 30s
  test_destructive: false
checks:
  enabled: [missing-headers]
`, baseURL, host)
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func TestScan_EndToEnd(t *testing.T) {
	t.Setenv("SCANNER_IT_PASSWORD", "lab-pass")

	srv, lab := newLabServer(t)
	dir := t.TempDir()
	specPath := writeSpec(t, dir)
	configPath := writeConfig(t, dir, srv.URL)
	outPath := filepath.Join(dir, "findings.json")

	if err := runScan([]string{"--spec", specPath, "--config", configPath, "--out", outPath}); err != nil {
		t.Fatalf("runScan() error = %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var out model.FindingsFile
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("findings.json is not valid JSON: %v", err)
	}

	if out.SchemaVersion != model.SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", out.SchemaVersion, model.SchemaVersion)
	}

	t.Run("authenticated once, up front", func(t *testing.T) {
		if got := lab.logins.Load(); got != 1 {
			t.Errorf("logins = %d, want exactly 1", got)
		}
	})

	t.Run("collection never sends an unsafe method", func(t *testing.T) {
		for _, m := range lab.seenMethods() {
			method, _, _ := strings.Cut(m, " ")
			if method != http.MethodGet {
				t.Errorf("lab received %s — collection must only use safe methods", m)
			}
		}
	})

	t.Run("destructive endpoint is never touched", func(t *testing.T) {
		for _, m := range lab.seenMethods() {
			if strings.Contains(m, "/items/") {
				t.Errorf("lab received %s for a destructive endpoint without opt-in", m)
			}
		}
	})

	t.Run("one baseline request per non-destructive endpoint", func(t *testing.T) {
		// /public, GET /items, POST /items, /secure = 4 endpoints,
		// DELETE /items/{id} skipped.
		if got := lab.requests.Load(); got != 4 {
			t.Errorf("lab received %d requests, want 4 — one baseline each, none per check", got)
		}
	})

	t.Run("findings are complete and attributable", func(t *testing.T) {
		if len(out.Findings) == 0 {
			t.Fatal("no findings — the missing-headers check should have fired on the bare routes")
		}
		for _, f := range out.Findings {
			if f.ID == "" {
				t.Error("finding has no ID")
			}
			if f.CheckName != "missing-headers" {
				t.Errorf("CheckName = %q", f.CheckName)
			}
			if f.Endpoint.Path == "" {
				t.Errorf("%s: Endpoint is empty — the attack stage could not reproduce this", f.ID)
			}
			if f.Severity == "" || f.OWASPCategory == "" {
				t.Errorf("%s: severity/category not stamped from metadata", f.ID)
			}
			if f.Confirmed {
				t.Errorf("%s: Confirmed = true, but scan only produces suspicions", f.ID)
			}
		}
	})

	t.Run("a route that sets its headers produces no findings", func(t *testing.T) {
		for _, f := range out.Findings {
			if f.Endpoint.Path == "/secure" {
				t.Errorf("/secure reported %q despite setting its security headers", f.ID)
			}
		}
	})

	t.Run("every finding names one of the checked headers", func(t *testing.T) {
		want := []string{
			"Content-Security-Policy",
			"Strict-Transport-Security",
			"X-Frame-Options",
			"X-Content-Type-Options",
		}
		for _, f := range out.Findings {
			named := false
			for _, h := range want {
				if strings.HasSuffix(f.ID, ":"+h) {
					named = true
					break
				}
			}
			if !named {
				t.Errorf("finding %q does not name one of %v", f.ID, want)
			}
		}
	})

	t.Run("severity is medium", func(t *testing.T) {
		for _, f := range out.Findings {
			if f.Severity != "medium" {
				t.Errorf("%s: Severity = %q, want medium", f.ID, f.Severity)
			}
		}
	})
}

// Running the same scan twice against an unchanged target must produce a
// byte-identical file, or findings.json cannot be reviewed with git diff.
func TestScan_IsReproducible(t *testing.T) {
	t.Setenv("SCANNER_IT_PASSWORD", "lab-pass")

	srv, _ := newLabServer(t)
	dir := t.TempDir()
	specPath := writeSpec(t, dir)
	configPath := writeConfig(t, dir, srv.URL)

	first := filepath.Join(dir, "a.json")
	second := filepath.Join(dir, "b.json")

	for _, out := range []string{first, second} {
		if err := runScan([]string{"--spec", specPath, "--config", configPath, "--out", out}); err != nil {
			t.Fatalf("runScan() error = %v", err)
		}
	}

	a, _ := os.ReadFile(first)
	b, _ := os.ReadFile(second)
	if string(a) != string(b) {
		t.Errorf("two scans of the same target differ:\n--- first ---\n%s\n--- second ---\n%s", a, b)
	}
}

func TestScan_UnknownCheckNameFailsBeforeAnyRequest(t *testing.T) {
	t.Setenv("SCANNER_IT_PASSWORD", "lab-pass")

	srv, lab := newLabServer(t)
	dir := t.TempDir()
	specPath := writeSpec(t, dir)

	configPath := filepath.Join(dir, "config.yaml")
	original, _ := os.ReadFile(writeConfig(t, dir, srv.URL))
	broken := strings.Replace(string(original), "missing-headers", "missing-headerz", 1)
	os.WriteFile(configPath, []byte(broken), 0o600)

	err := runScan([]string{"--spec", specPath, "--config", configPath, "--out", filepath.Join(dir, "f.json")})
	if err == nil {
		t.Fatal("runScan() error = nil, want an error for an unknown check name")
	}
	if !strings.Contains(err.Error(), "missing-headerz") {
		t.Errorf("error = %v, want it to name the typo", err)
	}
	if got := lab.requests.Load(); got != 0 {
		t.Errorf("lab received %d requests, want 0 — a config typo must fail before any traffic", got)
	}
}

func TestScan_OutOfScopeTargetIsRejected(t *testing.T) {
	t.Setenv("SCANNER_IT_PASSWORD", "lab-pass")

	srv, lab := newLabServer(t)
	dir := t.TempDir()
	specPath := writeSpec(t, dir)

	configPath := filepath.Join(dir, "config.yaml")
	original, _ := os.ReadFile(writeConfig(t, dir, srv.URL))
	host := strings.TrimPrefix(srv.URL, "http://")
	broken := strings.Replace(string(original), `["`+host+`"]`, `["somewhere-else.invalid:9999"]`, 1)
	os.WriteFile(configPath, []byte(broken), 0o600)

	err := runScan([]string{"--spec", specPath, "--config", configPath, "--out", filepath.Join(dir, "f.json")})
	if err == nil {
		t.Fatal("runScan() error = nil, want the scan refused")
	}
	if got := lab.requests.Load(); got != 0 {
		t.Errorf("lab received %d requests, want 0 — an out-of-scope target must never be contacted", got)
	}
}

// The example config ships with the tool, so every check it enables must
// actually be registered. Listing a check that does not exist yet makes the
// operator's first copy-paste abort — which is exactly what this caught.
func TestShippedConfigEnablesOnlyRegisteredChecks(t *testing.T) {
	t.Setenv("LAB_PASSWORD", "example")

	cfg, err := config.Load(filepath.Join("..", "..", "configs", "config.yaml"))
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}

	enabled, err := checks.Enabled(cfg.Checks.Enabled)
	if err != nil {
		t.Fatalf("configs/config.yaml enables a check that is not registered: %v", err)
	}
	if len(enabled) != len(cfg.Checks.Enabled) {
		t.Errorf("resolved %d checks from %d names", len(enabled), len(cfg.Checks.Enabled))
	}
}

// ---------------------------------------------------------------- attack

// sqliLabServer simulates a target with one SQLi-vulnerable query
// parameter realistically enough to exercise both halves of the pipeline
// end to end: scan's sqli-boolean check (boolean true/false comparison)
// and attack's confirmer (fresh re-verification, then UNION-based
// database-name extraction). Login is required, separately from
// newLabServer's, so this test can prove attack re-authenticates as its
// own process run rather than reusing anything from scan.
func sqliLabServer(t *testing.T) (*httptest.Server, *labServer) {
	t.Helper()
	const dbName = "labdb_billing"
	lab := &labServer{}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		lab.logins.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"access_token": "tok-sqli"},
		})
	})
	mux.HandleFunc("/items", func(w http.ResponseWriter, r *http.Request) {
		lab.requests.Add(1)
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(q, "ATTACKPOC_"):
			// A permissive-engine simulation: accepts the UNION regardless
			// of exact column count (that search is already exercised in
			// internal/attack's own unit tests) and evaluates the marker
			// expression, so this test proves the pipeline wiring, not the
			// column-count algorithm a second time.
			fmt.Fprintf(w, `{"items":[{"id":1,"name":%q}]}`, evalSQLiMarker(q, dbName))
		case strings.Contains(q, "1'='1") || strings.Contains(q, "1=1"):
			fmt.Fprint(w, `{"items":[`+strings.TrimSuffix(strings.Repeat(`{"id":1},`, 25), ",")+`]}`)
		case strings.Contains(q, "1'='2") || strings.Contains(q, "1=2"):
			fmt.Fprint(w, `{"items":[]}`)
		default:
			fmt.Fprint(w, `{"items":[{"id":1,"name":"item-1"}]}`)
		}
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, lab
}

func evalSQLiMarker(q, dbName string) string {
	switch {
	case strings.Contains(q, "'OK'"):
		return "ATTACKPOC_OK_ENDPOC"
	case strings.Contains(q, "database()"):
		return "ATTACKPOC_" + dbName + "_ENDPOC"
	default:
		// Candidates the fake engine doesn't recognise (current_database(),
		// DB_NAME(), sqlite_version()) fall through here, unmatched -- proof
		// the confirmer actually tries more than one candidate rather than
		// getting lucky on the first.
		return "no-match"
	}
}

func writeSQLiSpec(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "sqli-openapi.yaml")
	spec := `openapi: 3.0.3
info: {title: SQLi Lab, version: "1.0"}
security:
  - bearerAuth: []
paths:
  /items:
    get:
      operationId: listItems
      parameters:
        - name: q
          in: query
          required: false
          schema: {type: string}
      responses: {"200": {description: OK}}
components:
  securitySchemes:
    bearerAuth: {type: http, scheme: bearer}
`
	if err := os.WriteFile(path, []byte(spec), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func writeSQLiConfig(t *testing.T, dir, baseURL string) string {
	t.Helper()
	host := strings.TrimPrefix(baseURL, "http://")
	path := filepath.Join(dir, "sqli-config.yaml")
	cfg := fmt.Sprintf(`schema_version: 1
target:
  base_url: %s
scope:
  allowed_hosts: ["%s"]
auth:
  login_endpoint: /login
  credentials:
    username: admin
    password: ${SCANNER_IT_PASSWORD}
  token_path: data.access_token
  token_prefix: "Bearer "
engine:
  max_concurrency: 4
  requests_per_second: 500
  timeout: 30s
  test_destructive: false
checks:
  enabled: [sqli-boolean]
`, baseURL, host)
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

// TestScanAttack_SQLiEndToEnd is the cycle the task asked for: scan finds
// the suspicion, attack reproduces it against the same fake lab and writes
// confirmed.json -- two separate process invocations, two separate logins,
// sharing nothing but the files between them, exactly like two separate
// `scanner` runs would.
func TestScanAttack_SQLiEndToEnd(t *testing.T) {
	t.Setenv("SCANNER_IT_PASSWORD", "lab-pass")

	srv, lab := sqliLabServer(t)
	dir := t.TempDir()
	specPath := writeSQLiSpec(t, dir)
	configPath := writeSQLiConfig(t, dir, srv.URL)
	findingsPath := filepath.Join(dir, "findings.json")
	confirmedPath := filepath.Join(dir, "confirmed.json")

	if err := runScan([]string{"--spec", specPath, "--config", configPath, "--out", findingsPath}); err != nil {
		t.Fatalf("runScan() error = %v", err)
	}

	var scanned model.FindingsFile
	mustReadJSON(t, findingsPath, &scanned)
	if len(scanned.Findings) != 1 {
		t.Fatalf("scan produced %d findings, want 1", len(scanned.Findings))
	}
	suspicion := scanned.Findings[0]
	if suspicion.CheckName != "sqli-boolean" {
		t.Fatalf("CheckName = %q, want sqli-boolean", suspicion.CheckName)
	}
	if suspicion.Confirmed {
		t.Fatal("scan-time finding is already Confirmed — attack would have nothing to do")
	}
	if got := lab.logins.Load(); got != 1 {
		t.Fatalf("scan logged in %d times, want 1", got)
	}

	if err := runAttack([]string{"--in", findingsPath, "--config", configPath, "--out", confirmedPath}); err != nil {
		t.Fatalf("runAttack() error = %v", err)
	}

	t.Run("attack authenticates as its own run", func(t *testing.T) {
		if got := lab.logins.Load(); got != 2 {
			t.Errorf("total logins = %d, want 2 (scan's plus attack's own)", got)
		}
	})

	var confirmed model.FindingsFile
	mustReadJSON(t, confirmedPath, &confirmed)

	t.Run("the finding is confirmed", func(t *testing.T) {
		if len(confirmed.Findings) != 1 {
			t.Fatalf("got %d findings, want 1", len(confirmed.Findings))
		}
		f := confirmed.Findings[0]
		if !f.Confirmed {
			t.Fatalf("Confirmed = false, want true; evidence: %s", f.Evidence.ResponseSnippet)
		}
		if f.ID != suspicion.ID {
			t.Errorf("ID = %q, want the same ID scan assigned (%q) — this is the same finding, reproduced", f.ID, suspicion.ID)
		}
	})

	t.Run("the database name was extracted via UNION", func(t *testing.T) {
		f := confirmed.Findings[0]
		if !strings.Contains(f.Evidence.ResponseSnippet, "labdb_billing") {
			t.Errorf("Evidence = %q, want the extracted database name", f.Evidence.ResponseSnippet)
		}
		if !strings.Contains(strings.ToUpper(f.Request.Payload), "UNION SELECT") {
			t.Errorf("Request.Payload = %q, want the UNION payload used for extraction", f.Request.Payload)
		}
	})

	t.Run("the UNION request is independently reproducible", func(t *testing.T) {
		resp, err := http.Get(confirmed.Findings[0].Request.URL)
		if err != nil {
			t.Fatalf("replaying Request.URL: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "labdb_billing") {
			t.Errorf("replayed response = %s, want the extracted name again", body)
		}
	})

	t.Run("no wall-clock leaked into the confirmed finding", func(t *testing.T) {
		if confirmed.Findings[0].Evidence.ResponseTime != 0 {
			t.Errorf("ResponseTime = %v, want zero", confirmed.Findings[0].Evidence.ResponseTime)
		}
	})

	t.Run("attack is reproducible", func(t *testing.T) {
		secondPath := filepath.Join(dir, "confirmed-2.json")
		if err := runAttack([]string{"--in", findingsPath, "--config", configPath, "--out", secondPath}); err != nil {
			t.Fatalf("runAttack() error = %v", err)
		}
		a, _ := os.ReadFile(confirmedPath)
		b, _ := os.ReadFile(secondPath)
		if string(a) != string(b) {
			t.Errorf("two attack runs against the same unchanged target and findings produced different files:\n--- first ---\n%s\n--- second ---\n%s", a, b)
		}
	})

	t.Run("report renders confirmed.json without error", func(t *testing.T) {
		reportPath := filepath.Join(dir, "report.html")
		if err := runReport([]string{"--in", confirmedPath, "--out", reportPath}); err != nil {
			t.Fatalf("runReport() error = %v", err)
		}

		html, err := os.ReadFile(reportPath)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", reportPath, err)
		}
		if !strings.Contains(string(html), "sqli-boolean") {
			t.Errorf("report.html missing the confirmed check's name")
		}
		if !strings.Contains(string(html), "labdb_billing") {
			t.Errorf("report.html missing the extracted evidence")
		}

		jsonPath := filepath.Join(dir, "report.json")
		var rendered struct {
			SchemaVersion int `json:"schema_version"`
			Summary       struct {
				TotalFindings  int `json:"total_findings"`
				TotalConfirmed int `json:"total_confirmed"`
			} `json:"summary"`
			Findings []model.Finding `json:"findings"`
		}
		mustReadJSON(t, jsonPath, &rendered)
		if rendered.SchemaVersion != model.SchemaVersion {
			t.Errorf("report.json schema_version = %d, want %d", rendered.SchemaVersion, model.SchemaVersion)
		}
		if rendered.Summary.TotalFindings != 1 || rendered.Summary.TotalConfirmed != 1 {
			t.Errorf("report.json summary = %+v, want 1 finding, 1 confirmed", rendered.Summary)
		}
		if len(rendered.Findings) != 1 || !rendered.Findings[0].Confirmed {
			t.Fatalf("report.json findings = %+v, want the one confirmed finding", rendered.Findings)
		}
	})

	t.Run("report is reproducible", func(t *testing.T) {
		firstPath := filepath.Join(dir, "report.html")
		secondPath := filepath.Join(dir, "report-2.html")
		if err := runReport([]string{"--in", confirmedPath, "--out", secondPath}); err != nil {
			t.Fatalf("runReport() error = %v", err)
		}
		a, _ := os.ReadFile(firstPath)
		b, _ := os.ReadFile(secondPath)
		if string(a) != string(b) {
			t.Errorf("two report runs over the same confirmed.json produced different HTML")
		}
	})
}

func mustReadJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("Unmarshal(%s) error = %v", path, err)
	}
}

// A finding on a destructive endpoint must never be attacked without
// engine.test_destructive -- attack re-enforces this itself rather than
// trusting that whatever produced findings.json already filtered it out.
func TestAttack_DestructiveFindingIsNeverAttacked(t *testing.T) {
	t.Setenv("SCANNER_IT_PASSWORD", "lab-pass")

	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path == "/login" {
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"access_token": "tok"}})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	configPath := writeSQLiConfig(t, dir, srv.URL)

	findings := model.FindingsFile{
		SchemaVersion: model.SchemaVersion,
		Findings: []model.Finding{{
			ID:        "sqli-boolean:DELETE:/items/{id}:id",
			CheckName: "sqli-boolean",
			Endpoint:  model.Endpoint{Method: "DELETE", Path: "/items/{id}", Destructive: true},
			Request: model.CapturedRequest{
				Method:        "DELETE",
				URL:           srv.URL + "/items/1",
				InjectedParam: "id",
				Payload:       "' OR '1'='1",
			},
		}},
	}
	findingsPath := filepath.Join(dir, "findings.json")
	data, _ := json.Marshal(findings)
	os.WriteFile(findingsPath, data, 0o600)

	confirmedPath := filepath.Join(dir, "confirmed.json")
	if err := runAttack([]string{"--in", findingsPath, "--config", configPath, "--out", confirmedPath}); err != nil {
		t.Fatalf("runAttack() error = %v", err)
	}

	var confirmed model.FindingsFile
	mustReadJSON(t, confirmedPath, &confirmed)
	if confirmed.Findings[0].Confirmed {
		t.Error("Confirmed = true, want false — a destructive endpoint must never be attacked without opt-in")
	}
	// login (1) is the only request this run may have made.
	if requests > 1 {
		t.Errorf("server saw %d requests, want at most 1 (the login) — the destructive finding must not have been touched", requests)
	}
}

func TestAttack_UnknownSchemaVersionIsRejected(t *testing.T) {
	// Config must load cleanly so the failure this test checks for is
	// actually the schema_version check, not an incidental one from a
	// missing env var that would make this test pass for the wrong reason.
	t.Setenv("SCANNER_IT_PASSWORD", "lab-pass")

	dir := t.TempDir()
	findingsPath := filepath.Join(dir, "findings.json")
	os.WriteFile(findingsPath, []byte(`{"schema_version":99,"findings":[]}`), 0o600)

	configPath := writeSQLiConfig(t, dir, "http://127.0.0.1:1")
	err := runAttack([]string{"--in", findingsPath, "--config", configPath, "--out", filepath.Join(dir, "out.json")})
	if err == nil {
		t.Fatal("runAttack() error = nil, want an error for an unrecognised schema_version")
	}
	if !strings.Contains(err.Error(), "schema_version") {
		t.Errorf("error = %q, want it to name schema_version specifically", err)
	}
}

func TestAttack_EmptyFindingsProducesEmptyOutput(t *testing.T) {
	t.Setenv("SCANNER_IT_PASSWORD", "lab-pass")
	dir := t.TempDir()
	findingsPath := filepath.Join(dir, "findings.json")
	os.WriteFile(findingsPath, []byte(`{"schema_version":1,"findings":[]}`), 0o600)

	configPath := writeSQLiConfig(t, dir, "http://127.0.0.1:1")
	outPath := filepath.Join(dir, "confirmed.json")
	if err := runAttack([]string{"--in", findingsPath, "--config", configPath, "--out", outPath}); err != nil {
		t.Fatalf("runAttack() error = %v", err)
	}

	var out model.FindingsFile
	mustReadJSON(t, outPath, &out)
	if len(out.Findings) != 0 {
		t.Errorf("got %d findings, want 0", len(out.Findings))
	}
}

func TestAttack_MissingFlagsAreRequired(t *testing.T) {
	if err := runAttack(nil); err == nil {
		t.Fatal("runAttack() error = nil, want --in and --config required")
	}
}

func TestReport_MissingInFlagIsRequired(t *testing.T) {
	if err := runReport(nil); err == nil {
		t.Fatal("runReport() error = nil, want --in required")
	}
}

func TestReport_DefaultsJSONPathFromOutPath(t *testing.T) {
	dir := t.TempDir()
	confirmedPath := filepath.Join(dir, "confirmed.json")
	out := model.FindingsFile{SchemaVersion: model.SchemaVersion, Findings: []model.Finding{}}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := os.WriteFile(confirmedPath, data, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	htmlPath := filepath.Join(dir, "custom-report.html")
	if err := runReport([]string{"--in", confirmedPath, "--out", htmlPath}); err != nil {
		t.Fatalf("runReport() error = %v", err)
	}

	wantJSONPath := filepath.Join(dir, "custom-report.json")
	if _, err := os.Stat(wantJSONPath); err != nil {
		t.Errorf("expected %s to exist (derived from --out), got: %v", wantJSONPath, err)
	}
}

// If --out already ends in .json, the derived JSON path collides with the
// HTML one; report must refuse rather than silently writing one over the
// other.
func TestReport_RejectsCollidingOutputPaths(t *testing.T) {
	dir := t.TempDir()
	confirmedPath := filepath.Join(dir, "confirmed.json")
	data, err := json.Marshal(model.FindingsFile{SchemaVersion: model.SchemaVersion, Findings: []model.Finding{}})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := os.WriteFile(confirmedPath, data, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	outPath := filepath.Join(dir, "report.json") // derived JSON path is identical
	err = runReport([]string{"--in", confirmedPath, "--out", outPath})
	if err == nil {
		t.Fatal("runReport() error = nil, want a collision error when --out and the JSON output resolve to the same file")
	}
	if !strings.Contains(err.Error(), "same file") {
		t.Errorf("error = %q, want it to explain the path collision", err.Error())
	}
	// The collision is caught before anything is rendered, so the output
	// path must not have been created at all.
	if _, statErr := os.Stat(outPath); statErr == nil {
		t.Error("output path was written despite the collision error")
	}
}

// writeNoAuthConfig writes a valid config with no auth block at all — the
// public-target case M1 makes possible.
func writeNoAuthConfig(t *testing.T, dir, baseURL string) string {
	t.Helper()
	host := strings.TrimPrefix(baseURL, "http://")
	path := filepath.Join(dir, "config.yaml")
	cfg := fmt.Sprintf(`schema_version: 1
target:
  base_url: %s
scope:
  allowed_hosts: ["%s"]
engine:
  max_concurrency: 4
  requests_per_second: 500
  timeout: 30s
checks:
  enabled: [missing-headers]
`, baseURL, host)
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

// A spec with protected routes against a config that carries no auth block
// must fail with a clear message before any request goes out — not scan the
// protected routes unauthenticated and report them as skipped.
func TestScan_RequiresAuthButNoAuthConfigured(t *testing.T) {
	dir := t.TempDir()
	specPath := writeSpec(t, dir) // /items, /secure, POST /items all require auth
	configPath := writeNoAuthConfig(t, dir, "http://127.0.0.1:9")
	outPath := filepath.Join(dir, "findings.json")

	err := runScan([]string{"--spec", specPath, "--config", configPath, "--out", outPath})
	if err == nil {
		t.Fatal("runScan() error = nil, want an error when the spec needs auth but none is configured")
	}
	if !strings.Contains(err.Error(), "require authentication") {
		t.Errorf("error = %q, want it to explain the spec needs auth", err.Error())
	}
	if _, statErr := os.Stat(outPath); statErr == nil {
		t.Error("findings.json was written despite the auth configuration error")
	}
}

// The mirror of the above for a public spec: no auth block, and the scan
// runs to completion without ever logging in.
func TestScan_PublicSpecScansWithNoAuthBlock(t *testing.T) {
	srv, lab := newLabServer(t)
	dir := t.TempDir()

	specPath := filepath.Join(dir, "openapi.yaml")
	spec := `openapi: 3.0.3
info: {title: Public, version: "1.0"}
paths:
  /health:
    get:
      responses: {"200": {description: OK}}
  /status:
    get:
      responses: {"200": {description: OK}}
`
	if err := os.WriteFile(specPath, []byte(spec), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	configPath := writeNoAuthConfig(t, dir, srv.URL)
	outPath := filepath.Join(dir, "findings.json")

	if err := runScan([]string{"--spec", specPath, "--config", configPath, "--out", outPath}); err != nil {
		t.Fatalf("runScan() error = %v, want a public spec to scan with no auth block", err)
	}
	if got := lab.logins.Load(); got != 0 {
		t.Errorf("logins = %d, want 0 — a public target must never trigger a login", got)
	}

	var out model.FindingsFile
	mustReadJSON(t, outPath, &out)
	if len(out.Findings) == 0 {
		t.Error("no findings — missing-headers should have fired on the bare public routes")
	}
}

// The attack stage enforces the same rule independently: a finding on a
// protected route with no auth block configured is an error, not a silent
// unauthenticated replay.
func TestAttack_RequiresAuthButNoAuthConfigured(t *testing.T) {
	dir := t.TempDir()
	configPath := writeNoAuthConfig(t, dir, "http://127.0.0.1:9")

	inPath := filepath.Join(dir, "findings.json")
	in := model.FindingsFile{
		SchemaVersion: model.SchemaVersion,
		Findings: []model.Finding{{
			ID:        "sqli-boolean:GET:/items:q",
			CheckName: "sqli-boolean",
			Endpoint:  model.Endpoint{Method: "GET", Path: "/items", RequiresAuth: true},
			Request:   model.CapturedRequest{Method: "GET", URL: "http://127.0.0.1:9/items?q=x", InjectedParam: "q", Payload: "x"},
		}},
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := os.WriteFile(inPath, data, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	outPath := filepath.Join(dir, "confirmed.json")
	err = runAttack([]string{"--in", inPath, "--config", configPath, "--out", outPath})
	if err == nil {
		t.Fatal("runAttack() error = nil, want an error when a finding needs auth but none is configured")
	}
	if !strings.Contains(err.Error(), "require authentication") {
		t.Errorf("error = %q, want it to explain the finding needs auth", err.Error())
	}
}
