package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

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
	// secureHeaders, when set, makes /secure answer with a full set of
	// security headers so the check has something clean to find.
	mu      sync.Mutex
	methods []string
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

		if strings.HasPrefix(r.URL.Path, "/secure") {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Content-Security-Policy", "default-src 'none'")
			w.Header().Set("Referrer-Policy", "no-referrer")
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

	t.Run("HSTS is not reported against a plaintext lab", func(t *testing.T) {
		for _, f := range out.Findings {
			if strings.Contains(f.ID, "Strict-Transport-Security") {
				t.Errorf("%s reported over http:// — HSTS is a no-op there", f.ID)
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
