package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoad_ValidConfig(t *testing.T) {
	t.Setenv("SCANNER_TEST_LAB_PASSWORD", "s3cr3t-from-env")

	cfg, err := Load("testdata/config.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", cfg.SchemaVersion)
	}
	if cfg.Target.BaseURL != "http://localhost:8080" {
		t.Errorf("Target.BaseURL = %q, want http://localhost:8080", cfg.Target.BaseURL)
	}
	wantHosts := []string{"localhost:8080", "127.0.0.1:8080"}
	if len(cfg.Scope.AllowedHosts) != len(wantHosts) || cfg.Scope.AllowedHosts[0] != wantHosts[0] || cfg.Scope.AllowedHosts[1] != wantHosts[1] {
		t.Errorf("Scope.AllowedHosts = %v, want %v", cfg.Scope.AllowedHosts, wantHosts)
	}

	if cfg.Auth.LoginEndpoint != "/login" {
		t.Errorf("Auth.LoginEndpoint = %q, want /login", cfg.Auth.LoginEndpoint)
	}
	if cfg.Auth.Credentials.Username != "admin" {
		t.Errorf("Auth.Credentials.Username = %q, want admin", cfg.Auth.Credentials.Username)
	}
	if cfg.Auth.Credentials.Password != "s3cr3t-from-env" {
		t.Errorf("Auth.Credentials.Password = %q, want the expanded env value, not the literal ${VAR}", cfg.Auth.Credentials.Password)
	}
	if cfg.Auth.Credentials.UsernameField != "email" {
		t.Errorf("Auth.Credentials.UsernameField = %q, want email", cfg.Auth.Credentials.UsernameField)
	}
	if cfg.Auth.TokenPath != "data.access_token" {
		t.Errorf("Auth.TokenPath = %q, want data.access_token", cfg.Auth.TokenPath)
	}
	if cfg.Auth.TokenPrefix != "Bearer " {
		t.Errorf("Auth.TokenPrefix = %q, want %q", cfg.Auth.TokenPrefix, "Bearer ")
	}

	if cfg.Engine.MaxConcurrency != 5 {
		t.Errorf("Engine.MaxConcurrency = %d, want 5", cfg.Engine.MaxConcurrency)
	}
	if cfg.Engine.RequestsPerSecond != 10 {
		t.Errorf("Engine.RequestsPerSecond = %v, want 10", cfg.Engine.RequestsPerSecond)
	}
	if time.Duration(cfg.Engine.Timeout) != 5*time.Minute {
		t.Errorf("Engine.Timeout = %v, want 5m", cfg.Engine.Timeout)
	}
	if cfg.Engine.TestDestructive {
		t.Errorf("Engine.TestDestructive = true, want false")
	}

	wantChecks := []string{"missing-headers", "exposed-secrets", "sqli-boolean", "xss-reflected"}
	if len(cfg.Checks.Enabled) != len(wantChecks) {
		t.Fatalf("Checks.Enabled = %v, want %v", cfg.Checks.Enabled, wantChecks)
	}
	for i, name := range wantChecks {
		if cfg.Checks.Enabled[i] != name {
			t.Errorf("Checks.Enabled[%d] = %q, want %q", i, cfg.Checks.Enabled[i], name)
		}
	}
}

func TestLoad_MissingFile(t *testing.T) {
	if _, err := Load("testdata/does-not-exist.yaml"); err == nil {
		t.Fatal("Load() error = nil, want an error for a missing file")
	}
}

func TestLoad_MissingRequiredFieldsReportsAllOfThem(t *testing.T) {
	_, err := Load("testdata/missing-fields.yaml")
	if err == nil {
		t.Fatal("Load() error = nil, want an error listing every missing field")
	}

	// The auth block in this fixture is entirely empty, which is valid now
	// (a public target needs no credentials) — auth's optional/all-or-nothing
	// rule is covered by TestLoad_AuthOptional_* below. What this test proves
	// is that every OTHER missing required field is reported in one pass.
	wantSubstrings := []string{
		"target.base_url is required",
		"scope.allowed_hosts is required",
		"engine.max_concurrency must be greater than 0",
		"engine.requests_per_second must be greater than 0",
		"engine.timeout is required",
		"checks.enabled is required",
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err.Error(), want)
		}
	}
	// An all-empty auth block must not produce auth errors any more.
	if strings.Contains(err.Error(), "auth.") {
		t.Errorf("error %q reports an auth problem, but an empty auth block is valid", err.Error())
	}
}

func TestLoad_AuthOptionalWhenAbsent(t *testing.T) {
	cfg, err := Load("testdata/no-auth.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v, want a config with no auth block to be valid", err)
	}
	if cfg.Auth.Configured() {
		t.Errorf("Auth.Configured() = true, want false for a config with no auth block")
	}
}

func TestLoad_PartialAuthReportsMissingFields(t *testing.T) {
	_, err := Load("testdata/partial-auth.yaml")
	if err == nil {
		t.Fatal("Load() error = nil, want a half-filled auth block to be rejected")
	}
	// login_endpoint is set in the fixture, so the block counts as present
	// and the rest of the required set must be reported.
	wantSubstrings := []string{
		"auth.token_path is required when any auth field is set",
		"auth.credentials.username is required when any auth field is set",
		"auth.credentials.password is required when any auth field is set",
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err.Error(), want)
		}
	}
}

func TestLoad_UnsupportedSchemaVersion(t *testing.T) {
	_, err := Load("testdata/unsupported-schema-version.yaml")
	if err == nil {
		t.Fatal("Load() error = nil, want an error for an unsupported schema_version")
	}
	if !strings.Contains(err.Error(), "schema_version 99 is not supported") {
		t.Errorf("error = %q, want it to mention the unsupported version", err.Error())
	}
}

func TestLoad_TargetHostNotInScopeAllowlist(t *testing.T) {
	_, err := Load("testdata/host-out-of-scope.yaml")
	if err == nil {
		t.Fatal("Load() error = nil, want an error when target.base_url's host isn't in scope.allowed_hosts")
	}
	if !strings.Contains(err.Error(), "is not in scope.allowed_hosts") {
		t.Errorf("error = %q, want it to explain the ScopeGuard would block the target", err.Error())
	}
}

func TestLoad_InvalidDuration(t *testing.T) {
	_, err := Load("testdata/bad-duration.yaml")
	if err == nil {
		t.Fatal("Load() error = nil, want an error for an unparsable engine.timeout")
	}
	if !strings.Contains(err.Error(), "invalid duration") {
		t.Errorf("error = %q, want it to mention the invalid duration", err.Error())
	}
}

// A ${VAR} written inside a comment documents the syntax; it is not a
// reference to resolve. Expanding the raw file text (rather than the parsed
// scalar values) used to make the shipped configs/config.yaml unloadable
// because its own explanatory comment mentions ${VAR}.
func TestLoad_IgnoresPlaceholdersInComments(t *testing.T) {
	t.Setenv("SCANNER_TEST_LAB_PASSWORD", "s3cr3t-from-env")

	cfg, err := Load("testdata/placeholder-in-comment.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v — a ${VAR} in a comment must not be expanded", err)
	}
	if cfg.Auth.Credentials.Password != "s3cr3t-from-env" {
		t.Errorf("Credentials.Password = %q, want the real value still expanded", cfg.Auth.Credentials.Password)
	}
}

// The example config that ships with the tool must actually load, so a new
// operator's first copy-paste works. Its password placeholder is the only
// variable it needs.
func TestLoad_ShippedExampleConfigIsValid(t *testing.T) {
	t.Setenv("LAB_PASSWORD", "example")

	if _, err := Load("../../../configs/config.yaml"); err != nil {
		t.Fatalf("configs/config.yaml does not load: %v", err)
	}
}

func TestLoad_MalformedYAML(t *testing.T) {
	_, err := Load("testdata/malformed.yaml")
	if err == nil {
		t.Fatal("Load() error = nil, want a parse error for syntactically invalid YAML")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("error = %q, want it to identify the failure as a parse error", err.Error())
	}
}

func TestLoad_MissingEnvVar(t *testing.T) {
	_, err := Load("testdata/missing-env-var.yaml")
	if err == nil {
		t.Fatal("Load() error = nil, want an error for an unset ${VAR} in the config")
	}
	if !strings.Contains(err.Error(), "SCANNER_TEST_DEFINITELY_UNSET_VAR") {
		t.Errorf("error = %q, want it to name the missing environment variable", err.Error())
	}
}

func TestLoad_BurstIsOptional(t *testing.T) {
	t.Setenv("SCANNER_TEST_LAB_PASSWORD", "s3cr3t-from-env")

	cfg, err := Load("testdata/config.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	// The shipped example omits burst; the engine defaults it to 1.
	if cfg.Engine.Burst != 0 {
		t.Errorf("Engine.Burst = %d, want 0 when the file omits it", cfg.Engine.Burst)
	}
}

func TestLoad_NegativeBurstIsRejected(t *testing.T) {
	_, err := Load("testdata/negative-burst.yaml")
	if err == nil {
		t.Fatal("Load() error = nil, want an error for a negative engine.burst")
	}
	if !strings.Contains(err.Error(), "engine.burst") {
		t.Errorf("error = %q, want it to name the offending field", err)
	}
}
