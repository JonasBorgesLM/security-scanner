package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/JonasBorgesLM/security-scanner/internal/adapters/config"
	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
)

func TestAuthConfig_MapsEveryField(t *testing.T) {
	cfg := &config.Config{
		Auth: config.Auth{
			LoginEndpoint: "/signin",
			Method:        "PUT",
			Credentials: config.Credentials{
				Username:      "admin",
				Password:      "already-expanded",
				UsernameField: "email",
			},
			TokenPath:   "data.access_token",
			TokenHeader: "X-Token",
			TokenPrefix: "Bearer ",
		},
	}

	got := authConfig(cfg)

	if got.LoginEndpoint != "/signin" {
		t.Errorf("LoginEndpoint = %q, want /signin", got.LoginEndpoint)
	}
	if got.Method != "PUT" {
		t.Errorf("Method = %q, want PUT", got.Method)
	}
	if got.Credentials.Username != "admin" {
		t.Errorf("Username = %q, want admin", got.Credentials.Username)
	}
	if got.Credentials.Password != "already-expanded" {
		t.Errorf("Password = %q, want already-expanded", got.Credentials.Password)
	}
	if got.Credentials.UsernameField != "email" {
		t.Errorf("UsernameField = %q, want email", got.Credentials.UsernameField)
	}
	if got.TokenPath != "data.access_token" {
		t.Errorf("TokenPath = %q, want data.access_token", got.TokenPath)
	}
	if got.TokenHeader != "X-Token" {
		t.Errorf("TokenHeader = %q, want X-Token", got.TokenHeader)
	}
	if got.TokenPrefix != "Bearer " {
		t.Errorf("TokenPrefix = %q, want %q", got.TokenPrefix, "Bearer ")
	}
}

func TestEndpointCounts(t *testing.T) {
	endpoints := []model.Endpoint{
		{Method: "GET", Path: "/health"},
		{Method: "GET", Path: "/items", RequiresAuth: true},
		{Method: "POST", Path: "/items", RequiresAuth: true},
		{Method: "PUT", Path: "/items/{id}", RequiresAuth: true, Destructive: true},
		{Method: "DELETE", Path: "/items/{id}", RequiresAuth: true, Destructive: true},
	}

	if got := countRequiringAuth(endpoints); got != 4 {
		t.Errorf("countRequiringAuth() = %d, want 4", got)
	}
	if got := countDestructive(endpoints); got != 2 {
		t.Errorf("countDestructive() = %d, want 2", got)
	}
}

func TestEndpointCounts_EmptyInput(t *testing.T) {
	if got := countRequiringAuth(nil); got != 0 {
		t.Errorf("countRequiringAuth(nil) = %d, want 0", got)
	}
	if got := countDestructive(nil); got != 0 {
		t.Errorf("countDestructive(nil) = %d, want 0", got)
	}
}

func TestWriteJSON_ProducesIndentedFileWithTrailingNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.json")

	want := model.FindingsFile{
		SchemaVersion: model.SchemaVersion,
		Findings:      []model.Finding{},
	}
	if err := writeJSON(path, want); err != nil {
		t.Fatalf("writeJSON() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Error("output does not end with a newline — it should be a clean git diff")
	}

	var got model.FindingsFile
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if got.SchemaVersion != want.SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", got.SchemaVersion, want.SchemaVersion)
	}
}

// Identical input must produce a byte-identical file, so re-running a stage
// against an unchanged target shows up as an empty diff.
func TestWriteJSON_IsDeterministic(t *testing.T) {
	dir := t.TempDir()
	in := model.FindingsFile{
		SchemaVersion: model.SchemaVersion,
		Findings: []model.Finding{
			{ID: "f-1", CheckName: "missing-headers", Severity: "low"},
			{ID: "f-2", CheckName: "xss-reflected", Severity: "high"},
		},
	}

	first := filepath.Join(dir, "a.json")
	second := filepath.Join(dir, "b.json")
	if err := writeJSON(first, in); err != nil {
		t.Fatalf("writeJSON() error = %v", err)
	}
	if err := writeJSON(second, in); err != nil {
		t.Fatalf("writeJSON() error = %v", err)
	}

	a, _ := os.ReadFile(first)
	b, _ := os.ReadFile(second)
	if string(a) != string(b) {
		t.Errorf("two writes of the same value differ:\n%s\n---\n%s", a, b)
	}
}

func TestWriteJSON_OverwritesAtomically(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings.json")

	if err := writeJSON(path, model.FindingsFile{SchemaVersion: 1}); err != nil {
		t.Fatalf("first writeJSON() error = %v", err)
	}
	if err := writeJSON(path, model.FindingsFile{
		SchemaVersion: 1,
		Findings:      []model.Finding{{ID: "f-1"}},
	}); err != nil {
		t.Fatalf("second writeJSON() error = %v", err)
	}

	var got model.FindingsFile
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if len(got.Findings) != 1 {
		t.Errorf("Findings = %v, want the second write to have replaced the first", got.Findings)
	}

	// The temp file used for the atomic rename must not be left behind.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	if len(entries) != 1 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("directory contains %v, want only the output file", names)
	}
}

func TestWriteJSON_ErrorsOnUnwritableDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-subdir", "findings.json")

	if err := writeJSON(path, model.FindingsFile{}); err == nil {
		t.Fatal("writeJSON() error = nil, want an error for a missing directory")
	}
}

// TestRequestTimeout_ResolvesConfigOrDefault pins the policy the
// composition root owns: config.yaml decides when it says something, and
// silence means the default rather than "no limit at all" — which is the
// behaviour that let a single stalled route take a whole scan down.
func TestRequestTimeout_ResolvesConfigOrDefault(t *testing.T) {
	tests := []struct {
		name string
		set  time.Duration
		want time.Duration
	}{
		{name: "unset falls back to the default", set: 0, want: defaultRequestTimeout},
		{name: "configured value wins", set: 9 * time.Second, want: 9 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Engine.RequestTimeout = config.Duration(tt.set)

			if got := requestTimeout(cfg); got != tt.want {
				t.Errorf("requestTimeout() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestRequestTimeout_DefaultIsShorterThanTheExampleRunTimeout guards the
// relationship that makes the default useful at all: a per-request bound
// longer than the run's own deadline can never fire. configs/config.yaml
// ships engine.timeout: 5m.
func TestRequestTimeout_DefaultIsShorterThanTheExampleRunTimeout(t *testing.T) {
	if defaultRequestTimeout >= 5*time.Minute {
		t.Errorf("defaultRequestTimeout = %v, want well under the 5m run timeout configs/config.yaml ships",
			defaultRequestTimeout)
	}
}
