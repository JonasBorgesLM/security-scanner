// Command scanner is the CLI entry point for the three pipeline stages:
// scan, attack and report. It is the composition root — the single place
// that decides which concrete adapters the core packages run against, and
// therefore the single place responsible for wiring the ScopeGuard into the
// only HTTP client anything else is given.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/JonasBorgesLM/security-scanner/internal/adapters/config"
	"github.com/JonasBorgesLM/security-scanner/internal/adapters/httpclient"
	"github.com/JonasBorgesLM/security-scanner/internal/adapters/openapi"
	"github.com/JonasBorgesLM/security-scanner/internal/core/auth"
	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
	"github.com/JonasBorgesLM/security-scanner/internal/core/scope"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "scan":
		err = runScan(os.Args[2:])
	case "attack":
		err = runAttack(os.Args[2:])
	case "report":
		err = runReport(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `scanner - security scanner for lab APIs

Usage:
  scanner scan   --spec openapi.yaml --config config.yaml --out findings.json
  scanner attack --in findings.json  --config config.yaml --out confirmed.json
  scanner report --in confirmed.json --out report.html

Only ever point this at infrastructure you own or are authorised to test.
Hosts outside scope.allowed_hosts in config.yaml are rejected before any
request leaves the process.`)
}

// runScan imports routes from the OpenAPI spec, authenticates against the
// target, and writes findings.json.
func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	specPath := fs.String("spec", "", "path to the OpenAPI 3 spec (required)")
	configPath := fs.String("config", "", "path to config.yaml (required)")
	outPath := fs.String("out", "findings.json", "path to write the findings JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *specPath == "" || *configPath == "" {
		return errors.New("scan: --spec and --config are required")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	// Ctrl+C and the configured engine.timeout both cancel the whole run.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Engine.Timeout))
	defer cancel()

	endpoints, err := openapi.Load(ctx, *specPath)
	if err != nil {
		return err
	}
	if len(endpoints) == 0 {
		return fmt.Errorf("scan: %s declares no operations", *specPath)
	}

	// The ScopeGuard is built first and handed to the HTTP client, which is
	// the only object below that can reach the network. Everything else —
	// including the Authenticator's own login request — goes through this
	// one client, so no code path can bypass the allowlist.
	guard := scope.NewScopeGuard(cfg.Scope.AllowedHosts)
	client := httpclient.New(guard, nil)

	authenticator, err := auth.New(cfg.Target.BaseURL, authConfig(cfg), client)
	if err != nil {
		return err
	}

	// Log in eagerly so bad credentials fail here, with a clear message,
	// rather than surfacing as a wave of skipped routes later.
	if countRequiringAuth(endpoints) > 0 {
		if err := authenticator.Authenticate(ctx); err != nil {
			return err
		}
	}

	printScanSummary(cfg, *specPath, endpoints)

	// No checks are registered yet (internal/checks is still a stub), so
	// this run discovers routes and proves the wiring without producing
	// findings. The file is still written so the stage contract holds and
	// `attack` has a well-formed input the moment checks land.
	out := model.FindingsFile{
		SchemaVersion: model.SchemaVersion,
		Findings:      []model.Finding{},
	}
	if err := writeJSON(*outPath, out); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\nwrote %s (0 findings)\n", *outPath)
	fmt.Fprintln(os.Stderr, "note: no checks are registered yet — this run only imported and authenticated against the target.")
	return nil
}

func runAttack(args []string) error {
	fs := flag.NewFlagSet("attack", flag.ExitOnError)
	in := fs.String("in", "", "path to findings.json (required)")
	configPath := fs.String("config", "", "path to config.yaml (required)")
	out := fs.String("out", "confirmed.json", "path to write the confirmed JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_, _, _ = *in, *configPath, *out

	return errors.New("attack: not implemented yet — depends on the checks registry and engine")
}

func runReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	in := fs.String("in", "", "path to confirmed.json (required)")
	out := fs.String("out", "report.html", "path to write the HTML report")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_, _ = *in, *out

	return errors.New("report: not implemented yet — depends on the attack stage output")
}

// authConfig maps the YAML-facing config.Auth onto the domain-facing
// auth.Config. The two types stay deliberately separate: the adapter owns
// the file format, the core owns the behaviour, and this function is the
// seam between them. ${VAR} references were already expanded by
// config.Load, so auth.New's own expansion pass is a no-op here.
func authConfig(cfg *config.Config) auth.Config {
	return auth.Config{
		LoginEndpoint: cfg.Auth.LoginEndpoint,
		Method:        cfg.Auth.Method,
		Credentials: auth.Credentials{
			Username: cfg.Auth.Credentials.Username,
			Password: cfg.Auth.Credentials.Password,
		},
		TokenPath:   cfg.Auth.TokenPath,
		TokenHeader: cfg.Auth.TokenHeader,
		TokenPrefix: cfg.Auth.TokenPrefix,
	}
}

func countRequiringAuth(endpoints []model.Endpoint) int {
	n := 0
	for _, ep := range endpoints {
		if ep.RequiresAuth {
			n++
		}
	}
	return n
}

func countDestructive(endpoints []model.Endpoint) int {
	n := 0
	for _, ep := range endpoints {
		if ep.Destructive {
			n++
		}
	}
	return n
}

// printScanSummary reports what the run is about to work with. It goes to
// stderr so stdout stays free for future machine-readable output.
func printScanSummary(cfg *config.Config, specPath string, endpoints []model.Endpoint) {
	destructive := countDestructive(endpoints)

	fmt.Fprintf(os.Stderr, "target:     %s\n", cfg.Target.BaseURL)
	fmt.Fprintf(os.Stderr, "scope:      %v\n", cfg.Scope.AllowedHosts)
	fmt.Fprintf(os.Stderr, "spec:       %s\n", specPath)
	fmt.Fprintf(os.Stderr, "endpoints:  %d (%d require auth, %d destructive)\n",
		len(endpoints), countRequiringAuth(endpoints), destructive)

	if destructive > 0 && !cfg.Engine.TestDestructive {
		fmt.Fprintf(os.Stderr, "            %d destructive endpoint(s) will be skipped (engine.test_destructive is false)\n", destructive)
	}
}

// writeJSON writes v as indented JSON with a trailing newline, so each
// stage's output stays readable and git-diffable between runs. It writes to
// a temporary file in the destination directory and renames it into place,
// so an interrupted run cannot leave a half-written findings file behind.
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename below succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("finalise %s: %w", path, err)
	}
	return nil
}
