// Command scanner is the CLI entry point for the three pipeline stages:
// scan, attack and report. It is the composition root — the single place
// that decides which concrete adapters the core packages run against, and
// therefore the single place responsible for wiring the ScopeGuard into the
// only HTTP client anything else is given.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/JonasBorgesLM/security-scanner/internal/adapters/config"
	"github.com/JonasBorgesLM/security-scanner/internal/adapters/httpclient"
	"github.com/JonasBorgesLM/security-scanner/internal/adapters/openapi"
	"github.com/JonasBorgesLM/security-scanner/internal/attack"
	"github.com/JonasBorgesLM/security-scanner/internal/checks"
	"github.com/JonasBorgesLM/security-scanner/internal/core/auth"
	"github.com/JonasBorgesLM/security-scanner/internal/core/engine"
	"github.com/JonasBorgesLM/security-scanner/internal/core/model"
	"github.com/JonasBorgesLM/security-scanner/internal/core/scope"
	"github.com/JonasBorgesLM/security-scanner/internal/ports"
	"github.com/JonasBorgesLM/security-scanner/internal/report"
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
  scanner report --in confirmed.json --out report.html [--json report.json]

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

	// Resolve the enabled checks before spending a single request: a typo in
	// checks.enabled should fail immediately, not after a full collection.
	enabled, err := checks.Enabled(cfg.Checks.Enabled)
	if err != nil {
		return err
	}

	authenticator, err := auth.New(cfg.Target.BaseURL, authConfig(cfg), client)
	if err != nil {
		return err
	}

	// Only put the Authenticator in the path when the spec actually declares
	// protected routes. It logs in lazily on its first request, so wrapping
	// an unauthenticated API in it would force a pointless — and failing —
	// login before any scanning could start.
	scanClient := ports.HTTPClient(client)
	if countRequiringAuth(endpoints) > 0 {
		// Log in eagerly so bad credentials fail here, with a clear message,
		// rather than surfacing as a wave of skipped routes later.
		if err := authenticator.Authenticate(ctx); err != nil {
			return err
		}
		scanClient = authenticator
	}

	eng, err := engine.New(engineConfig(cfg), scanClient)
	if err != nil {
		return err
	}

	printScanSummary(cfg, *specPath, endpoints, enabled)

	targets, err := eng.Collect(ctx, endpoints)
	if err != nil {
		return fmt.Errorf("scan: baseline collection incomplete, refusing to report a partial scan as a whole one: %w", err)
	}

	results, err := eng.Run(ctx, eng.BuildJobs(targets, enabled))
	if err != nil {
		return fmt.Errorf("scan: checks incomplete, refusing to report a partial scan as a whole one: %w", err)
	}

	findings, skipped, failed := summarise(results)

	out := model.FindingsFile{
		SchemaVersion: model.SchemaVersion,
		Findings:      findings,
	}
	if err := writeJSON(*outPath, out); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\nwrote %s (%d findings, %d skipped, %d failed)\n",
		*outPath, len(findings), len(skipped), len(failed))
	for _, s := range skipped {
		fmt.Fprintf(os.Stderr, "  skipped: %s\n", s)
	}
	for _, f := range failed {
		fmt.Fprintf(os.Stderr, "  failed:  %s\n", f)
	}
	return nil
}

// summarise flattens results into the findings to write plus human-readable
// lines for the runs that could not conclude. Skipped and failed routes are
// reported explicitly: a scan that silently omits what it could not examine
// reads as a clean bill of health it has not earned.
func summarise(results []engine.Result) (findings []model.Finding, skipped, failed []string) {
	findings = []model.Finding{}
	for _, r := range results {
		switch {
		case r.Skipped:
			skipped = append(skipped, fmt.Sprintf("%s on %s %s: %s",
				r.CheckName, r.Endpoint.Method, r.Endpoint.Path, r.SkipReason))
		case r.Err != nil:
			failed = append(failed, fmt.Sprintf("%s on %s %s: %v",
				r.CheckName, r.Endpoint.Method, r.Endpoint.Path, r.Err))
		default:
			findings = append(findings, r.Findings...)
		}
	}
	return findings, skipped, failed
}

// engineConfig maps the YAML-facing config onto the engine's own, the same
// adapter/core seam authConfig sits on.
func engineConfig(cfg *config.Config) engine.Config {
	return engine.Config{
		BaseURL:           cfg.Target.BaseURL,
		MaxConcurrency:    cfg.Engine.MaxConcurrency,
		RequestsPerSecond: cfg.Engine.RequestsPerSecond,
		Burst:             cfg.Engine.Burst,
		TestDestructive:   cfg.Engine.TestDestructive,
	}
}

// runAttack reads findings.json, replays each unconfirmed finding's
// CapturedRequest with a non-destructive proof of concept, and writes
// confirmed.json. It shares runScan's wiring (ScopeGuard, auth, rate
// limiting) because a Confirmer sends real requests to the same target —
// the security boundary that matters during scan matters exactly as much
// here.
func runAttack(args []string) error {
	fs := flag.NewFlagSet("attack", flag.ExitOnError)
	inPath := fs.String("in", "", "path to findings.json (required)")
	configPath := fs.String("config", "", "path to config.yaml (required)")
	outPath := fs.String("out", "confirmed.json", "path to write the confirmed JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inPath == "" || *configPath == "" {
		return errors.New("attack: --in and --config are required")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	in, err := readFindings(*inPath)
	if err != nil {
		return err
	}
	if len(in.Findings) == 0 {
		fmt.Fprintf(os.Stderr, "%s has no findings; nothing to attack\n", *inPath)
		return writeJSON(*outPath, model.FindingsFile{SchemaVersion: model.SchemaVersion, Findings: []model.Finding{}})
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(cfg.Engine.Timeout))
	defer cancel()

	// Same boundary as scan: the ScopeGuard-wrapped client is the only path
	// to the network, for a Confirmer exactly as much as for a check.
	guard := scope.NewScopeGuard(cfg.Scope.AllowedHosts)
	client := httpclient.New(guard, nil)

	authenticator, err := auth.New(cfg.Target.BaseURL, authConfig(cfg), client)
	if err != nil {
		return err
	}

	attackClient := ports.HTTPClient(client)
	if countFindingsRequiringAuth(in.Findings) > 0 {
		if err := authenticator.Authenticate(ctx); err != nil {
			return err
		}
		attackClient = authenticator
	}

	// A PoC is still traffic against the operator's own target: gentle by
	// design applies here exactly as it does during scan, via the same
	// rate limiter the engine uses internally.
	rateLimited := engine.NewRateLimitedClient(attackClient, cfg.Engine.RequestsPerSecond, cfg.Engine.Burst)

	destructive := countDestructiveFindings(in.Findings)
	fmt.Fprintf(os.Stderr, "target:     %s\n", cfg.Target.BaseURL)
	fmt.Fprintf(os.Stderr, "findings:   %d (%d destructive)\n", len(in.Findings), destructive)
	if destructive > 0 && !cfg.Engine.TestDestructive {
		fmt.Fprintf(os.Stderr, "            %d destructive finding(s) will be skipped (engine.test_destructive is false)\n", destructive)
	}

	outcomes := attack.Run(ctx, in.Findings, rateLimited, cfg.Engine.TestDestructive)
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("attack: run did not finish: %w", err)
	}

	confirmed, skipped, failed := summariseAttack(outcomes)

	out := model.FindingsFile{
		SchemaVersion: model.SchemaVersion,
		Findings:      allAttacked(outcomes),
	}
	if err := writeJSON(*outPath, out); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\nwrote %s (%d confirmed, %d skipped, %d failed, %d not confirmed)\n",
		*outPath, confirmed, len(skipped), len(failed), len(out.Findings)-confirmed-len(skipped)-len(failed))
	for _, s := range skipped {
		fmt.Fprintf(os.Stderr, "  skipped: %s\n", s)
	}
	for _, f := range failed {
		fmt.Fprintf(os.Stderr, "  failed:  %s\n", f)
	}
	return nil
}

// readFindings loads and validates a findings.json / confirmed.json file.
// Shared by attack (reads findings.json) and report (reads confirmed.json).
func readFindings(path string) (model.FindingsFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return model.FindingsFile{}, fmt.Errorf("read %s: %w", path, err)
	}
	var f model.FindingsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return model.FindingsFile{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if f.SchemaVersion != model.SchemaVersion {
		return model.FindingsFile{}, fmt.Errorf("%s has schema_version %d, this build writes %d",
			path, f.SchemaVersion, model.SchemaVersion)
	}
	return f, nil
}

// summariseAttack counts confirmations and collects the human-readable
// lines for outcomes attack could not act on, the same transparency
// principle runScan's summarise applies to skipped/failed checks.
func summariseAttack(outcomes []attack.Outcome) (confirmed int, skipped, failed []string) {
	for _, o := range outcomes {
		switch {
		case o.Skipped != "":
			skipped = append(skipped, fmt.Sprintf("%s on %s %s: %s",
				o.Finding.CheckName, o.Finding.Endpoint.Method, o.Finding.Endpoint.Path, o.Skipped))
		case o.Err != nil:
			failed = append(failed, fmt.Sprintf("%s on %s %s: %v",
				o.Finding.CheckName, o.Finding.Endpoint.Method, o.Finding.Endpoint.Path, o.Err))
		case o.Finding.Confirmed:
			confirmed++
		}
	}
	return confirmed, skipped, failed
}

// allAttacked returns every outcome's Finding, confirmed or not: attack
// never drops a finding from the file, since the pipeline's whole audit
// trail depends on every stage accounting for what it saw.
func allAttacked(outcomes []attack.Outcome) []model.Finding {
	out := make([]model.Finding, len(outcomes))
	for i, o := range outcomes {
		out[i] = o.Finding
	}
	return out
}

func countFindingsRequiringAuth(findings []model.Finding) int {
	n := 0
	for _, f := range findings {
		if f.Endpoint.RequiresAuth {
			n++
		}
	}
	return n
}

func countDestructiveFindings(findings []model.Finding) int {
	n := 0
	for _, f := range findings {
		if f.Endpoint.Destructive {
			n++
		}
	}
	return n
}

// runReport reads confirmed.json and renders it as an HTML report plus a
// report.json summary. Unlike scan and attack it never touches the network
// — no ScopeGuard, client, or auth wiring is needed, since rendering
// already-collected findings can't reach the target.
func runReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	inPath := fs.String("in", "", "path to confirmed.json (required)")
	outPath := fs.String("out", "report.html", "path to write the HTML report")
	jsonPath := fs.String("json", "", "path to write the JSON report (default: --out with its extension replaced by .json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inPath == "" {
		return errors.New("report: --in is required")
	}

	in, err := readFindings(*inPath)
	if err != nil {
		return err
	}

	data := report.Build(in.Findings)

	var html bytes.Buffer
	if err := data.WriteHTML(&html); err != nil {
		return fmt.Errorf("report: render %s: %w", *outPath, err)
	}
	if err := writeFile(*outPath, html.Bytes()); err != nil {
		return err
	}

	jsonOut := *jsonPath
	if jsonOut == "" {
		jsonOut = strings.TrimSuffix(*outPath, filepath.Ext(*outPath)) + ".json"
	}
	var js bytes.Buffer
	if err := data.WriteJSON(&js); err != nil {
		return fmt.Errorf("report: render %s: %w", jsonOut, err)
	}
	if err := writeFile(jsonOut, js.Bytes()); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "wrote %s and %s (%d findings, %d confirmed)\n",
		*outPath, jsonOut, data.Summary.TotalFindings, data.Summary.TotalConfirmed)
	return nil
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
func printScanSummary(cfg *config.Config, specPath string, endpoints []model.Endpoint, enabled []model.Check) {
	destructive := countDestructive(endpoints)

	names := make([]string, len(enabled))
	for i, c := range enabled {
		names[i] = c.Metadata().Name
	}

	fmt.Fprintf(os.Stderr, "target:     %s\n", cfg.Target.BaseURL)
	fmt.Fprintf(os.Stderr, "scope:      %v\n", cfg.Scope.AllowedHosts)
	fmt.Fprintf(os.Stderr, "spec:       %s\n", specPath)
	fmt.Fprintf(os.Stderr, "endpoints:  %d (%d require auth, %d destructive)\n",
		len(endpoints), countRequiringAuth(endpoints), destructive)
	fmt.Fprintf(os.Stderr, "checks:     %s\n", strings.Join(names, ", "))

	if destructive > 0 && !cfg.Engine.TestDestructive {
		fmt.Fprintf(os.Stderr, "            %d destructive endpoint(s) will be skipped (engine.test_destructive is false)\n", destructive)
	}
}

// writeJSON writes v as indented JSON with a trailing newline, so each
// stage's output stays readable and git-diffable between runs.
func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	return writeFile(path, append(data, '\n'))
}

// writeFile writes data to a temporary file in the destination directory
// and renames it into place, so an interrupted run cannot leave a
// half-written pipeline-stage file behind — the same atomicity every stage
// output (findings.json, confirmed.json, report.html, report.json) needs.
func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	// No-op once the rename below succeeds; nothing useful to do if it fails.
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
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
