// Command scanner is the CLI entry point for the three pipeline stages:
// scan, attack and report. It is the composition root — the single place
// that decides which concrete adapters the core packages run against, and
// therefore the single place responsible for wiring the ScopeGuard into the
// only HTTP client anything else is given.
package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
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

// defaultRequestTimeout bounds one request when config.yaml does not say.
// Policy lives here rather than in the config package because cmd/scanner
// is the composition root — the place this project already puts the
// decisions about which concrete behaviour the core runs against.
//
// Thirty seconds is chosen to be far longer than any healthy response from
// a lab target and far shorter than a typical engine.timeout, so it fires
// only on a route that is genuinely stuck.
const defaultRequestTimeout = 30 * time.Second

// requestTimeout resolves the per-request bound: what config.yaml asked
// for, or the default when it said nothing. Validation already rejected a
// negative value.
func requestTimeout(cfg *config.Config) time.Duration {
	if d := time.Duration(cfg.Engine.RequestTimeout); d > 0 {
		return d
	}
	return defaultRequestTimeout
}

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
	client := httpclient.New(guard, nil, requestTimeout(cfg))

	// Resolve the enabled checks before spending a single request: a typo in
	// checks.enabled should fail immediately, not after a full collection.
	enabled, err := checks.Enabled(cfg.Checks.Enabled)
	if err != nil {
		return err
	}

	// Only build and use the Authenticator when the spec actually declares
	// protected routes. A fully public target needs no auth block at all, so
	// wiring one in unconditionally would force a pointless — and failing —
	// login before any scanning could start.
	scanClient := ports.HTTPClient(client)
	if countRequiringAuth(endpoints) > 0 {
		if !cfg.Auth.Configured() {
			return fmt.Errorf("scan: %d endpoint(s) require authentication but config.yaml has no auth block; add one or scan a spec with no protected routes",
				countRequiringAuth(endpoints))
		}
		authenticator, err := auth.New(cfg.Target.BaseURL, authConfig(cfg), client)
		if err != nil {
			return err
		}
		// Log in eagerly so bad credentials fail here, with a clear message,
		// rather than surfacing as a wave of skipped routes later.
		if err := authenticator.Authenticate(ctx); err != nil {
			return err
		}
		scanClient = authenticator
	}

	// `client` is the ScopeGuard-enforcing client with no Authenticator
	// above it, so it is exactly the anonymous identity: same boundary, same
	// timeout, no credentials. Passing it here rather than building a second
	// one is what keeps invariant 1 true for both identities — there is only
	// ever one path to the network, and it is guarded.
	eng, err := engine.New(engineConfig(cfg), scanClient, client)
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

	findings, examined, skipped, failed := summarise(results)
	examined = sortCoverage(examined, examinedKey)
	skipped = sortCoverage(append(skipped, heldBackEndpoints(targets, endpoints, cfg.Engine.TestDestructive)...), unexaminedKey)
	failed = sortCoverage(failed, unexaminedKey)

	out := model.FindingsFile{
		SchemaVersion: model.SchemaVersion,
		Coverage: model.Coverage{
			EndpointsTotal: len(endpoints),
			ChecksRun:      len(results),
			Examined:       examined,
			Skipped:        skipped,
			Failed:         failed,
		},
		Findings: findings,
	}
	if err := writeJSON(*outPath, out); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\nwrote %s (%d findings, %d examined, %d skipped, %d failed; %d checks run over %d endpoints)\n",
		*outPath, len(findings), len(examined), len(skipped), len(failed), len(results), len(endpoints))
	for _, s := range skipped {
		fmt.Fprintf(os.Stderr, "  skipped: %s\n", describe(s))
	}
	for _, f := range failed {
		fmt.Fprintf(os.Stderr, "  failed:  %s\n", describe(f))
	}
	return nil
}

// summarise flattens results into the findings to write plus the account of
// everything that could not be concluded. A scan that silently omits what it
// could not examine reads as a clean bill of health it has not earned, so
// both lists travel into the stage file rather than only onto the terminal.
func summarise(results []engine.Result) (findings []model.Finding, examined []model.ExaminedCheck, skipped, failed []model.Unexamined) {
	findings = []model.Finding{}
	for _, r := range results {
		// Findings and an admission are not alternatives. A check that
		// examined three parameters and could not reach a fourth produces
		// both, and a switch that picked one would either lose a real
		// finding or let a partly-examined route read as a whole one.
		findings = append(findings, r.Findings...)

		entry := model.Unexamined{
			Check:  r.CheckName,
			Method: r.Endpoint.Method,
			Path:   r.Endpoint.Path,
		}
		switch {
		case r.Skipped:
			entry.Reason = r.SkipReason
			skipped = append(skipped, entry)
		case r.Err != nil:
			entry.Reason = r.Err.Error()
			failed = append(failed, entry)
		default:
			// Reached a verdict. Recording it is what lets a reader see
			// that this route was looked at, rather than infer it from the
			// route's absence everywhere else.
			examined = append(examined, model.ExaminedCheck{
				Check: r.CheckName, Method: r.Endpoint.Method, Path: r.Endpoint.Path,
			})
		}
	}
	return findings, examined, skipped, failed
}

// heldBackEndpoints accounts for endpoints no check ever ran against,
// because something decided before scheduling that none should.
//
// Two reasons reach it today: the non-destructive gate, and a route the
// spec declares that the target does not actually serve. The engine drops
// both silently — correctly, since that is its job — but "the scanner did
// not look here" is exactly the kind of gap the coverage block exists to
// make visible. Reported per endpoint, with no check name, because the
// decision precedes any check.
//
// It takes the collected targets rather than the raw endpoints so absence
// can be read off the baseline, and it asks engine.AbsentFromTarget rather
// than re-deriving the rule — one definition, so the account and the
// scheduling cannot come to different conclusions.
func heldBackEndpoints(targets []model.Target, endpoints []model.Endpoint, testDestructive bool) []model.Unexamined {
	var out []model.Unexamined

	if !testDestructive {
		for _, ep := range endpoints {
			if ep.Destructive {
				out = append(out, model.Unexamined{
					Method: ep.Method,
					Path:   ep.Path,
					Reason: "endpoint is destructive; engine.test_destructive is not set",
				})
			}
		}
	}

	for _, t := range targets {
		if engine.AbsentFromTarget(t) {
			out = append(out, model.Unexamined{
				Method: t.Endpoint.Method,
				Path:   t.Endpoint.Path,
				Reason: engine.AbsentReason,
			})
		}
	}
	return out
}

// sortCoverage orders an account deterministically, by route then check.
// The engine already returns results in job order, which is stable — this
// is the same belt-and-braces the openapi adapter applies to its own
// output, so that a later change to how work is scheduled cannot turn a
// committed stage file into a spurious diff.
func sortCoverage[T any](entries []T, key func(T) (path, method, check string)) []T {
	slices.SortStableFunc(entries, func(a, b T) int {
		ap, am, ac := key(a)
		bp, bm, bc := key(b)
		return cmp.Or(
			strings.Compare(ap, bp),
			strings.Compare(am, bm),
			strings.Compare(ac, bc),
		)
	})
	return entries
}

func unexaminedKey(u model.Unexamined) (string, string, string) {
	return u.Path, u.Method, u.Check
}

func examinedKey(e model.ExaminedCheck) (string, string, string) {
	return e.Path, e.Method, e.Check
}

// describe renders one unexamined entry for the terminal.
func describe(u model.Unexamined) string {
	if u.Check == "" {
		return fmt.Sprintf("%s %s: %s", u.Method, u.Path, u.Reason)
	}
	return fmt.Sprintf("%s on %s %s: %s", u.Check, u.Method, u.Path, u.Reason)
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
	client := httpclient.New(guard, nil, requestTimeout(cfg))

	// Only wire in auth when a finding sits on a protected route — same
	// optional-auth rule as scan. A findings.json full of public routes needs
	// no credentials to reproduce.
	attackClient := ports.HTTPClient(client)
	if countFindingsRequiringAuth(in.Findings) > 0 {
		if !cfg.Auth.Configured() {
			return fmt.Errorf("attack: %d finding(s) are on endpoints that require authentication but config.yaml has no auth block; add one to reproduce them",
				countFindingsRequiringAuth(in.Findings))
		}
		authenticator, err := auth.New(cfg.Target.BaseURL, authConfig(cfg), client)
		if err != nil {
			return err
		}
		if err := authenticator.Authenticate(ctx); err != nil {
			return err
		}
		attackClient = authenticator
	}

	// A PoC is still traffic against the operator's own target: gentle by
	// design applies here exactly as it does during scan, via the same
	// rate limiter the engine uses internally — and, as there, one budget
	// shared by both identities. `client` is the guarded client with no
	// Authenticator above it, so it is the anonymous one.
	clients := engine.NewRateLimitedClients(attackClient, client, cfg.Engine.RequestsPerSecond, cfg.Engine.Burst)

	destructive := countDestructiveFindings(in.Findings)
	fmt.Fprintf(os.Stderr, "target:     %s\n", cfg.Target.BaseURL)
	fmt.Fprintf(os.Stderr, "findings:   %d (%d destructive)\n", len(in.Findings), destructive)
	if destructive > 0 && !cfg.Engine.TestDestructive {
		fmt.Fprintf(os.Stderr, "            %d destructive finding(s) will be skipped (engine.test_destructive is false)\n", destructive)
	}

	outcomes := attack.Run(ctx, in.Findings, clients, cfg.Engine.TestDestructive)
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("attack: run did not finish: %w", err)
	}

	confirmed, examined, skipped, failed := summariseAttack(outcomes)

	// Carry scan's account forward and add this stage's own. The two are
	// different questions — "could the scan examine this route?" and "could
	// the attack reproduce this finding?" — but a report built only on the
	// second would present a confirmed-nothing run over routes scan never
	// reached as though the target had simply held up.
	coverage := in.Coverage
	coverage.Examined = sortCoverage(append(slices.Clone(coverage.Examined), examined...), examinedKey)
	coverage.Skipped = sortCoverage(append(slices.Clone(coverage.Skipped), skipped...), unexaminedKey)
	coverage.Failed = sortCoverage(append(slices.Clone(coverage.Failed), failed...), unexaminedKey)

	out := model.FindingsFile{
		SchemaVersion: model.SchemaVersion,
		Coverage:      coverage,
		Findings:      allAttacked(outcomes),
	}
	if err := writeJSON(*outPath, out); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "\nwrote %s (%d confirmed, %d skipped, %d failed, %d not confirmed)\n",
		*outPath, confirmed, len(skipped), len(failed), len(out.Findings)-confirmed-len(skipped)-len(failed))
	for _, s := range skipped {
		fmt.Fprintf(os.Stderr, "  skipped: %s\n", describe(s))
	}
	for _, f := range failed {
		fmt.Fprintf(os.Stderr, "  failed:  %s\n", describe(f))
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

// summariseAttack counts confirmations and collects the account of outcomes
// attack could not act on — the same transparency principle runScan's
// summarise applies, in the stage where "no proof of concept exists for
// this check" is the most common reason of all.
func summariseAttack(outcomes []attack.Outcome) (confirmed int, examined []model.ExaminedCheck, skipped, failed []model.Unexamined) {
	for _, o := range outcomes {
		ep := o.Finding.Endpoint
		switch {
		case o.Skipped != "":
			skipped = append(skipped, model.Unexamined{
				Check: o.Finding.CheckName, Method: ep.Method, Path: ep.Path, Reason: o.Skipped,
			})
		case o.Err != nil:
			failed = append(failed, model.Unexamined{
				Check: o.Finding.CheckName, Method: ep.Method, Path: ep.Path, Reason: o.Err.Error(),
			})
		default:
			// A Confirmer ran to completion. It reached a verdict whether or
			// not the proof of concept reproduced, so it belongs in the same
			// account as a check that came back clean.
			examined = append(examined, model.ExaminedCheck{
				Check: o.Finding.CheckName, Method: ep.Method, Path: ep.Path,
			})
			if o.Finding.Confirmed {
				confirmed++
			}
		}
	}
	return confirmed, examined, skipped, failed
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

	jsonOut := *jsonPath
	if jsonOut == "" {
		jsonOut = strings.TrimSuffix(*outPath, filepath.Ext(*outPath)) + ".json"
	}
	// Resolve both to the same form before comparing: otherwise one would
	// silently overwrite the other (e.g. --out report.json makes the derived
	// JSON path collide with the HTML one), leaving a single file that is
	// neither what was asked for.
	if samePath(*outPath, jsonOut) {
		return fmt.Errorf("report: --out (%s) and the JSON output (%s) resolve to the same file; pass a distinct --json path",
			*outPath, jsonOut)
	}

	data := report.Build(in.Findings, in.Coverage)

	var html bytes.Buffer
	if err := data.WriteHTML(&html); err != nil {
		return fmt.Errorf("report: render %s: %w", *outPath, err)
	}
	if err := writeFile(*outPath, html.Bytes()); err != nil {
		return err
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
			Username:      cfg.Auth.Credentials.Username,
			Password:      cfg.Auth.Credentials.Password,
			UsernameField: cfg.Auth.Credentials.UsernameField,
		},
		TokenPath:    cfg.Auth.TokenPath,
		TokenHeader:  cfg.Auth.TokenHeader,
		ExtraHeaders: cfg.Auth.ExtraHeaders,
		TokenPrefix:  cfg.Auth.TokenPrefix,
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

// samePath reports whether a and b name the same file. It compares absolute,
// cleaned forms so "report.json" and "./report.json" are recognised as one;
// it does not resolve symlinks, which is more than this collision guard
// needs. If either path cannot be made absolute, it falls back to comparing
// cleaned relative forms rather than claiming they differ.
func samePath(a, b string) bool {
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return absA == absB
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
