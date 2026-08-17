# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Go CLI security scanner built for study purposes, targeting **only the author's own lab API** (controlled environment). It discovers vulnerabilities, confirms them via controlled/non-destructive attacks, and generates a report. The full architecture and rationale live in `doc/security-scanner-projeto.md` — read it before making structural changes; it is the source of truth for this project.

## Commands

```bash
go build ./...                          # build everything
go vet ./...                            # static checks
golangci-lint run ./...                 # lint (config in .golangci.yml)
go test ./...                           # run all tests
go test ./internal/checks/... -run TestX -v   # run a single test
go build -o scanner ./cmd/scanner       # build the CLI binary
```

CLI usage (subcommands are separate pipeline stages, chained via JSON files):

```bash
scanner scan   --spec openapi.yaml --config config.yaml --out findings.json
scanner attack --in findings.json  --config config.yaml --out confirmed.json
scanner report --in confirmed.json --out report.html
```

## Architecture

Lightweight hexagonal (ports/adapters), so checks can be tested against a fake `HTTPClient` with no real network calls.

- `internal/ports/` — interfaces only (`HTTPClient`, `Reporter`, `Store`).
- `internal/adapters/httpclient/` — the real HTTP client. **This is where `ScopeGuard` is wired in as a middleware** — every outbound request passes through it. Nothing bypasses this client.
- `internal/adapters/openapi/` — parses an OpenAPI spec into `[]Endpoint`.
- `internal/core/model/` — shared data types: `Endpoint`, `Check`, `CheckMetadata`, `Finding`, `CapturedRequest`, `Evidence`.
- `internal/core/engine/` — baseline collection + worker pool + rate limiter (`x/time/rate`) + orchestration. Three phases: `Collect` fetches one baseline response per endpoint **using only safe methods** (a POST endpoint is probed with GET; `Response.ProbedMethod` records the substitution); `BuildJobs` pairs targets with applicable checks and enforces the destructive and `RequiresAuth` gates; `Run` executes them across `max_concurrency` workers drawing from a channel, returning results in job order so output never depends on which worker finished first. `Run` also stamps `Endpoint`, `CheckName`, `Severity`, `OWASPCategory` and a deterministic `ID` onto every `Finding`, so checks never repeat metadata they already declared. The rate limiter is a `ports.HTTPClient` decorator the engine wraps around the client it was given, so it charges per *request*, not per job. Cancelling the context returns partial results plus an error — both phases refuse to let a truncated run look complete. A panicking check becomes a failed `Result`; a panic anywhere else in the pool drops that item rather than the process.
- `internal/core/auth/` — automatic login + single re-auth retry on 401. A route whose auth fails becomes `skipped`, never a false "vulnerable" finding.
- `internal/core/scope/` — `ScopeGuard`: allowlist of hosts. This is the hard security boundary of the whole tool.
- `internal/checks/` — one file per check, self-registering via `init()` into `registry.go` (same pattern as `database/sql` drivers). Each check declares `CheckMetadata{Kind: model.KindPassive|model.KindActive, AppliesTo: func(Endpoint) bool, ...}`. `RegisterCheck` panics on a duplicate/empty name or unknown `Kind` — startup-time programming errors, not runtime conditions. `Enabled(names)` resolves `checks.enabled` from config and **errors on an unknown name**, so a typo cannot silently disable a check and yield a clean-looking report.
- `internal/adapters/config/` — reads and validates `config.yaml`. Accumulates every validation failure into one message instead of stopping at the first, and cross-checks that `target.base_url`'s host is in `scope.allowed_hosts`.
- `internal/envexpand/` — shared `${VAR}` expansion used by `config` and `auth`. Expands YAML scalar values only (never comments) and errors, naming every unset variable, rather than passing a literal `${VAR}` through as a credential.
- `internal/report/` — HTML templates + JSON writer for the final report.
- `internal/checks/payloads/` and `internal/checks/patterns/` — attack payload wordlists (strings *sent to* the target, e.g. `payloads/sqli.txt`) and detection regexes (`patterns/secrets.txt`) respectively, both loaded via `go:embed` so they extend without touching check logic. Both live beside the check that embeds them rather than in a shared top-level directory — `go:embed` cannot ascend past the embedding source file's own directory, so there is nowhere else they could live and still be embeddable.
- `internal/attack/` — the `attack` stage. One `Confirmer` per check that has a proof of concept, self-registered via `init()` under `RegisterCheck`'s `CheckName` (same `database/sql`-style pattern as `internal/checks`). `Run` dispatches each `Finding` by `CheckName`; a `Finding` from a check with no registered `Confirmer` (a passive observation like `missing-headers`, which has nothing to "reproduce") passes through unchanged and is reported `skipped`, never silently promoted to `Confirmed: true`. Re-enforces the destructive gate independently of whatever produced `findings.json`, since `attack` is a separate process invocation that cannot assume that decision still holds.
- `configs/` — `config.yaml`: a single commented example covering target, scope, auth, engine tuning and enabled checks. Scope lives inside it under `scope.allowed_hosts` (there is no separate `scope.yaml`; `doc/security-scanner-projeto.md` §6 is the format of record).
- `cmd/scanner/` — CLI and **composition root**. The only place that picks concrete adapters, and therefore the only place responsible for handing every component the ScopeGuard-enforcing HTTP client.

### Pipeline contract

`scan` → `findings.json` (suspicions, `Confirmed: false`) → `attack` → `confirmed.json` (reproduced via the `CapturedRequest` stored on each `Finding`, using non-destructive PoCs) → `report` → HTML + JSON summary by severity. Each stage's output is a versioned (`schema_version`), git-diffable JSON file — manually reviewable before the next stage runs, and re-runnable on a different machine.

## Non-negotiable invariants

These constraints are the actual point of the project and must never be relaxed without the user explicitly asking:

1. **ScopeGuard is mandatory and centralized in the HTTP client.** No request may be constructed or sent through any other path. A host not in `scope.allowed_hosts` must be rejected before the request leaves the process. Core packages take a `ports.HTTPClient` and cannot verify which adapter they got — so `cmd/scanner` is the only place allowed to construct them, and it must always pass the `httpclient.Client` built around a `ScopeGuard`. Handing any component a bare `*http.Client` silently disables the boundary with no compile or test failure.
2. **Non-destructive by default.** `Endpoint.Destructive` (true for DELETE/PUT/PATCH) means the endpoint is skipped unless `engine.test_destructive` (or a per-endpoint opt-in) is explicitly set. Never add a check or attack that mutates/deletes state without that opt-in gate. Baseline collection is stricter still: it only ever sends GET/HEAD/OPTIONS, substituting GET for any unsafe method, because a phase named "collect" must not create or destroy anything.
3. **Rate-limited and worker-pooled.** All active traffic goes through the engine's worker pool + rate limiter — never fire requests in an unbounded loop, even in tests against a fake client, since check code should look the same whether the client is fake or real.
4. **Baseline comparison before flagging.** The engine collects one baseline response per endpoint up front and hands it to every check as `Target.Baseline`. Boolean/response-diff-based checks (e.g. SQLi) must compare against it, not against a hardcoded expectation, to avoid false positives from dynamic content (timestamps, CSRF tokens). `Target.Baseline` is nil when collection failed (`BaselineErr` says why) — a check that needs it must then return no findings, never treat the absence as evidence.
5. **Passive checks never touch the network.** A `KindPassive` check works from `Target.Baseline` alone; the engine enforces this by handing it a client that refuses every request (`ErrPassiveCheckRequest`). This is what keeps request count proportional to the spec instead of the spec times the number of enabled checks. `Target.Baseline` is shared by pointer across the checks running concurrently on one endpoint — it is **read-only**; mutating its `Headers` map or `Body` is a data race that also corrupts what the other checks compare against.
6. **Auth failure is `skipped`, not `vulnerable`.** Re-auth once on 401; if it still fails, the route must not produce a finding. A check that cannot conclude — no baseline, failed auth — returns `model.Skippedf(...)`, and the engine records `Result.Skipped` with the reason. Skipped routes must reach the report: showing a route as clean when it was never examined is worse than admitting it could not be looked at.
7. **Secrets only via env** (e.g. `${LAB_PASSWORD}` in `config.yaml`) — never commit credentials into config or test fixtures. An unset variable is a hard error naming it, never a silent pass-through of the literal `${VAR}`.
8. **Deterministic output.** Each stage's JSON is committed and reviewed by hand, so identical inputs must produce byte-identical files. Never let Go's randomized map iteration reach the output: sort before emitting (see `resolveSecurity` and `sortedPaths` in `internal/adapters/openapi`). The same rule bans wall-clock from findings: leave `Evidence.ResponseTime` zero unless the finding is *about* timing. `cmd/scanner.TestScan_IsReproducible` enforces this end to end.

## Testing approach

- Unit tests for checks run against a fake `HTTPClient` fed from `testdata/` — no real network.
- A dedicated baseline test proves dynamic content doesn't cause false positives.
- A dedicated `ScopeGuard` test proves an out-of-allowlist host is blocked.
- `cmd/scanner/pipeline_test.go` assembles the whole stack against an `httptest.Server`: it is the only place that proves ScopeGuard, auth, rate limiter, collection and a real check fit together. Add to it when a new layer lands.
- Integration tests against a real (vulnerable, lab-only) API via Docker Compose are optional.

## Implementation order

Checks are built in this order (see `doc/security-scanner-projeto.md` §7 for rationale): missing security headers (passive, **done** — `internal/checks/headers.go`) → exposed secrets (passive, **done** — `internal/checks/secrets.go`) → SQLi boolean-based (active, **done** — `internal/checks/sqli.go`) → XSS reflected (active) → IDOR / weak JWT (phase 2, require richer models).

`scanner report` is implemented (`internal/report/`): reads `confirmed.json`, renders `report.html` via `html/template` (never `text/template` — `Evidence`/`Request` carry attacker-influenced strings that must render as inert text) and `report.json` with the same executive summary and severity-first ordering. Remediation copy lives in a `CheckName`-keyed lookup inside the `report` package, not on `model.Finding` — it is presentation text, not part of the versioned pipeline schema. Unlike `scan`/`attack`, `report` never touches the network.

Two rules any secret-adjacent check must keep: **redact the value** in `Evidence` (findings.json is committed, so writing the secret there relocates the leak rather than reporting it), and put anything regex-shaped behind a placeholder filter — a check that flags `"password": "changeme"` in example docs is one people learn to ignore.

`sqli-boolean` is the first active check and sets the pattern any check that injects its own requests should follow: measure the endpoint's own noise (repeat a benign request `sqliNoiseSamples` times, same value every time) *before* comparing anything, and only flag a difference that clears that noise floor — never a fixed threshold, since what counts as "noise" is a property of the target, not a constant. It does not read `Target.Baseline`'s body (that baseline has no parameters filled in, so it cannot answer "does changing this parameter change the response"); it reuses only `Target.Baseline.URL` for the target's scheme and host, since nothing else in the `Check` contract carries that.

A new check is one file in `internal/checks/`: implement `model.Check`, call `RegisterCheck` from `init()`, and add its name to `checks.enabled`. Return `model.Skippedf(...)` rather than guessing when the baseline is missing, and set only `Finding.ID` (as a discriminator) plus `Evidence` — the engine fills in the rest.
