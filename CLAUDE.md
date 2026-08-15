# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A Go CLI security scanner built for study purposes, targeting **only the author's own lab API** (controlled environment). It discovers vulnerabilities, confirms them via controlled/non-destructive attacks, and generates a report. The full architecture and rationale live in `doc/security-scanner-projeto.md` — read it before making structural changes; it is the source of truth for this project.

## Commands

```bash
go build ./...                          # build everything
go vet ./...                            # static checks
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
- `internal/core/engine/` — worker pool + rate limiter (`x/time/rate`) + orchestration. Only spends real requests on `Kind: "active"` checks; passive checks don't hit the network.
- `internal/core/auth/` — automatic login + single re-auth retry on 401. A route whose auth fails becomes `skipped`, never a false "vulnerable" finding.
- `internal/core/scope/` — `ScopeGuard`: allowlist of hosts. This is the hard security boundary of the whole tool.
- `internal/checks/` — one file per check, self-registering via `init()` into `registry.go` (same pattern as `database/sql` drivers). Each check declares `CheckMetadata{Kind: "passive"|"active", AppliesTo: func(Endpoint) bool, ...}`.
- `internal/report/` — HTML templates + JSON writer for the final report.
- `payloads/` — attack payload wordlists, loaded via `go:embed` so they can be extended without touching check logic.
- `configs/` — `config.yaml` (target, scope, auth, engine tuning, enabled checks) and `scope.yaml`.

### Pipeline contract

`scan` → `findings.json` (suspicions, `Confirmed: false`) → `attack` → `confirmed.json` (reproduced via the `CapturedRequest` stored on each `Finding`, using non-destructive PoCs) → `report` → HTML + JSON summary by severity. Each stage's output is a versioned (`schema_version`), git-diffable JSON file — manually reviewable before the next stage runs, and re-runnable on a different machine.

## Non-negotiable invariants

These constraints are the actual point of the project and must never be relaxed without the user explicitly asking:

1. **ScopeGuard is mandatory and centralized in the HTTP client.** No request may be constructed or sent through any other path. A host not in `scope.allowed_hosts` must be rejected before the request leaves the process.
2. **Non-destructive by default.** `Endpoint.Destructive` (true for DELETE/PUT/PATCH) means the endpoint is skipped unless `engine.test_destructive` (or a per-endpoint opt-in) is explicitly set. Never add a check or attack that mutates/deletes state without that opt-in gate.
3. **Rate-limited and worker-pooled.** All active traffic goes through the engine's worker pool + rate limiter — never fire requests in an unbounded loop, even in tests against a fake client, since check code should look the same whether the client is fake or real.
4. **Baseline comparison before flagging.** Boolean/response-diff-based checks (e.g. SQLi) must compare against a captured baseline response, not a hardcoded expectation, to avoid false positives from dynamic content (timestamps, CSRF tokens).
5. **Auth failure is `skipped`, not `vulnerable`.** Re-auth once on 401; if it still fails, the route must not produce a finding.
6. **Secrets only via env** (e.g. `${LAB_PASSWORD}` in `config.yaml`) — never commit credentials into config or test fixtures.

## Testing approach

- Unit tests for checks run against a fake `HTTPClient` fed from `testdata/` — no real network.
- A dedicated baseline test proves dynamic content doesn't cause false positives.
- A dedicated `ScopeGuard` test proves an out-of-allowlist host is blocked.
- Integration tests against a real (vulnerable, lab-only) API via Docker Compose are optional.

## Implementation order

Checks are built in this order (see `doc/security-scanner-projeto.md` §7 for rationale): missing security headers (passive) → exposed secrets (passive) → SQLi boolean-based (active) → XSS reflected (active) → IDOR / weak JWT (phase 2, require richer models).
