# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

The general engineering rules — effort proportional to the task, architecture
discipline, clean code, testing, review, security, git hygiene, verification —
are in `~/.claude/CLAUDE.md` and are already loaded. This file carries only what
is true of this scanner.

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

- `internal/ports/` — interfaces only (`HTTPClient`). (`Reporter`/`Store` were considered but dropped as YAGNI — the report writes files directly and stage output is JSON on disk.)
- `internal/adapters/httpclient/` — the real HTTP client. **This is where `ScopeGuard` is wired in as a middleware** — every outbound request passes through it. Nothing bypasses this client.
- `internal/adapters/openapi/` — parses an OpenAPI spec into `[]Endpoint`.
- `internal/core/model/` — shared data types: `Endpoint`, `Check`, `CheckMetadata`, `Finding`, `CapturedRequest`, `Evidence`.
- `internal/core/engine/` — baseline collection + worker pool + rate limiter (`x/time/rate`) + orchestration. Three phases: `Collect` fetches one baseline response per endpoint **using only safe methods** (a POST endpoint is probed with GET; `Response.ProbedMethod` records the substitution); `BuildJobs` pairs targets with applicable checks and enforces the destructive and `RequiresAuth` gates, and drops routes `AbsentFromTarget` reports as missing — a 404 answered to the endpoint's **own** method on a path with **no** template parameter, the only reading of a 404 that is not ambiguous (a substituted method can 404 for lacking a handler; a placeholder id can 404 for not existing). Dropping produces no `Result`, so `cmd/scanner` accounts for those endpoints from the same predicate, as it already does for the destructive gate. The rule errs towards declaring absence: being wrong that way loses coverage *and says so in the report*, while being wrong the other way spends probes on nothing and records the route as examined and clean; `Run` executes them across `max_concurrency` workers drawing from a channel, returning results in job order so output never depends on which worker finished first. `Run` also stamps `Endpoint`, `CheckName`, `Severity`, `OWASPCategory` and a deterministic `ID` onto every `Finding`, so checks never repeat metadata they already declared. The rate limiter is a `ports.HTTPClient` decorator the engine wraps around the client it was given, so it charges per *request*, not per job. Cancelling the context returns partial results plus an error — both phases refuse to let a truncated run look complete. A panicking check becomes a failed `Result`; a panic anywhere else in the pool drops that item rather than the process.
- `internal/core/auth/` — automatic login + single re-auth retry on 401. A route whose auth fails becomes `skipped`, never a false "vulnerable" finding.
- `internal/core/scope/` — `ScopeGuard`: allowlist of hosts. This is the hard security boundary of the whole tool.
- `internal/checks/` — one file per check, self-registering via `init()` into `registry.go` (same pattern as `database/sql` drivers). Each check declares `CheckMetadata{Kind: model.KindPassive|model.KindActive, AppliesTo: func(Endpoint) bool, ...}`. `RegisterCheck` panics on a duplicate/empty name or unknown `Kind` — startup-time programming errors, not runtime conditions. `Enabled(names)` resolves `checks.enabled` from config and **errors on an unknown name**, so a typo cannot silently disable a check and yield a clean-looking report.
- `internal/adapters/config/` — reads and validates `config.yaml`. Accumulates every validation failure into one message instead of stopping at the first, and cross-checks that `target.base_url`'s host is in `scope.allowed_hosts`. The `auth` block is optional and all-or-nothing: absent is valid (a fully public target), but any field set requires the whole set (`Auth.anyFieldSet`/`Configured`). Whether the target *actually* needs auth depends on the spec, so `cmd/scanner` (`runScan`/`runAttack`) makes that cross-check — building the `Authenticator` only when an endpoint requires auth, and erroring clearly if one does but no `auth` block was configured.
- `internal/envexpand/` — shared `${VAR}` expansion used by `config` and `auth`. Expands YAML scalar values only (never comments) and errors, naming every unset variable, rather than passing a literal `${VAR}` through as a credential.
- `internal/report/` — HTML templates + JSON writer for the final report.
- `internal/checks/payloads/` and `internal/checks/patterns/` — attack payload wordlists (strings *sent to* the target, e.g. `payloads/sqli.txt` and the marker templates in `payloads/xss.txt`) and detection regexes (`patterns/secrets.txt`) respectively, both loaded via `go:embed` so they extend without touching check logic. Both live beside the check that embeds them rather than in a shared top-level directory — `go:embed` cannot ascend past the embedding source file's own directory, so there is nowhere else they could live and still be embeddable.
- `internal/attack/` — the `attack` stage. One `Confirmer` per check that has a proof of concept, self-registered via `init()` under `RegisterCheck`'s `CheckName` (same `database/sql`-style pattern as `internal/checks`). `Run` dispatches each `Finding` by `CheckName`; a `Finding` from a check with no registered `Confirmer` (a passive observation like `missing-headers`, which has nothing to "reproduce") passes through unchanged and is reported `skipped`, never silently promoted to `Confirmed: true`. Re-enforces the destructive gate independently of whatever produced `findings.json`, since `attack` is a separate process invocation that cannot assume that decision still holds.
- `configs/` — `config.yaml`: a single commented example covering target, scope, auth, engine tuning and enabled checks. Scope lives inside it under `scope.allowed_hosts` (there is no separate `scope.yaml`; `doc/security-scanner-projeto.md` §6 is the format of record).
- `tools/reqcount/` — a counting reverse proxy, used to measure what a scan actually sends. Not part of the scanner: it exists because the scanner's own output cannot honestly report its own under-reporting, so a stage whose exit criterion is a request count needs an instrument outside it. **Running a scan through it moves the ScopeGuard's guarantee into the `-upstream` flag** (the allowlist then covers the proxy, not the target) — a measurement-only trade, never part of a normal run. See its package doc.
- `cmd/scanner/` — CLI and **composition root**. The only place that picks concrete adapters, and therefore the only place responsible for handing every component the ScopeGuard-enforcing HTTP client.

### Pipeline contract

`scan` → `findings.json` (suspicions, `Confirmed: false`) → `attack` → `confirmed.json` (reproduced via the `CapturedRequest` stored on each `Finding`, using non-destructive PoCs) → `report` → HTML + JSON summary by severity. Each stage's output is a versioned (`schema_version`), git-diffable JSON file — manually reviewable before the next stage runs, and re-runnable on a different machine.

**Every stage file carries a `coverage` block alongside its findings** (`model.Coverage`, schema version 3). It is what separates "looked and found nothing" from "could not look": counts of endpoints and checks run, plus a `model.ExaminedCheck` entry per check that reached a verdict and a `model.Unexamined` entry per route/check pair that was skipped or failed, each with its reason. The three lists close — `len(Examined)` + the check-level entries in `Skipped` + `len(Failed)` == `ChecksRun` — so every scheduled check lands in exactly one of them, and a route that came back clean is **named** rather than inferred from its absence everywhere else. `scan` builds it (check-level skips, plus endpoints the non-destructive gate held back), `attack` carries it forward and adds its own, and `report` renders it — an empty findings list with a non-empty coverage renders as an explicit caveat, never as "No findings". An older `schema_version` is refused rather than read with the missing part empty: a v1 file read as "nothing failed" and a v2 file read as "no check reached a verdict" are both silently false, and both in the direction this block exists to prevent. This is invariant 6's other half: a skipped route that only reaches stderr has not reached the report.

## Non-negotiable invariants

These constraints are the actual point of the project and must never be relaxed without the user explicitly asking:

1. **ScopeGuard is mandatory and centralized in the HTTP client.** No request may be constructed or sent through any other path. A host not in `scope.allowed_hosts` must be rejected before the request leaves the process. Core packages take a `ports.HTTPClient` and cannot verify which adapter they got — so `cmd/scanner` is the only place allowed to construct them, and it must always pass the `httpclient.Client` built around a `ScopeGuard`. Handing any component a bare `*http.Client` silently disables the boundary with no compile or test failure. This includes every hop of an HTTP redirect: `httpclient.New` sets `CheckRedirect` on the `*http.Client` it builds (never on a caller-supplied one in place — see its doc comment) so a `3xx` from an in-scope host cannot carry the scanner to an out-of-scope `Location` by following it automatically, which `net/http.Client.Do` otherwise does internally without ever calling back through `Client.Do`. The boundary is **name-based and exact**: it never resolves a host, so it does not defend against DNS pointing an allowed name elsewhere, and `LOCALHOST:8080` does not match `localhost:8080`. That second one always fails closed — the scan cannot reach its own target, never somebody else's. It is built for the operator's honest mistake (a stale `base_url`, a copied config, a redirect off the lab host), not for an adversary holding the config file or the resolver; `internal/core/scope`'s package doc is the full statement of what it does and does not cover.
2. **Non-destructive by default.** `Endpoint.Destructive` (true for DELETE/PUT/PATCH) means the endpoint is skipped unless `engine.test_destructive` (or a per-endpoint opt-in) is explicitly set. Never add a check or attack that mutates/deletes state without that opt-in gate. Baseline collection is stricter still: it only ever sends GET/HEAD/OPTIONS, substituting GET for any unsafe method, because a phase named "collect" must not create or destroy anything.
3. **Rate-limited and worker-pooled.** All active traffic goes through the engine's worker pool + rate limiter — never fire requests in an unbounded loop, even in tests against a fake client, since check code should look the same whether the client is fake or real. **One budget, not one per identity:** `model.Clients` hands a check two clients and both wrap the *same* `rate.Limiter`, because what the limit protects is the target's experience and the target does not care which credentials a request carried. `engine.NewRateLimitedClients` is the one way to build the pair, so a caller cannot assemble them with two limiters by accident.
4. **Baseline comparison before flagging.** The engine collects one baseline response per endpoint up front and hands it to every check as `Target.Baseline`. Boolean/response-diff-based checks (e.g. SQLi) must compare against it, not against a hardcoded expectation, to avoid false positives from dynamic content (timestamps, CSRF tokens). `Target.Baseline` is nil when collection failed (`BaselineErr` says why) — a check that needs it must then return no findings, never treat the absence as evidence.
5. **Passive checks never touch the network (on either identity), and are only shown a baseline that is the route's own response.** A `KindPassive` check works from `Target.Baseline` alone; the engine enforces this by handing it a `model.Clients` whose `Default` **and** `Anonymous` both refuse every request (`ErrPassiveCheckRequest`). It also refuses to run one at all when collection had to substitute a safe method (`substitutedMethod` in `runJob`): what came back is then some other handler's answer — on a strict-routing server, the target's 405 page — and judging it files the wrong response under this route's name, once per passive check per route, so one error page arrives as a stack of duplicate findings. The route becomes a `Skipped` with that reason instead. Active checks are unaffected: they send their own requests with the endpoint's own method and read only `Baseline.URL`. A real fix — an OPTIONS probe — waits on the probe set. This is what keeps request count proportional to the spec instead of the spec times the number of enabled checks. `Target.Baseline` is shared by pointer across the checks running concurrently on one endpoint — it is **read-only**; mutating its `Headers` map or `Body` is a data race that also corrupts what the other checks compare against.
6. **Auth failure is `skipped`, not `vulnerable`.** Re-auth once on 401; if it still fails, the route must not produce a finding. A check that cannot conclude — no baseline, failed auth — returns `model.Skippedf(...)`, and the engine records `Result.Skipped` with the reason. **A skip and a finding are not alternatives:** a check that examined three parameters and could not reach a fourth returns both, and `Result` carries both — dropping the findings loses a real vulnerability, dropping the skip lets a partly-examined route read as a whole one. Active checks get this right by sweeping through `runPerParameter`/`outcome` in `internal/checks/probe.go` rather than tracking it each for themselves; format the cause with `%w` so `errors.Is` can still reach it. Skipped routes must reach the report: showing a route as clean when it was never examined is worse than admitting it could not be looked at.
7. **Secrets only via env** (e.g. `${LAB_PASSWORD}` in `config.yaml`) — never commit credentials into config or test fixtures. An unset variable is a hard error naming it, never a silent pass-through of the literal `${VAR}`.
8. **Deterministic identity, descriptive evidence.** Each stage's JSON is committed, reviewed by hand and compared between runs, which needs two different guarantees rather than one. **A finding's identity is deterministic:** `Finding.ID` derives only from the check, the endpoint and a discriminator computed from stable input — never from anything measured at the target. That is what `scanner diff` compares, so a re-scan of an unchanged target must yield the same set of ids or every run reads as a wave of fixes and regressions. **Evidence is descriptive, not comparable:** body snippets, noise floors and byte differences are what a human reads to judge a finding, and they move with the target — by design. Byte-identical output therefore holds against a static target only (`TestScan_IsReproducible`); `TestScan_AgainstADynamicTargetIdentityIsStableEvidenceIsNot` covers the real case, with a control that fails if the test target stops being dynamic. Never let Go's randomized map iteration reach the output: sort before emitting (see `resolveSecurity` and `sortedPaths` in `internal/adapters/openapi`). Wall-clock stays banned from findings — leave `Evidence.ResponseTime` zero unless the finding is *about* timing — because that varies without anything at the target having changed, which is a different thing from evidence that moves because the target did. A discriminator must be derived from **content**, never from position: `exposed-secrets` keys its id on a short digest of the matched value (see `findingDiscriminator`), because numbering matches by output position renamed every later one whenever an earlier was fixed.

## Testing approach

- Unit tests for checks run against a fake `HTTPClient` fed from `testdata/` — no real network.
- A dedicated baseline test proves dynamic content doesn't cause false positives.
- A dedicated `ScopeGuard` test proves an out-of-allowlist host is blocked.
- `cmd/scanner/pipeline_test.go` assembles the whole stack against an `httptest.Server`: it is the only place that proves ScopeGuard, auth, rate limiter, collection and a real check fit together. Add to it when a new layer lands.
- Integration tests against a real (vulnerable, lab-only) API via Docker Compose are optional. `lab/` is that API — a deliberately vulnerable Go service (own `go.mod`, untouched by the scanner's own `go build ./...`) behind a real Postgres, brought up with `docker-compose.yml` at the repo root. See README.md's "Lab" section for the walkthrough; it is a target to scan by hand, not part of `go test ./...`.

## Implementation order

Checks are built in this order (see `doc/security-scanner-projeto.md` §7 for rationale): missing security headers (passive, **done** — `internal/checks/headers.go`) → exposed secrets (passive, **done** — `internal/checks/secrets.go`) → SQLi boolean-based (active, **done** — `internal/checks/sqli.go`) → XSS reflected (active, **done** — `internal/checks/xss.go`) → IDOR / weak JWT (phase 2, require richer models). The two active checks share one request path (`sendProbe` in `internal/checks/probe.go`); a new active check should reuse it rather than re-implement probing.

`scanner report` is implemented (`internal/report/`): reads `confirmed.json`, renders `report.html` via `html/template` (never `text/template` — `Evidence`/`Request` carry attacker-influenced strings that must render as inert text) and `report.json` with the same executive summary and severity-first ordering. Remediation copy lives in a `CheckName`-keyed lookup inside the `report` package, not on `model.Finding` — it is presentation text, not part of the versioned pipeline schema. Unlike `scan`/`attack`, `report` never touches the network.

Two rules any secret-adjacent check must keep: **redact the value** in `Evidence` (findings.json is committed, so writing the secret there relocates the leak rather than reporting it), and put anything regex-shaped behind a placeholder filter — a check that flags `"password": "changeme"` in example docs is one people learn to ignore.

`sqli-boolean` is the first active check and sets the pattern any check that injects its own requests should follow: measure the endpoint's own noise (repeat a benign request `sqliNoiseSamples` times, same value every time) *before* comparing anything, and only flag a difference that clears that noise floor — never a fixed threshold, since what counts as "noise" is a property of the target, not a constant. It does not read `Target.Baseline`'s body (that baseline has no parameters filled in, so it cannot answer "does changing this parameter change the response"); it reuses only `Target.Baseline.URL` for the target's scheme and host, since nothing else in the `Check` contract carries that.

**A rejected probe is not a result.** Before comparing anything, an active check must confirm the target actually processed its benign value: if the filler itself comes back 4xx/5xx, the payload would be refused the same way and the comparison is between two error pages. Against a real API this is the common case, not the edge one — a parameter declared as an enum or an integer answers 400 to `1` exactly as it answers 400 to an injection. Return `notExercisedf(...)` (see `internal/checks/probe.go`), which `runPerParameter` records as untested so it reaches the coverage block. The distinction the rule turns on: a benign value that **succeeds** while the payload is refused is the opposite outcome — that is validation working, and the parameter *was* exercised. The same applies when no probe could be sent at all: reaching the end of the payload loop having sent none means nothing was tried, which is not the same as trying everything and finding nothing.

**A check is handed identities, not a client.** `Run` receives a `model.Clients` with `Default` (authenticated when the config has an auth block, plain otherwise) and `Anonymous` (never any credentials). Use `Default` for everything that is not specifically about identity — reaching for `Anonymous` by habit means scanning a protected route unauthenticated and reporting whatever the login wall says, which is the misattribution invariant 5 exists to stop. `Anonymous` exists for the questions only it can ask: `auth-required` (is a route the spec calls protected actually protected?) and `idor`. Confirmers in `internal/attack` receive the same pair, for the same reason.

A new check is one file in `internal/checks/`: implement `model.Check`, call `RegisterCheck` from `init()`, and add its name to `checks.enabled`. Return `model.Skippedf(...)` rather than guessing when the baseline is missing, and set only `Finding.ID` (as a discriminator) plus `Evidence` — the engine fills in the rest.

## Global tooling, and where it helps here

**Graphify checks invariant 1, which nothing else can.** ScopeGuard is
centralized in the HTTP client, and the CLAUDE.md above says the failure mode
out loud: handing a component a bare `*http.Client` "silently disables the
boundary with no compile or test failure". A defect with no compile error and
no failing test is exactly what a reachability query finds:

```bash
graphify query "http.Client construction httpclient New ScopeGuard"
# Today: ports.HTTPClient, the httpclient adapter, ScopeGuard, and
# runScan()/runAttack() in cmd/scanner/main.go -- the composition root, which
# is the only place allowed to construct one. A core package appearing in that
# answer is the violation.

graphify affected "ScopeGuard"     # everything the boundary reaches
```

The graph is 710 nodes, 2094 edges, **11% `INFERRED`** — the highest ratio in
the ecosystem, so verify before concluding. Rebuild with `graphify update .`
after edits.

**`/security-review` and `claude-security` need a caveat here.** This repository
*is* attack code, deliberately, and `lab/` is a deliberately vulnerable service.
A scanner run over either will produce findings that are the point of the file
rather than defects in it. Reviewing this codebase means asking whether the
scanner's own boundaries hold — scope, non-destructiveness, rate limiting,
secrets from env — not whether it contains attack strings. It does. That is what
it is for.

**Superpowers' `systematic-debugging`** fits the failure this project actually
produces: a check that reports a finding it cannot justify. Invariant 4 says
compare against the baseline, invariant 6 says an inconclusive check returns
`Skipped` — and a false positive is the two of those interacting, which is not
something to guess at.

**`/impeccable`, the animation skills and Playwright do not apply.** This is a
CLI with no interface. The equivalent of an end-to-end check here is
`cmd/scanner/pipeline_test.go`, which is the only place proving ScopeGuard,
auth, the rate limiter, collection and a real check fit together.
