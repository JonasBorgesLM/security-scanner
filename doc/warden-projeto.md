# Security Scanner — Project, Architecture and Implementation Plan

A Go study tool for discovering vulnerabilities, confirming them via controlled attacks, and generating a final report. Exclusive target: your own lab API (a controlled environment).

---

## 1. Scope and principles

- **Restricted to your own/authorised environment.** The `ScopeGuard` (host allowlist) is mandatory and centralized in the HTTP client — no request leaves without passing through it.
- **Non-destructive by default.** Only safe methods are tested (`GET`, test `POST`); `DELETE`/`PUT`/`PATCH` require explicit opt-in per endpoint.
- **Gentle by design.** A worker pool + rate limiter avoid self-DoS even against your own lab.
- **Auditable.** Each stage writes versioned JSON. A finding's **identity** is deterministic — it is what two scans are compared by; its **evidence** is descriptive and moves with the target. Byte-identical output only holds against a static target (see `doc/warden-evolucao.md` §4.3).

---

## 2. Flow (separate subcommands)

```
warden scan   --spec openapi.yaml --config config.yaml --out findings.json
warden attack --in findings.json  --config config.yaml --out confirmed.json
warden report --in confirmed.json --out report.html [--json report.json] [--sarif report.sarif]
warden diff   before.json after.json [--fail-on high]
```

- **scan** — imports routes from the OpenAPI spec, authenticates, runs checks (passive + active suspicions), writes `findings.json` (`Confirmed: false`). **Done.**
- **attack** — reproduces each suspicion with a non-destructive proof of concept, writes `confirmed.json`. **Done** — `internal/attack`, §7 below.
- **report** — reads `confirmed.json`, consolidates into HTML (`html/template`) + JSON, plus an optional SARIF file, with an executive summary by severity. **Done** — `internal/report`. Never touches the network: it only reads the input file and renders.
- **diff** — compares two `findings.json`/`confirmed.json` runs by finding identity, not by file bytes, and exits `2` on a regression. **Done** — `internal/diff`; see `doc/warden-evolucao.md` §4.3 and §6 (Stage 4).

Intermediate files are the contract between stages: version-controllable in git, manually reviewable before `attack` runs, and runnable on different machines.

---

## 3. Architecture

**Lightweight hexagonal** (`ports` / `adapters`) so checks can be tested without real network traffic.

```
warden/
├── cmd/warden/main.go             # CLI + composition root: scan | attack | report | diff
├── internal/
│   ├── ports/                     # interfaces: HTTPClient
│   ├── adapters/
│   │   ├── httpclient/            # real client + ScopeGuard middleware
│   │   ├── openapi/               # spec parser → []Endpoint
│   │   └── config/                # config.yaml reading + validation
│   ├── core/
│   │   ├── model/                 # Endpoint, Finding, Evidence, Target, Check
│   │   ├── engine/                # worker pool + rate limiter + orchestration
│   │   ├── auth/                  # automatic login + re-auth on 401
│   │   └── scope/                 # ScopeGuard
│   ├── checks/                    # one file per check, self-registering via init()
│   │   ├── registry.go
│   │   ├── headers.go             # passive
│   │   ├── secrets.go             # passive
│   │   ├── patterns/secrets.txt   # detection regexes, go:embed
│   │   ├── sqli.go                # active
│   │   ├── payloads/sqli.txt      # attack payloads, go:embed
│   │   ├── xss.go                 # active
│   │   └── payloads/xss.txt       # marker templates, go:embed
│   ├── attack/                    # PoC confirmers for the attack stage, same init() pattern
│   │   ├── attack.go              # Confirmer, Register, Run
│   │   ├── sqli.go                # sqli-boolean: re-verifies + extracts via UNION
│   │   └── xss.go                 # xss-reflected: fresh-marker reflection
│   ├── envexpand/                 # shared ${VAR} expansion
│   ├── diff/                      # finding-identity comparison between two runs
│   └── report/                    # HTML templates + JSON/SARIF writer
├── configs/
│   └── config.yaml                # commented example (scope included, no scope.yaml)
└── testdata/                      # fake specs and responses for tests
```

**Composition root.** `cmd/warden` is the only place that chooses concrete adapters.
Packages under `core/` receive a `ports.HTTPClient` and, by construction, cannot
verify which implementation they got — so the guarantee that everyone received the
client with `ScopeGuard` lives there, and only there. Handing a raw `*http.Client` to
any component would turn off the security boundary without breaking either a build or
a test.

### Key decisions (validated)

| Decision | Choice | Reason |
|---|---|---|
| Organisation | Lightweight hexagonal | Deterministic testability without a network |
| Concurrency | Worker pool + `x/time/rate` | Avoids self-DoS; the pattern real scanners use |
| Extensibility | Registry via `init()` + metadata | Idiomatic (like `database/sql` drivers) |
| Stages | Versioned JSON files (`schema_version`) | Auditability and Unix-style composition |
| Security | `ScopeGuard` as a central middleware | Security by design, not by convention |
| Storage | JSON on disk | YAGNI — no DB for now |
| Payloads | `go:embed` of files | Extends without recompiling the logic |

---

## 4. Data model

```go
type Endpoint struct {
    Method         string
    Path           string
    Parameters     []Parameter
    RequiresAuth   bool
    SecurityScheme string
    Destructive    bool   // DELETE/PUT/PATCH → skipped without opt-in
}

type CheckMetadata struct {
    Name          string
    OWASPCategory string
    Severity      string
    Kind          string              // KindPassive | KindActive
    RequiresAuth  bool
    AppliesTo     func(Endpoint) bool
}

// Response is the response captured during initial collection, read fully into
// memory so several checks can inspect the same one without redoing the request.
type Response struct {
    URL          string      // baseline origin (scheme/host for active checks)
    StatusCode   int
    Headers      http.Header
    Body         []byte
    ProbedMethod string      // the method actually used (GET replaces unsafe methods)
}

// Target is what a check points at: the endpoint plus its collected baseline.
type Target struct {
    Endpoint    Endpoint
    Baseline    *Response   // nil if collection failed
    BaselineErr error
}

type Check interface {
    Metadata() CheckMetadata
    Run(ctx context.Context, t Target, c ports.HTTPClient) ([]Finding, error)
}

type Finding struct {
    ID            string
    CheckName     string
    Endpoint      Endpoint
    Severity      string
    OWASPCategory string
    Request       CapturedRequest   // the FULL request, so attack can reproduce it
    Evidence      Evidence
    Confirmed     bool
}

// Unexamined is the opposite of a Finding: the absence of information about a
// route. Deliberately a separate type — mixing it in among findings would make
// "I looked and found nothing" and "I could not look" collapse back into the
// same shape, which is exactly what it exists to prevent.
type Unexamined struct {
    Check  string   // empty when the decision precedes any check
    Method string
    Path   string
    Reason string
}

// ExaminedCheck is a check that ran against a route and reached a verdict —
// whether or not it produced a finding. It carries no reason, and that is the
// whole difference from Unexamined: a gap has to explain itself, a completed
// check has nothing to explain.
type ExaminedCheck struct {
    Check  string
    Method string
    Path   string
}

// Coverage accounts for what the stage actually managed to examine.
// Without it, a scan that reached nothing and a scan of a clean target
// produce the same file — an empty findings list — and every downstream
// decision errs the same way.
type Coverage struct {
    EndpointsTotal int
    ChecksRun      int
    Examined       []ExaminedCheck
    Skipped        []Unexamined
    Failed         []Unexamined
}

// The three lists reconcile:
//   len(Examined) + check-level entries in Skipped + len(Failed) == ChecksRun
// Skipped also holds endpoint-level entries (a destructive route, a route
// absent from the target), decided before any check was scheduled — those
// are not check-runs, and are excluded from the sum because they carry no
// check name.

// FindingsFile is the on-disk contract of scan and attack. Coverage travels
// alongside findings, not in a sibling file, so the two cannot diverge and no
// stage receives findings without the accounting of what produced them.
type FindingsFile struct {
    SchemaVersion int        // 3 — v1 had no Coverage, v2 had no Examined; both refused
    Coverage      Coverage
    Findings      []Finding
}

type CapturedRequest struct {
    Method  string
    URL     string
    Headers map[string]string
    Body    string
    InjectedParam string
    Payload       string
}

type Evidence struct {
    BaselineResponse string        // the "clean" response to compare against (anti-false-positive)
    ResponseSnippet  string
    ResponseTime     time.Duration
    StatusCode       int
}
```

---

## 5. Corrections folded into the plan

1. **Payloads via `go:embed`** — not hardcoded; extends without touching logic.
2. **`Kind` passive/active** — the engine never spends a request on a passive check; it receives the initial collection's response plus a client that refuses requests.
3. **Full `CapturedRequest` on the Finding** — `attack` can reproduce the suspicion.
4. **Anti-false-positive baseline** — repeats a clean request to measure noise (timestamp, CSRF token) before comparing, in boolean-based SQLi.
5. **`Destructive` flag** — destructive methods skipped by default; explicit opt-in.
6. **Secrets via env** — `config.yaml` supports `${LAB_PASSWORD}` so credentials never get committed.
7. **Context + global timeout + graceful shutdown** — `--timeout` and `Ctrl+C` cleanly cancel the pool.
8. **Re-auth on 401** — re-logs in once before marking a failure; routes with a failed login become "skipped", never "vulnerable".

---

## 6. Config

Format implemented in `internal/adapters/config`. The commented example file
lives at `configs/config.yaml` — **there is no separate `scope.yaml`**; scope is the
`scope:` section of this same file.

```yaml
schema_version: 1
target:
  base_url: http://localhost:8080
scope:
  allowed_hosts: ["localhost:8080", "127.0.0.1:8080"]
auth:
  login_endpoint: /login
  method: POST                    # optional, defaults to POST
  credentials:
    username: admin
    password: ${LAB_PASSWORD}     # via env
    username_field: email         # optional, defaults to "username" — the login body's JSON key
  token_path: data.access_token
  token_header: Authorization     # optional, defaults to Authorization
  token_prefix: "Bearer "
engine:
  max_concurrency: 5
  requests_per_second: 10
  timeout: 5m
  test_destructive: false
checks:
  enabled: [missing-headers, exposed-secrets, sqli-boolean, xss-reflected]
```

### Validation rules

`config.Load` accumulates **every** problem and fails once, listing each one —
whoever is fixing the file sees the whole list instead of discovering one error per
run.

| Rule | Reason |
|---|---|
| `schema_version` must be exactly `1` | A future format change fails loudly instead of being silently misread |

> **Note (v2/v3).** The `schema_version` of the stage files (`findings.json`,
> `confirmed.json`) went up to `2` with the `coverage` block, and to `3` with the
> `examined` list. A v1 file is
> **refused**, not read with an empty coverage: a file written before the
> scanner knew how to account for what it failed to examine is
> indistinguishable from one where nothing failed, and reading it as the
> latter silently reintroduces the exact confusion that block exists to end. The
> `config.yaml`'s `schema_version: 1` is a different number, and has not changed.
| `target.base_url` must be an absolute URL | With no host there is nothing to check against the allowlist |
| `scope.allowed_hosts` cannot be empty, and no entry can be blank | It is the security boundary |
| **the `target.base_url` host ∈ `scope.allowed_hosts`** | An incoherent config would make `ScopeGuard` block the target itself; fail at startup instead of on every request |
| the `auth` block is **optional, all-or-nothing**: absent is valid; if any field is set, `login_endpoint`, `token_path`, `credentials.username` and `credentials.password` become required | A public target needs no credentials; but a half-filled block is almost always a mistake (wrong key, forgotten field) |
| `engine.max_concurrency`, `requests_per_second`, `timeout` > 0 | Zero would turn off the pool or the rate limiter |
| `checks.enabled` cannot be empty | A scan with no checks is noise |

`auth.method` and `auth.token_header` are optional (default `POST` and `Authorization`).

If the config **validates** (an absent `auth` block is valid), the question only the
spec can answer remains: does the target *need* auth? That cross-check lives in
`cmd/warden` (`runScan`/`runAttack`), not in `config`: the `Authenticator` is only
built when there is an endpoint with `RequiresAuth`, and if a protected route exists
with no `auth` block configured, the stage fails with a clear message instead of
scanning the route without authentication.

### `${VAR}` expansion

Performed on the **already-parsed YAML's scalar values**, never on raw text —
so a `${LAB_PASSWORD}` quoted inside an explanatory comment stays documentation,
not a reference to resolve. An undefined variable aborts with its name in the
message (`envexpand.MissingVarsError` carries the full list, retrievable via
`errors.As`), instead of sending the literal `${VAR}` to the target as a credential.

### Check registry

Implemented in `internal/checks/registry.go`, following the `database/sql`
driver pattern: each check self-registers in an `init()`, so adding a check means
adding a file — there is no central list to keep in sync.

- **`RegisterCheck(c)`** panics on a nil check, an empty name, an unknown `Kind`
  or a duplicate name. All of these are programming errors in our own code,
  detectable the instant the binary starts — returning an `error` from inside an
  `init()` would give no one a way to handle it.
- **`Enabled(names)`** resolves `checks.enabled` from the config. An unknown name is
  an **error**, listing the available ones — a typo in `config.yaml` would otherwise
  silently disable a check and produce a clean-looking report that simply never ran it.
- **`All()` / `Names()`** return in name order.

The engine **does not** import the registry: it receives an already-resolved
`[]model.Check`. This keeps the engine testable without global state and preserves
the direction of dependencies (`core/` does not depend on `checks/`). The
composition root is what stitches the two together.

### Engine contract

Implemented in `internal/core/engine`:

- **`Collect(ctx, endpoints)`** — the *initial collection*: one request per
  endpoint, parallelised across the pool and bounded by the rate limiter, producing
  `[]Target` with each one's baseline. **Only sends a safe method** (GET/HEAD/OPTIONS):
  an endpoint declared as POST/PUT/PATCH/DELETE is probed with GET, and the
  substitution is recorded in `Response.ProbedMethod`. A phase called "collection"
  cannot create or destroy anything on the target, and the headers passive checks
  look at belong to the route, not the verb. Path parameters (`{id}`) are filled with
  a placeholder; 404, 405 or 400 are still a valid baseline. A destructive endpoint
  **is not collected** without opt-in, so it costs no request at all. A collection
  that fails still returns a `Target`, with `BaselineErr` in place of the response.
  Cancellation returns whatever was already collected **plus an error** — the caller
  cannot mistake a truncated collection for a complete one.
- **`BuildJobs(targets, checks)`** — crosses each target with its applicable checks,
  and reapplies the non-destructive rule (a security invariant guaranteed in exactly
  one place is one refactor away from being guaranteed nowhere). Two filters:
  `AppliesTo`, and `CheckMetadata.RequiresAuth` — a check that only makes sense with a
  session (IDOR and the like) is never paired with a public route. Checks are paired
  in name order, so the job list does not depend on the order the registry handed
  them over in.
- **`Run(ctx, jobs)`** — a worker pool of `max_concurrency` workers consuming from a
  channel. Returns results in job order, regardless of which worker finished first.
- **Rate limiter as a decorator of `ports.HTTPClient`**, not as a gate per job.
  Charging happens per *request*: a passive check that makes no request spends no
  budget; an active check that makes three is charged three times. A single limiter
  is shared by all workers, so concurrency never multiplies the rate.
- **A passive check receives a client that refuses every request**
  (`ErrPassiveCheckRequest`). "Passive never touches the network" holds by
  construction, not by trusting each check. This is what keeps request count
  proportional to the size of the spec, not to the spec times the number of enabled
  checks.
- **Graceful shutdown** — cancelling the `ctx` (global timeout or Ctrl+C) stops the
  dispatch of new jobs, lets the workers finish what they already picked up, and
  returns the partial results together with `ctx.Err()`. The `ctx` also reaches the
  checks, so a request in flight unwinds instead of holding up shutdown behind a
  hung connection.
- **A panicking check becomes an error on the `Result`**, not a crash of the whole
  scan — losing ten minutes of scanning to a bug in one check would be worse than
  reporting it. A panic outside a check (during collection, say) is contained by the
  pool: that item disappears from the result and the phase reports itself incomplete.
- **`Run` stamps what it already knows onto each `Finding`**: `Endpoint`,
  `CheckName`, `Severity`, `OWASPCategory` and a deterministic `ID`. This way no
  check repeats metadata it already declared — and none can forget the `Endpoint`,
  which is exactly what the `attack` stage needs to reproduce it.
- **A check that cannot conclude returns `model.Skippedf(...)`** and becomes a
  `Result.Skipped` with the reason, never a finding and never an error. A route shown
  as clean without having been examined is worse than a route admittedly not
  examined.
- A check's error is recorded on that job's `Result.Err`; `Run` only returns an
  error when some job failed to run at all.

The `Authenticator`'s login/re-auth sits *below* the limiter and is therefore not
rate-limited by it — a deliberate decision: logins are rare and already collapsed
into a single in-flight one by the `Authenticator` itself.

### Authentication contract

Implemented in `internal/core/auth`:

- Login against `login_endpoint`, token extracted by `token_path` (dot notation over
  JSON objects; no array indexing) and injected into `token_header` with
  `token_prefix`.
- **Re-auth on 401, exactly once.** If the retry still returns 401, that 401
  response is passed through as a valid response — it is up to the checks layer to
  mark the route as `skipped`, never as "vulnerable".
- If the re-login itself fails, the error wraps `auth.ErrReAuthFailed` (testable
  with `errors.Is`), distinguishing "auth is broken" from "the route genuinely isn't
  authorised".
- Concurrent 401s from the worker pool collapse into a **single** re-login
  (generation counter + mutex), rather than one login per in-flight request.
- Requests with a body must be re-executable (`GetBody`), or the retry after
  re-auth is rejected with an explicit error instead of resending an empty body.

---

## 7. Implementation order (test cases)

| Order | Check | Kind | Why |
|---|---|---|---|
| 1 | Missing headers | passive | **Done** — `internal/checks/headers.go`. Zero ambiguity; exercises the whole pipeline |
| 2 | Exposed secrets | passive | **Done** — `internal/checks/secrets.go`. Pattern matching only; no attack |
| 3 | SQLi boolean-based | active | **Done** — `internal/checks/sqli.go`. First real attack; exercises noise measurement |
| 4 | Reflected XSS | active | **Done** — `internal/checks/xss.go`. Injects a marker, verifies unescaped reflection |
| (5) | IDOR | active | Requires a user↔resource relationship (phase 2) |
| (6) | Weak JWT (`alg:none`) | active | Signature validation (phase 2) |

---

### The `sqli-boolean` contract

Implemented in `internal/checks/sqli.go` — the first active check, and the first
that does not read `Target.Baseline`'s body.

- **Payloads in `true`/`false` pairs**, embedded from
  `internal/checks/payloads/sqli.txt` via `go:embed` (format
  `name ||| true-payload ||| false-payload`, one per line). A malformed file
  panics in `init()` — it is our own data, embedded in the binary, so it's a build
  error, not a runtime condition.
- **`AppliesTo`** restricts jobs to endpoints with at least one `query` or `path`
  parameter — header and body are out of scope for now (body would need to know
  the payload's format, not just a string to substitute).
- **Noise measurement BEFORE injecting**: repeats a benign request (fixed value
  `"1"`, same parameter, same endpoint) `sqliNoiseSamples` (3) times and uses the
  largest body-size difference across those repetitions as the noise floor —
  this measures the variation from dynamic content (timestamp, nonce, CSRF token)
  that has nothing to do with the injected parameter.
- **Only flags a suspicion if `diff(true, false) > noise`**, never a fixed
  threshold — "noise" is a property of the target, not a constant in the code.
  The endpoint's other parameters are filled with the same benign value during the
  test, so an empty required parameter cannot confound the result.
- **Never reads `Target.Baseline` as content** — that baseline was collected with
  no parameter filled in, so it cannot answer "does changing this parameter change
  the response?". It reuses only `Target.Baseline.URL` to learn the target's
  scheme/host, since nothing else in the `Check` contract carries that. With no
  baseline (collection failed), the check returns `Skippedf` — there is no way to
  know where to send the request.
- **Full `CapturedRequest`**: `Method`, `URL` (already encoding the true payload,
  ready to reproduce with `curl` or via the `attack` stage), `InjectedParam`,
  `Payload`.

---

### The `attack` contract

Implemented in `internal/attack` — reads `findings.json`, tries to confirm each
unconfirmed `Finding`, writes `confirmed.json`. It is a **separate** process from
`scan`: it inherits no session, no state, and authenticates from scratch against the
same `config.yaml`.

- **Registry by `CheckName`**, the same `init()` + `RegisterCheck` pattern as
  `internal/checks`: each check with a PoC implements `attack.Confirmer` (method
  `CheckName() string` + `Confirm(ctx, Finding, HTTPClient) (Finding, error)`) and
  registers via `attack.Register`. `attack.Run` dispatches each finding by name;
  with no registered confirmer for that `CheckName`, the finding passes through
  **unchanged** to `confirmed.json`, listed as `skipped` — never promoted to
  `Confirmed: true` without real verification. `missing-headers` and
  `exposed-secrets` fall into that case today: they are direct observations of a
  single already-collected response, with nothing to "reproduce".
- **The `Destructive` gate is reapplied**, independent of whatever `scan` already
  decided — `attack` is a separate process invocation and cannot assume that
  decision still holds.
- **`sqli-boolean`**: two steps.
  1. Re-verifies the SAME true/false comparison the check made, measuring noise
     again now (it does not trust what `scan` measured earlier — the target may have
     changed). This reproduction alone is enough for `Confirmed: true`.
  2. Only then does it try to extract **the database name via `UNION SELECT`** —
     a pure read, never a write. It discovers the column count by testing 1 through
     `sqliMaxColumns` (6), wrapping a constant in `CONCAT('ATTACKPOC_','OK','_ENDPOC')`
     in the last column — finding the marker in the response proves the right
     column count, that `CONCAT` works on this engine, and that the last column
     surfaces in the response, all in a single request. Once the count is found, it
     tries candidates (`database()`, `current_database()`, `DB_NAME()`,
     `sqlite_version()`) in the same position. **Best-effort**: if the extraction
     fails (unknown engine), the finding stays confirmed by the boolean reproduction
     — only the evidence note changes to say extraction didn't work.
  3. `FalsePayloadFor` (exported from `internal/checks/sqli.go`) reconstructs the
     false payload paired with the `Finding`'s true one, reusing the SAME
     `payloads/sqli.txt` — a single source of truth, no duplicated parser.
- **`xss-reflected`**: resends with a **fresh, newly generated** marker
  (`crypto/rand`, not the scan's original payload) — avoids caching and
  distinguishes "reflected unescaped" (confirmed) from "reflected but escaped"
  (not confirmed, but stated explicitly — not the same as "did not reflect").
- **`withInjectedValue`** rewrites the captured URL, swapping only the injected
  parameter's value, without needing the endpoint's parameter list — works for
  query (via `net/url`) and for path (a substring match against the *decoded* form
  of `u.Path`; comparing against the escaped form was a real bug this package's own
  tests found — `url.URL` stores the decoded path and only uses `RawPath` when it
  matches the current `Path`).
- **Probes with the endpoint's real method, never forces GET.** Follows the
  principle already stated in §1 ("only safe methods are tested: GET, test POST")
  — DELETE/PUT/PATCH never reach this check (the engine's non-destructive gate
  already filters `Destructive` before any job exists); POST stays in scope on
  purpose. Deliberate tradeoff: a POST endpoint that turns out not vulnerable
  still absorbs up to `sqliNoiseSamples + 2×pairs` requests per parameter before
  being dismissed — if that route creates a resource on every call, it leaves
  behind real (modest, rate-limited) test data in the lab. Forcing GET would avoid
  this, but a server that routes strictly by method would answer 404 to every
  probe, and the check would "clean" a route it never actually exercised — a worse
  way to fail than a few extra rows in the operator's own lab database.

---

### The `report` contract

Implemented in `internal/report` — reads `confirmed.json` and writes `report.html`
+ `report.json`. It is the only stage that never touches the network: nothing here
builds or sends a request, so it needs no `ScopeGuard`, no HTTP client, and no
authentication.

- **`html/template`, never `text/template`.** `Evidence` and `Request` carry text
  potentially influenced by whoever was attacked — an SQLi payload, a reflected XSS
  marker, a raw response snippet. `html/template` escapes by context automatically;
  rendering this with `text/template` would turn the report itself into an XSS sink
  when opened in a browser. `TestWriteHTML_EscapesAttackerControlledContent` proves
  this by injecting a real `<script>` into a sample finding and checking that it
  comes out as `&lt;script&gt;`, never as an executable tag.
- **Template embedded via `go:embed`** (`internal/report/template.html`), the same
  pattern as `patterns/secrets.txt` and `payloads/sqli.txt`: it lives beside the
  package that uses it, parsed once in `init()` — a malformed template is a build
  error, not a runtime condition.
- **Deterministic ordering**: `Build` sorts by severity (critical → high → medium →
  low → unknown), then confirmed before unconfirmed, then by `CheckName`,
  `Endpoint.Path` and `ID` as a tiebreaker — never by the order `scan` discovered
  them in. This holds for both the HTML and `report.json`, so the two files show
  findings in the same order and `report.json` comes out byte-identical across two
  runs over the same `confirmed.json`, preserving the pipeline's determinism
  invariant.
- **Executive summary** counts findings by severity and, within each severity, how
  many have already been confirmed by a PoC — the distinction matters: a confirmed
  `high` weighs far more than a `high` that's still only a suspicion.
- **Remediation copy lives only in the `report` package** (a `CheckName` → text
  map), not on `model.Finding`: it is presentation content, not part of the
  versioned JSON schema `scan` and `attack` populate. A check with no entry in the
  map gets a generic fallback text instead of being left blank.
- **`--json` is optional**: by default it derives from `--out` by swapping the
  extension (`report.html` → `report.json`), but it accepts an explicit path.

---

## 8. Tests

- **Unit** — each check against a fake `HTTPClient` with responses from `testdata/`; no network.
- **Baseline** — a dedicated test proving dynamic content does not turn into a false positive.
- **ScopeGuard** — a dedicated test proving a host outside the allowlist is blocked (the scanner's own security).
- **Integration** — optional, against the lab's vulnerable API via Docker Compose:
  `lab/` (its own Go module) + a real Postgres, brought up by `docker-compose.yml`
  at the repo root. Covers this project's four classes — boolean-based SQLi with
  real extraction via `UNION SELECT`, exposed secrets, missing headers, and
  reflected XSS (`scan` discovers it via `internal/checks/xss.go`, `attack`
  confirms it with its own marker via `internal/attack/xss.go`).
  `GET /items/{id}` is deliberately parametrized — a negative control to notice a
  false positive. Not part of `go test ./...`; it's a target for running the
  `scan → attack → report` cycle by hand. See README.md's Lab section.
