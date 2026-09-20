# security-scanner

A Go CLI security scanner: discovers vulnerabilities in a live API, confirms
them with controlled proof-of-concept attacks, and produces a report — built
as a study project against the author's own lab API.

[![CI](https://github.com/JonasBorgesLM/security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/JonasBorgesLM/security-scanner/actions/workflows/ci.yml)

---

## ⚠️ Scope of use

**Use this tool exclusively against infrastructure you own or are formally
authorized to test.**

Scanning third-party systems without written authorization is illegal in most
jurisdictions. This project was built for the author's own lab API in a
controlled environment, and nothing here changes that responsibility: whoever
runs the tool answers for the target they chose.

The tool enforces this technically, not just by convention:

- **`scope.allowed_hosts`** in `config.yaml` is a mandatory allowlist. Every
  request passes through the `ScopeGuard` inside the project's single HTTP
  client; a host outside the list is rejected **before the connection ever
  opens** — including every hop of an HTTP redirect, not just the initial
  request (a malicious or misconfigured target cannot use a `3xx` to steer
  the scanner to another host).
- The scanner **refuses to start** if `target.base_url`'s host is not in the
  allowlist — an incoherent configuration fails early, with an explicit
  message.
- **Non-destructive by default:** `DELETE`/`PUT`/`PATCH` endpoints are
  skipped unless `engine.test_destructive: true` is set explicitly.
- **Collection only ever uses safe methods.** An endpoint declared as `POST`
  is probed with `GET` — the phase that builds the baseline never creates or
  destroys anything on the target.
- **Gentle by design:** a worker pool and rate limiter keep the scanner from
  taking its own target down.

---

## Contents

- [Requirements](#requirements)
- [Build](#build)
- [Configuration](#configuration)
- [Environment variables](#environment-variables)
- [Usage](#usage)
- [Checks](#checks)
- [Confirming a finding: the `attack` stage](#confirming-a-finding-the-attack-stage)
- [Lab](#lab)
- [Architecture](#architecture)
- [Testing](#testing)
- [License](#license)

---

## Requirements

- Go 1.25 or later (see `go.mod`). The floor is set by the dependencies
  (`kin-openapi`, `golang.org/x/time`), not by the scanner's own code.

`go.mod` also pins an exact `toolchain` version, one patch release ahead of
the `go` directive's minimum, for a reason worth knowing before it costs you
a debugging session: **`golangci-lint` and `govulncheck` are compiled against
a specific Go version and fail with `export data version N is greater than
maximum supported version M` when the local Go is newer** — the errors
surface inside the standard library and look nothing like this repository,
which reads as "lint is broken here" rather than what it is. Prefixing the
command with the pinned version fixes it:

```bash
GOTOOLCHAIN=go1.25.14 golangci-lint run ./...
GOTOOLCHAIN=go1.25.14 go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
```

CI already runs with the right toolchain; this only matters for a local Go
newer than the pin.

## Build

```bash
go build -o scanner ./cmd/scanner
```

## Configuration

Copy the annotated example and adjust it for your lab:

```bash
cp configs/config.yaml my-lab.yaml
```

Required fields (the tool validates all of them and reports **every** one
that is missing at once, not one failure per run):

| Field | Description |
|---|---|
| `schema_version` | Must be `1` |
| `target.base_url` | Absolute URL of the API under test |
| `scope.allowed_hosts` | Allowlist of `host:port`; must include the target's own host |
| `engine.max_concurrency` | Worker pool size (> 0) |
| `engine.requests_per_second` | Rate limit (> 0) |
| `engine.timeout` | Global run deadline, e.g. `5m` |
| `checks.enabled` | List of checks to run |

Optional under `engine`: `burst` (requests allowed before the sustained rate
applies, default 1), `request_timeout` (per-request limit, default 30s —
without it, one hung route can pin a worker until the global deadline fires)
and `test_creates` (lets active checks send a request body, which starts
**creating resources** on POST routes; off by default, and kept separate
from `test_destructive` because creating is recoverable and deleting is
not).

The **`auth` block is optional**: a target whose spec declares no protected
routes can be scanned with no `auth` section at all. When present, it is
**all-or-nothing** — if any auth field is set, the full set is required
(`login_endpoint`, `token_path`, `credentials.username`,
`credentials.password`), because a half-filled block is almost always a
mistake (a typo'd key, a forgotten field). If the spec has protected routes
but the config carries no `auth` block, `scan`/`attack` fails with a clear
message instead of scanning the routes unauthenticated.

| Field (`auth`, optional) | Description |
|---|---|
| `auth.login_endpoint` | Login route, resolved against `base_url` |
| `auth.credentials.username` / `password` | Lab credentials |
| `auth.credentials.username_field` | Optional, default `"username"` — the JSON key `username` is sent under in the login body (e.g. `email`, for a target that logs in by email) |
| `auth.token_path` | Dot-notation path to the token in the JSON response |
| `auth.token_header` / `token_prefix` | Header and prefix the token is injected under (default `Authorization` / `"Bearer "`) |
| `auth.extra_headers` | Optional, login request only — for an endpoint that requires a header to merely be *present* (a CSRF defense), independent of its value |
| `auth.secondary_credentials` | Optional; a second account for `idor`. Same login endpoint and token handling, only the credentials differ. Without it, `idor` skips |

### Environment variables

Secrets **never** go in the configuration file. Write them as `${VAR}` and
export them before running — expansion happens on the parsed YAML values
(comments are left alone), and an unset variable aborts the run naming it,
instead of sending the literal `${VAR}` to the target as a password.

| Variable | Used in | Description |
|---|---|---|
| `LAB_PASSWORD` | `auth.credentials.password` in the example `configs/config.yaml` | Password of the lab's test user |

```bash
export LAB_PASSWORD='your-lab-password'
```

Any `${OTHER_VAR}` you add to your own config becomes required the same way.

---

## Usage

The pipeline is four subcommands chained by versioned JSON files. Each
intermediate file is the contract between stages: git-diffable, reviewable
by hand before `attack` runs, and re-runnable on a different machine.

```bash
scanner scan   --spec openapi.yaml --config config.yaml --out findings.json
scanner attack --in findings.json  --config config.yaml --out confirmed.json
scanner report --in confirmed.json --out report.html [--json report.json] [--sarif report.sarif]
scanner diff   before.json after.json [--fail-on high]     # exit 2 = regressed
```

- **`scan`** — imports routes from the OpenAPI spec, authenticates against
  the target, runs the enabled checks, and writes `findings.json`
  (suspicions, `confirmed: false`) with a **coverage** block that accounts
  for every route examined, skipped, or failed — so an empty findings list
  can never be mistaken for a clean target.
- **`attack`** — reproduces each suspicion with a non-destructive proof of
  concept and writes `confirmed.json`, carrying scan's coverage forward
  unchanged.
- **`report`** — reads `confirmed.json` and writes `report.html` +
  `report.json`, and with `--sarif`, a SARIF 2.1.0 file GitHub Code Scanning
  reads natively. An executive summary by severity up top, then per finding
  the check, endpoint, OWASP category, evidence, and a remediation note; and
  coverage tables (examined / not examined).
- **`diff`** — compares two stage files and reports `+new`, `-resolved`,
  `? not examined`, and lost coverage. A finding that disappeared is only
  "resolved" when the newer run actually reached a verdict on that route —
  otherwise it vanishes along with the information, not the problem. Exits
  with code 2 when something got worse. See
  [`doc/ci-gate.md`](doc/ci-gate.md) for wiring this into CI.

Example `scan` run:

```console
$ export LAB_PASSWORD='...'
$ scanner scan --spec openapi.yaml --config configs/config.yaml
target:     http://localhost:8080
scope:      [localhost:8080 127.0.0.1:8080]
spec:       openapi.yaml
endpoints:  6 (5 require auth, 2 destructive)
checks:     exposed-secrets, missing-headers, sqli-boolean, xss-reflected
            2 destructive endpoint(s) will be skipped (engine.test_destructive is false)

wrote findings.json (17 findings, 0 skipped, 0 failed)
```

Endpoints that could not be examined show up as `skipped`, with the reason —
never as "clean".

---

## Checks

Twelve checks, up from the four this project started with. Full rationale
for each — including the audit that found the ones worth adding and the
live measurements behind their design — is in
[`doc/security-scanner-evolucao.md`](doc/security-scanner-evolucao.md).

| Check | Kind | What it reports | OWASP |
|---|---|---|---|
| `missing-headers` | passive | Missing security headers; severity downgraded to `low` on a response that is not a document (JSON), where CSP/X-Frame have nothing to restrict. | A05 |
| `exposed-secrets` | passive | Credentials in the body, including inside HTML/JS comments. The value is **redacted** in the report; the finding's ID discriminator is a digest of the value, never its position. | A02 |
| `cache-on-authenticated` | passive | An authenticated route's response that a cache is allowed to keep (`public`, or missing `no-store`). Only judges a 2xx — an error page is not the route's own response. | A05 |
| `cors-misconfigured` | passive¹ | A CORS policy that reflects an arbitrary origin. **The absence of CORS is the secure state** — inverted logic relative to `missing-headers`. | A05 |
| `dangerous-http-methods` | active | TRACE enabled, proven by echo. `low`: Cross-Site Tracing has not been reachable from a browser for years; what remains is information disclosure. | A05 |
| `sqli-boolean` | active | Boolean-based SQLi: compares the injected response against the endpoint's own measured noise. | A03 |
| `xss-reflected` | active | Reflected XSS: a deterministic marker that only counts if it comes back raw **and** is absent from the baseline. | A03 |
| `auth-required` | active | A route the spec declares protected answers 2xx **without** credentials. The oracle is the status code, so it concludes where injection checks cannot. `critical`. | A01 |
| `idor` | active | One user's resource read with another user's session. Needs `auth.secondary_credentials`; without it, skips naming the missing config. | A01 |
| `jwt-weak` | active | `alg:none` accepted (`critical`, with a PoC) and a missing/overlong `exp` (`low`, structural). Skips when the session token is not a JWT. | A02 |
| `verbose-errors` | active | Malformed input that leaks a stack trace, raw SQL, or a filesystem path — absent from the baseline. | A05 |
| `open-redirect` | active | A redirect-shaped parameter that accepts an external host. Reads the `Location` off the 3xx without following it (the `ScopeGuard` blocks the hop). | A01 |

¹ Active during collection (one probe carrying `Origin:` is sent once per
endpoint); passive in the check itself.

`exposed-secrets`' patterns live in `internal/checks/patterns/secrets.txt`,
embedded via `go:embed` — the list can grow without touching the check's
logic. Each pattern declares `high` or `low` confidence: the generic ones
(`low`) only become a finding after clearing a placeholder filter, so
`"password": "changeme"` in example documentation does not turn into noise.

`sqli-boolean` was the first **active** check: instead of reading the
baseline the engine already collected, it sends its own requests. For each
query/path parameter it measures dynamic-content noise by repeating a
benign request 3 times, injects true/false pairs from
`internal/checks/payloads/sqli.txt` (also via `go:embed`), and only flags a
suspicion if the size difference between the two responses is **larger**
than the noise already observed — the false-positive defense described in
invariant #4. When the OpenAPI spec supplies a real, valid value for a
parameter — an `example`, an enum member, or a synthetic UUID for
`format: uuid` — the check uses that instead of a generic filler, which is
what lets it reach a verdict on a strictly-typed parameter that would
otherwise reject the filler exactly as it rejects an injection payload. Each
finding's `CapturedRequest` carries the exact URL that produced the result,
ready for the `attack` stage (or a plain `curl`) to reproduce.

**Secrets are redacted in the report** (`AKIA****************`, with the
length). A secrets scanner that writes the secret into a committed
`findings.json` has relocated the leak, not found it.

An unknown name in `checks.enabled` aborts the run before any request is
sent — a typo does not silently disable a check.

The `report` uses `html/template` (never `text/template`) on purpose:
`Evidence` and `Request` carry content potentially controlled by whoever was
attacked — an SQLi payload, a reflected XSS marker, a raw response snippet —
and it has to render as inert text on the page, never as executable HTML.
Findings are ordered by severity and then confirmed-before-unconfirmed, not
by scan order, so the reader sees what matters most first. `report.json`
carries the same summary and the same ordering, so the two files are the
same information in two formats, not two different reports. Remediation
text per check lives only in the `report` package (not on `model.Finding`):
it is presentation content, not part of the other two stages' versioned
JSON contract.

---

## Confirming a finding: the `attack` stage

`attack` is a separate run of the binary — it shares nothing with `scan`
beyond the files, and authenticates again from scratch — that reads each
`Finding` in `findings.json` and tries to confirm it with a technique
specific to the check that produced it, via a small registry
(`internal/attack`, the same `init()` pattern as `internal/checks`):

| Check | Confirmation |
|---|---|
| `sqli-boolean` | Measures the endpoint's noise again, now, and only confirms if the true/false difference is still larger than the noise — the target may have changed since `scan`. Once confirmed, it attempts to extract **only the database name** via `UNION SELECT` (never a write: no `DROP`, no `UPDATE`, read-only), trying column counts and a handful of common functions (`database()`, `current_database()`, `DB_NAME()`, `sqlite_version()`). Extraction is best-effort: if it does not work against the target's engine, the finding stays confirmed by the boolean reproduction alone — only the extraction note changes. |
| `xss-reflected` | Resends with a **fresh, unique marker** (not the scan's original payload, so a cached response cannot be mistaken for a live one) and confirms only if it comes back unescaped — an escaped reflection is not exploitable and is reported as such, never as "did not reproduce". |
| `auth-required` | Replays the request with no credentials at all. A 2xx confirms; anything else means the route is not open now — the finding may have been wrong, or the control was added since the scan. |
| `jwt-weak` | Re-forges the `alg:none` token from the current session token's claims (not the one captured at scan time — the proof is that a freshly minted unsigned token is honoured *now*) and confirms if the target still accepts it. The structural `exp` finding has no PoC: it is a fact read off the token, not a suspicion, so `attack` reports it `skipped` — "nothing to reproduce" — rather than leaving it `confirmed: false`, which would read as suspected-and-unproven. |
| `verbose-errors` | Resends both the malformed request and a benign one at the same parameter, and confirms only if the leak appears with the malformed value and not the benign one — proving the malformed input is the cause, not a rerun of the same request. |
| `open-redirect` | Replays the request and reads the `Location` off the 3xx without following it — the `ScopeGuard` is what actually blocks the hop, and the finding is what the target tried to do, not where the scanner ended up. |

A `CheckName` with no registered confirmer (`missing-headers`,
`exposed-secrets`, `cache-on-authenticated`, `cors-misconfigured`,
`dangerous-http-methods`, `idor` — direct observations or comparisons that
have nothing further to "reproduce") passes through to `confirmed.json`
unchanged, listed as `skipped`, never promoted to `confirmed: true` without
real verification.

`Endpoint.Destructive` is honoured again here, independent of whatever
`scan` already decided — `attack` is a separate process and does not assume
another process's decision still holds.

Example:

```console
$ scanner attack --in findings.json --config configs/config.yaml
target:     http://127.0.0.1:8099
findings:   17 (0 destructive)

wrote confirmed.json (1 confirmed, 16 skipped, 0 failed, 0 not confirmed)
  skipped: missing-headers on GET /health: no PoC available for check "missing-headers"
  ...
```

A confirmed `sqli-boolean` finding carries the exact URL that extracted the
data — reproducible with plain `curl`, no scanner needed:

```console
$ curl 'http://127.0.0.1:8099/items?q=%27+UNION+SELECT+CONCAT%28%27ATTACKPOC_%27%2Cdatabase%28%29%2C%27_ENDPOC%27%29--+-'
{"items": [{"id": 1, "name": "ATTACKPOC_labdb_billing_ENDPOC"}]}
```

---

## Lab

`lab/` is a **deliberately vulnerable** Go API behind a real Postgres, only
to give the scanner a target of its own to run the full cycle against —
nothing here should ever run anywhere but your own machine. It is a
separate Go module (`lab/go.mod`); `go build ./...` from the repo root never
touches it.

| Vulnerability | Where | How |
|---|---|---|
| Boolean-based SQLi | `GET /items?q=` | `q` is concatenated unsanitized into a `WHERE name = '<q>'`. Caught by `sqli-boolean`; `attack` reproduces it and extracts the real database name via `UNION SELECT` against Postgres. |
| Exposed secrets | `GET /debug` | An AWS-shaped key (AWS's own public documentation example, not a real credential) and a generic `api_key`. Caught by `exposed-secrets`. |
| Missing headers | every response | No route sets `CSP`/`HSTS`/`X-Frame-Options`/`X-Content-Type-Options`. Caught by `missing-headers`. |
| Reflected XSS | `GET /search?term=` | `term` comes back unescaped inside `<html>`. Caught by `xss-reflected`; `attack` reproduces it with a fresh, independent marker. |

`GET /items/{id}` is deliberately **safe** (a bound parameter, not
concatenated) — a control to notice if the scanner ever produced a false
positive on it. `PUT`/`DELETE /items/{id}` exist only to exercise the
destructive gate (skipped by default, since `configs/config.yaml` ships
`engine.test_destructive: false`).

### Bringing the lab up

```bash
docker compose up -d --build
```

This starts two services: `db` (Postgres, schema and seed data in
`lab/db/init.sql`) and `lab-api` (host port `8080`, only starts once `db` is
healthy). The `admin` user's password already ships with a default
(`lab-pass-only-123`) matching the comment in `configs/config.yaml` — to use
a different one, export `LAB_PASSWORD` **before** bringing compose up (it is
read as an environment variable by `docker compose`, not by the scanner).

```bash
curl http://localhost:8080/health   # {"ok":true}
```

### Running the full cycle against it

`configs/config.yaml` already points at the lab (`localhost:8080`) with
nothing to edit — just export the same password:

```bash
export LAB_PASSWORD='lab-pass-only-123'

scanner scan   --spec lab/openapi.yaml --config configs/config.yaml --out findings.json
scanner attack --in findings.json      --config configs/config.yaml --out confirmed.json
scanner report --in confirmed.json     --out report.html
```

`scan` should find `sqli-boolean` on `/items`, `exposed-secrets` (2×) on
`/debug`, and `missing-headers` on every route a baseline could be
collected for. `attack` should confirm the SQLi suspicion and, against the
real Postgres, extract the database name (`labapi`) via `UNION SELECT` —
check `confirmed.json` rather than taking this README's word for it. Open
`report.html` in a browser for the consolidated result.

### Tearing the lab down

```bash
docker compose down -v   # -v also removes the Postgres volume
```

---

## Architecture

Lightweight hexagonal (ports/adapters), so checks are testable against a
fake `HTTPClient` with no real network.

```
cmd/scanner/          CLI and composition root — the only place that wires adapters
internal/
  ports/               interfaces: HTTPClient
  adapters/
    httpclient/        the real HTTP client; this is where ScopeGuard is applied
    openapi/            OpenAPI 3 spec parser → []Endpoint (also computes Parameter.Sample)
    config/             config.yaml reading and validation
  core/
    model/               Endpoint, Check, Finding, Evidence, Clients
    engine/              baseline + probe collection, worker pool, rate limiter
    auth/                automatic login + re-auth on 401
    scope/               ScopeGuard (host allowlist)
  checks/               one file per check, self-registered via init()
    registry.go          RegisterCheck + checks.enabled resolution
    probe.go             shared active-probe machinery (sendProbe, schema-aware fillers)
    patterns/             secret-detection regexes, via go:embed
    payloads/              sqli payloads and xss marker templates, via go:embed
  attack/                confirmers for the attack stage, same init() pattern
    attack.go             Register + dispatch by CheckName
  diff/                  scanner diff: compares two stage files, coverage-aware
  report/                HTML template (go:embed) + JSON + SARIF writers
  envexpand/             shared ${VAR} expansion
configs/                example config.yaml
tools/reqcount/         counting reverse proxy, used to measure what a scan actually sends
lab/                     study-purpose vulnerable API (separate Go module) + spec + init.sql
docker-compose.yml       brings lab/ up behind a real Postgres — see §Lab above
```

Design details and rationale in
[`doc/security-scanner-projeto.md`](doc/security-scanner-projeto.md) and
[`doc/security-scanner-evolucao.md`](doc/security-scanner-evolucao.md).

---

## Testing

```bash
go test ./...              # all tests
go test ./... -race        # race detector
go test ./... -cover       # coverage
go vet ./...                # static analysis
golangci-lint run ./...     # lint (errcheck, bodyclose, errorlint, staticcheck, …)
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...   # known-vulnerable dependencies
```

If your local Go is newer than the pin in `go.mod`, prefix the last two with
`GOTOOLCHAIN=go1.25.14` — see [Requirements](#requirements) for why.

Tests never touch the outside network: checks run against a fake
`HTTPClient` fed from `testdata/`, and authentication tests use an
`httptest.Server` on loopback. There are dedicated tests for the
`ScopeGuard` (a host outside the allowlist is blocked before it ever becomes
a connection) and for the parser's determinism.

End-to-end tests (`cmd/scanner/pipeline_test.go`) assemble the whole stack —
ScopeGuard, authentication, rate limiter, collection, and a real check —
against an `httptest.Server`, and verify, among other things, that
collection never sends an unsafe method, that a destructive endpoint is
never touched, and that two scans of the same target produce byte-identical
finding identities. One of them runs the full `scan` → `attack` cycle
against a target with real (simulated) SQLi, including `UNION` extraction —
two separate process runs, two separate authentications, exactly as two real
`scanner` invocations would.

CI (`.github/workflows/ci.yml`) runs gofmt, vet, golangci-lint, govulncheck,
tests, race, and coverage.

---

## License

See [LICENSE](LICENSE).
