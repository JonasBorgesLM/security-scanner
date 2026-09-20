# Security Scanner — Evolution: audit, decisions and roadmap

Complements `security-scanner-projeto.md`, which remains the source of truth
for the **current** architecture. This document records the audit performed
on the implemented code, the structural decisions that came out of it, and
the resulting order of evolution. Nothing here describes code that already
exists.

---

> **Status (complete).** The five stages below have all been implemented. The
> scanner went from 4 to 12 checks, gained the coverage block (`schema_version`
> 3), `scanner diff`, SARIF output and a documented CI gate. Two cross-cutting
> capabilities the roadmap did not foresee came out of the way: a second pair
> of identities (`Clients.Anonymous`/`Secondary`) and the token exposed to the
> check (`Clients.SessionToken`), which are what unlocked `auth-required`,
> `idor` and `jwt-weak`. The decisions are in §4 and §6; the final measurement
> against Stage 1's exit criterion is recorded in issue #33.

## 1. The yardstick

The scanner answers **one** question: *"is this observable behaviour correct
from a security standpoint?"* — under four invariants:

1. **Correctness over volume** — asserts little, precisely.
2. **Only asserts with proof** — a noise floor in scan, a separate confirmer in attack.
3. **Gentle by design** — ScopeGuard + rate limiter + non-destructive gate.
4. **Auditable and comparable** — each stage's output is reviewable by hand,
   and two runs against the same target are comparable item by item.

The fourth invariant's wording changed — the earlier version promised more
than the code delivers. See §4.3.

**Test for any new capability:** is it a verifiable correctness question,
provable gently, about something observable from outside? If it requires
internal state, volume, source code, or modifying the target — it's out
(§7).

---

## 2. Corrections to the proposed design

Four points from the original evolution map did not survive contact with the
code. Recorded here because the conclusion alone gets lost; the reasoning is
what keeps the same mistake from being made again.

### 2.1 Passive is not a synonym for gentle

`Target.Baseline` is **one** response, obtained with **one** method, with
**no** forged request header. Any check whose question is *"what happens if I
vary the request?"* is active by definition, however cheap it is.

| Check proposed as passive | Reality |
|---|---|
| `cors-misconfigured` | A correct CORS middleware only emits `Access-Control-Allow-Origin` when there is an `Origin` in the request. The baseline sends no `Origin` — passively you only catch the always-on `ACAO: *` case, and origin reflection stays invisible |
| `dangerous-http-methods` | `TRACE` is only detectable by sending TRACE; `Allow:` in practice only shows up on a 405 or in response to OPTIONS, not on a typical 200 |
| `insecure-cookie-flags` | Genuinely passive, but on a JSON API with a Bearer token, `Set-Cookie` tends to never appear |
| `cache-on-authenticated` | Genuinely passive and correct — the baseline **is** authenticated (`runScan` passes the `Authenticator` to `engine.New`) |

Consequence: the configuration-checks block stops being "one new file each"
and starts depending on a collection decision. See §4.2.

### 2.2 A check only has one identity

`Authenticator.Do` injects the token into **every** request, unconditionally,
and sits *below* the rate limiter in the chain. A check receives a
`ports.HTTPClient` and has no way to send an anonymous request, nor one as
another user.

This repositions `idor`: it is not an isolated high-complexity case, it is the
**second** consumer of a capability whose first consumer (§2.4) is cheap and
more valuable. Solving identity once serves both.

### 2.3 `deps` and `rate-limit-bypass` are outside the yardstick

- **`govulncheck`** reads `go.mod` and the source code: that's static
  analysis, which the yardstick explicitly excludes. And it queries the
  vulnerability database over the network at run time, so two runs over the
  same code can diverge. Still valuable — but as a **CI step**, not a scanner
  subcommand, and never mixed into `findings.json`.
- **`rate-limit-bypass`** depends on the target's timing and concurrency: the
  result isn't comparable across runs. And "429 shows up under burst" is a
  miniature load test, which the yardstick also excludes. If it comes in, it
  comes in through its own output channel, outside the comparable contract.

### 2.4 What was missing: `auth-required`

For every endpoint the spec declares protected, send the request **with no
token** and verify it comes back 401/403. If it comes back 200, that's A01,
critical, trivial proof.

It's the best item in the whole roadmap: deterministic, black-and-white, no
noise floor, non-destructive by construction, and it **needs no second
user** — the oracle is the spec's own declaration. `Endpoint.RequiresAuth`
and `SecurityScheme` are already extracted by `resolveSecurity` and today only
serve to decide whether logging in is worthwhile.

### 2.5 Signal before volume

`missing-headers` on a JSON-only API reports CSP and X-Frame-Options on
every route. Neither one means anything for an `application/json` response
that no browser ever renders as a document. It's the same failure mode
`exposed-secrets` already avoids with its placeholder filter: a check people
learn to ignore takes the real findings down with it.

---

## 3. Audit of the current code

Overall state: build, `vet` and tests are green; coverage 82–100% per
package; CI runs gofmt/vet/lint/test/race. The security invariants are
*built*, not just documented — `deniedClient` makes "passive never touches the
network" impossible to violate, `CheckRedirect` closes the redirect hop,
`runPool` preserves input order instead of sorting afterward.

What follows is what isn't in good shape.

| # | Sev | Finding | Evidence | Issue |
|---|---|---|---|---|
| 1 | HIGH | Skipped/failed routes never reach the report | `cmd/scanner/main.go:163,167`; `model/finding.go:44-47`; `report/report.go:105-115` | #12 |
| 2 | HIGH | "Byte-identical" only holds against a static target | `checks/sqli.go:263-266`; `checks/xss.go` (`BaselineResponse`) | #13 |
| 3 | MEDIUM | Active checks clear POST routes they never exercised | `checks/sqli.go:322-356` (body `nil`), `sqli.go:163-171` | #28 |
| 4 | MEDIUM | No per-request timeout | `adapters/httpclient/httpclient.go:38-39` | #15 |
| 5 | MEDIUM | ~~Auth failure becomes `failed`, not `skipped`~~ → **fixed:** *partial* auth failure is silently dropped | `checks/sqli.go`, `checks/xss.go`: `lastErr` discarded when `tested > 0` | #16 |
| 6 | LOW | `ExtraHeaders` can overwrite `Content-Type`, contradicting its own doc | `core/auth/auth.go:223-226` vs `auth.go:58-63` | #17 |
| 7 | LOW | `anyFieldSet` ignores `username_field` and `extra_headers` | `adapters/config/config.go:97-105` | #17 |
| 8 | LOW | `expandTree` swallows any error that isn't a `MissingVarsError` | `adapters/config/config.go:197-207` | #17 |
| 9 | LOW | ScopeGuard is an exact string comparison; allowlist by name | `core/scope/scope.go:37` | #18 |
| 10 | LOW | Stale comments that contradict the code | `checks/xss.go`; `attack/request.go:59-63`; `envexpand.go:4` | #18 |

### 3.1 The two HIGHs in detail

**#1 — coverage.** `CLAUDE.md` states *"Skipped routes must reach the
report: showing a route as clean when it was never examined is worse than
admitting it could not be looked at"*, and `engine.Result.Skipped`'s doc
comment repeats it. In practice `summarise` returns `skipped` and `failed`,
`runScan` writes only `findings`, and both lists turn into discarded stderr
lines. `model.FindingsFile` has nowhere to carry them.

A scan where auth broke on 90% of routes produces a `report.html`
indistinguishable from a clean scan of a healthy API — just with fewer
findings.

It's blocking for `scanner diff`: comparing yesterday's `findings.json` with
today's would report `-resolved` for a route that simply wasn't examined
today. A false green is the worst possible failure mode for a regression
guard.

**#2 — determinism.** `sqli.go` embeds three live-measured values into
`Evidence` (noise floor, byte `diff`, response snippet); `xss.go` embeds the
baseline snippet. Against a target with a timestamp, request id or counter,
two identical scans produce different files.

`TestScan_IsReproducible` passes because `newLabServer` serves a static
body — the test is honest, but it doesn't cover the condition the invariant
needs to protect.

**Confirmed empirically** (reproducer in #13): against a vulnerable server
that carries a fixed-width request id in every response, two runs of
`sqli-boolean` produce findings with different `evidence` — and with
**identical identity** (same `ID`, URL and `payload`). This directly
confirms the §4.3 rule: comparing by identity works, comparing bytes doesn't.

Finding 3 was also confirmed by test (reproducer in #28): 15 probes spent
against a POST route that requires a body, all rejected with 400, zero
reaching the vulnerable path, and `Run` returning `(nil, nil)` — neither a
finding nor a skip.

### 3.1.1 Correction to finding 5

Finding 5 was stated wrong, and the correction is recorded here, because a
document that only keeps the right conclusion doesn't teach anyone to
distrust the wrong one.

**What I claimed:** no check maps `auth.ErrReAuthFailed` to
`model.Skippedf`, so broken auth falls into `Result.Err`.

**What the measurement showed:** *total* auth failure already becomes
`Skipped`, through two paths the reading didn't follow all the way —
`tested == 0` in `sqli`/`xss`, and a nil baseline when collection fails.
`errors.Is(err, model.ErrSkipped)` is `true` in all three tested cases.
**Invariant 6 was holding.**

**The real defect, which only the measurement found:** the *partial* case.
With two parameters, one working and the other with broken auth:

```
findings=0  err=<nil>
requests served=18  rejected=6
```

Six probes rejected, and `Run` returns `(nil, nil)`. `lastErr` gets filled
and then discarded whenever `tested > 0`. The route ends up **examined and
clean** — the same failure mode as finding 3, through a different door.

The methodological lesson is the same as §3.3: reading code produces a
hypothesis, not a finding. This one stayed a whole stage in the document with
its statement inverted.

---

### 3.2 A limit ScopeGuard does not cover

The allowlist is **by hostname**, and does not resolve IPs. It offers no
protection against DNS rebinding, and does not normalize case or an implicit
port (`LOCALHOST:8080` does not match `localhost:8080`). It fails closed
always, so it isn't a bypass — but `CLAUDE.md` calls ScopeGuard *"the hard
security boundary"* with no qualifier, and a control described as complete
when it's partial is worse than one that's simply absent. It's correct for
the threat model ("don't accidentally scan someone else's machine"); what was
missing was saying so.

### 3.3 A live run against `task-api`

The audit above is a reading of the code. A real scan, measured with a
counting proxy between the scanner and the target, changed the order of
magnitude of finding 1 and revealed three causes the reading had missed.

Target: local `task-api`, 30 endpoints in the spec, 22 non-destructive,
authenticated.

The instrument is `tools/reqcount`, a counting proxy that sits between the
scanner and the target and reports how many requests went out and what came
back. It exists because the scanner's own output cannot give that number —
this whole stage started from the observation that it was under-reporting
what it did, so measuring it with itself would be circular:

```
go run ./tools/reqcount -upstream http://localhost:8080 &
scanner scan --spec openapi.yaml --config config-via-proxy.yaml --out findings.json
kill -TERM %1
```

**The cost of this setup:** run through the proxy, ScopeGuard ends up
validating the *proxy's* address, not the target's. The allowlist still
holds — nothing leaves it — but what it guarantees becomes "the scanner only
talked to the proxy", and the proxy talks to whatever `-upstream` points it
at. The boundary that matters moved inside a flag. That trade is acceptable
for a deliberate measurement against your own lab, and unacceptable for
anything else.

```
TOTAL: 278 requests from the scanner

GET  -> 200 :  10      <-- 4%
GET  -> 400 : 136
GET  -> 404 : 109
GET  -> 405 :   5
POST -> 200 :   1      (the login)
POST -> 400 :  17
```

The scanner's own output, in full:

```
wrote findings.json (0 findings, 0 skipped, 0 failed)
```

**11 of 278 requests got a useful response**, and the file says `0 skipped, 0
failed`.

The contrast that makes this hard to see without measuring it: `task-api`
**is** genuinely well hardened — the four headers `missing-headers` looks for
are present on every response, so zero findings is honest *for that check*.
An empty-and-correct report and an empty-because-blind report are, today, the
same file. That's exactly why finding 1 is this stage's top-priority item.

The three causes, each with its own issue:

| Cause | Evidence | Issue |
|---|---|---|
| A rejected probe (4xx) is read as a valid response | `/v1/tasks?status=1` → 400; the **benign filler** is rejected right alongside the payload, so `measureNoise` ends up measuring the noise of error pages | #30 |
| The baseline of a non-GET route is a 405 page | `/v1/auth/{logout,register,password}` → 405; passives judge the error page, and `ProbedMethod` is written and never read | #31 |
| Spec routes absent from the target | `/v1/links` → 36 probes, 36× 404 | #32 |

The methodological lesson: **against a well-built API, today's active checks
conclude almost nothing — and don't say so.** §1's yardstick says "assert
little, precisely"; what the scanner does today is assert little with no
precision at all, which is a different thing.

Note on finding 2: this scan doesn't exercise it, because with no findings at
all there's no `evidence` to vary between runs. The two files come out
identical, trivially. Finding 2's confirmation is #13's, via a dedicated
test.

---

## 4. Structural decisions

Four decisions that hold for the whole project, not just the stage each one
is implemented in. Each records the option **not** taken: the conclusion
alone is what a future reader will question, the reasoning is what they need.

### 4.1 Coverage enters the contract — `schema_version: 2` *(Stage 1, #12)*

`FindingsFile` gains a `coverage` block alongside `findings`:

```json
{
  "schema_version": 2,
  "coverage": {
    "endpoints_total": 14,
    "checks_run": 42,
    "skipped": [
      { "check": "sqli-boolean",
        "endpoint": "POST /v1/tasks",
        "reason": "auth failed after re-auth" }
    ],
    "failed": []
  },
  "findings": [ ]
}
```

`attack` propagates the coverage it received and adds its own; `report` now
shows, next to the executive summary, what was **not** examined.

**Option not taken:** a separate `coverage.json`, leaving the schema at 1.
Cheaper up front (zero contract change) but keeps two files in manual sync,
and nothing stops running `report` with only `findings.json` — which
reproduces exactly today's false green. The bump's cost is paid once; the
optional file's cost is paid on every future run.

### 4.2 A safe probe set during collection *(implemented in Stage 3, #14)*

`Collect` now obtains, per endpoint, a **fixed and small** set of responses
using safe methods:

| Probe | Request | Serves |
|---|---|---|
| `baseline` | today's, unchanged | everything that already exists |
| `options` | OPTIONS on the same URL | `dangerous-http-methods`, CORS preflight |
| `origin` | GET with a sentinel `Origin:` | `cors-misconfigured` |

`Target.Baseline` stays **exactly** as it is — invariants 4 and 5 intact —
and gains `Target.Probes` alongside it, with the same reading rule: shared by
pointer across concurrent checks, therefore read-only.

Cost: 3 requests per endpoint instead of 1. In context, `sqli-boolean`
already spends `3 + 2×len(pairs)` requests **per parameter**; +2 per endpoint
is noise next to that. The property that matters is preserved: requests
proportional to the size of the spec, not to the spec × the number of checks.

**Option not taken:** each active check sends its own probe, via
`sendProbe`. Simpler and requires no architectural change, but multiplies
requests per check, pushes three configuration checks into `KindActive` with
no real need, and makes `sendProbe` — the *attack* path — get used by things
that don't attack. Choosing (b) is only justified because there are **three
concrete consumers today**, not a hypothetical one; with only one, the
duplication would be cheaper.

**Not configurable.** The set is fixed in code. A YAML-extensible probe set
would be a door into arbitrary requests outside the non-destructive gate.

### 4.3 Determinism: identity separated from evidence *(Stage 1, #13)*

Invariant 8 is now stated in two parts:

- **A finding's identity is deterministic.** `ID` derives only from
  check + method + path + discriminator, and never from anything measured on
  the target. It's what `scanner diff` compares by — never file bytes.
- **Evidence is descriptive, not comparable.** Body snippets, noise floor and
  byte differences are what a human reads to judge the finding; they vary
  with the target and that's expected.

What stays forbidden is wall-clock time in a finding that isn't about timing
(`Evidence.ResponseTime`), because that varies even when **nothing** on the
target changed.

`TestScan_IsReproducible` gains a companion that serves a dynamic body and
asserts the stability of **IDs**, not of the whole file.

**Consequence for `exposed-secrets`:** its discriminator is
`findingDiscriminator(p.name, len(findings))` — a positional index within the
pattern. If one of two findings from the same pattern disappears, the
remaining one's ID changes and the diff reports "1 removed + 1 new" for what
was only one removal. It needs a stable discriminator before `diff`.

### 4.4 Per-request timeout *(Stage 1, #15)*

`httpclient.New` now applies a per-request timeout, configurable via
`engine.request_timeout` (a modest default). Today the only limit is the
whole run's ctx: five hung routes tie up all five workers until
`engine.timeout` fires, and the whole scan is lost. With collection tripling
requests, the risk triples along with it.

---

## 5. The principle that orders the plan

The live run (§3.3) split the checks into two groups with different
destinies, and that split is what orders everything below.

| The check's oracle | Survives validated input? | Examples |
|---|---|---|
| **A property of the response** (status, header) | **Yes** — a validation 400 is still not a 401 | `auth-required`, `missing-headers`, `cache-on-authenticated`, `cors` |
| **Reflection of the payload** | **No** — validation rejects the probe before it ever reaches any query | `sqli-boolean`, `xss-reflected` |

### Measured, not argued

The table above was a prediction when it was written. With `auth-required`
implemented (#21), it became a measurement — same target, same run, five
checks side by side:

| Check | Oracle | Verdicts | Skips |
|---|---|---|---|
| `auth-required` | status code | **15** | 1 |
| `exposed-secrets` | already-collected body | 13 | 8 |
| `missing-headers` | already-collected headers | 13 | 8 |
| `sqli-boolean` | payload reflection | **0** | 8 |
| `xss-reflected` | payload reflection | **0** | 8 |

`auth-required` concluded on **15 of 16** routes it applied to. The two
injection checks concluded on **zero** — rejected by validation before
reaching anything, exactly as §3.3 predicted.

And the 15 verdicts aren't silence: each one is the assertion that a route
the spec declares protected genuinely **does refuse** a request with no
credential, verified by sending one. It's the first "clean" this scanner has
ever earned.

One detail that cost less than I feared: `POST /v1/auth/logout` and its
siblings got a verdict even with no body, because authentication runs before
validation — the 401 comes back regardless. Trading away "don't send a body"
cost one verdict, not fifteen.

Two consequences the original plan had no way to see:

1. **`auth-required` is immune to #30's failure mode**, so it's the first new
   check — not an item in the middle of the queue.
2. **`sqli`/`xss` gain nothing from new checks alongside them.** They need
   #30 and #28 before they're worth anything against a real API.

And §1's yardstick gains a corollary the measurement made obvious: *"assert
little, precisely"* is not the same as asserting little. A scan that
concludes nothing and doesn't say so asserts little **with no** precision at
all.

---

## 6. The plan

Five stages. Each has a measurable exit criterion against the baseline set in
§3.3 — 278 requests, 11 useful, `0 skipped, 0 failed`.

### Stage 1 — Honesty

**Property this stage buys:** the scan's output distinguishes "clean" from
"not examined".

Nothing after this is worth anything until it's in place: every report, diff
and gate built on today's output inherits the lie of omission.

| Issue | Item |
|---|---|
| #12 | Coverage enters the contract (`schema_version 2`) |
| #30 | A rejected probe (4xx) becomes `Skipped`, not silence |
| #31 | A 405 baseline from a substituted method is declared |
| #32 | A spec route absent from the target becomes `Skipped` |
| #16 | Auth failure becomes `skipped`, not `failed` |
| #13 | Determinism: identity separated from evidence |
| #15 | Per-request timeout |
| #17 | Three point fixes (findings 6, 7, 8) |
| #18 | ScopeGuard's limits + stale comments |
| #19 | Binary in `.gitignore` + `govulncheck` in CI |

**Exit criterion:** run the same `task-api` scan and get a report that
accounts for all 22 non-destructive routes, one by one. Secondary and
equally measurable: the 109 requests against nonexistent routes go to zero.

### Stage 2 — Conclusion

**Property:** checks can reach a conclusion about an API with validated
input.

| Issue | Item | Why here |
|---|---|---|
| #21 | **`auth-required`** | The first check that concludes where the current ones can't. Its oracle is a status code, immune to #30. It brings the alternate identity #25 depends on |
| #20 | `Content-Type` awareness in `missing-headers` | Signal before volume; fixes the existing check's noise |
| #28 | Body on POST routes | Unlocks `sqli`/`xss` on the routes that today only look clean |

**Exit criterion:** the `task-api` scan produces at least one sustained
positive verdict — "this route was exercised and is clean" — instead of
silence. And the reason for every remaining `Skipped` is a named limitation,
not "unknown".

### Stage 3 — Configuration family

**Property:** the scanner covers the vulnerability class most common in
production APIs — configuration.

| Issue | Item |
|---|---|
| #14 | A safe probe set during collection (`Target.Probes`) |
| #22 | `cache-on-authenticated` |
| #23 | `cors-misconfigured` + `dangerous-http-methods` |

Internal order: #14 first, and only because it has three concrete consumers
in this same stage (§4.2). Building it before that would be speculative
generality.

**Exit criterion:** all three checks run over `Target.Probes` with no request
of their own, and collection stays at 3 requests per endpoint.

### Stage 4 — Continuity

**Property:** the scanner stops being a one-off audit and becomes a guard.

| Issue | Item |
|---|---|
| #24 | `scanner diff` |
| #29 | SARIF output → CI gate |

**Why only now, despite being item 2 of the original plan:** a diff over
today's output compares two reports that don't know what they didn't
examine, and reports `-resolved` for a route that was simply never looked
at. `diff`'s leverage is real; it only exists on top of an honest base.

**Exit criterion:** two runs against an unchanged `task-api` produce an empty
diff, and turning off one protection on the target produces exactly one `+`
line.

### Stage 5 — Remaining classes

| Issue | Item |
|---|---|
| #25 | `idor` |
| #26 | `jwt-weak` |
| #27 | `verbose-errors` + `open-redirect` |

`idor` stopped being the final step: the alternate identity arrives in
Stage 2, with `auth-required`. What's left is its real work — discovering,
black-box and deterministically, a resource known to belong to a specific
user.

**Out of stage:** extract a `pkg/` only once a second real consumer exists —
probably once the CI gate matures.

---

## 6.1 What changed relative to the original plan

| Change | Reason |
|---|---|
| Ten issues that didn't exist jump ahead of everything | The audit (§3) and the measurement (§3.3) found defects the original plan had no way to see |
| `scanner diff` drops from 2nd place to Stage 4 | A diff over a dishonest report is a false green |
| `auth-required` comes in as the 1st new check | It didn't exist in the original plan; it's the only one that concludes against a validated API |
| The "passive block" dissolves | Three of the four weren't passive (§2.1); `insecure-cookie-flags` is out for being harmless on a JSON API; `security-txt-missing` is out for being hygiene, not a vulnerability |
| `deps` becomes a CI step (#19) | Source analysis + a result that isn't comparable across runs (§2.3) |
| `rate-limit-bypass` leaves the roadmap | Non-deterministic and a miniature load test (§2.3). If it returns, it gets its own output channel |
| `idor` stops being last | The alternate identity arrives with `auth-required` |

---

## 7. What stays out — and why

- **Load testing** (throughput, p99) — not comparable across runs, and an
  aggressive mode contradicts "gentle by design".
- **SAST / source analysis** — the scanner is black-box by decision. This
  includes `govulncheck`, which is why it becomes a CI step (§2.3).
- **Deep fuzzing** — fights both gentleness and comparability.
- **Any exploration that modifies state** — the non-destructive gate is
  non-negotiable. Extraction via `UNION SELECT` (read-only) is the limit, and
  already is one.
- **Probabilistic heuristics with no way to confirm** — violates "only assert
  with proof".

The line is always the same: inside it, a vulnerability is a property
**observable from outside** and **provable without causing harm**; outside
it, something requires internal state, volume, or the source code. The goal
isn't to do everything — it's to answer *one* question, better each time.
