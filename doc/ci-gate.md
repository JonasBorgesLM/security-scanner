# Running the scanner as a CI gate

The scanner produces two artifacts a pipeline consumes: a **SARIF** file that
GitHub Code Scanning reads natively, and an **exit code** from `scanner
diff` that decides whether the build passes.

---

## The exit code policy

| Command | 0 | 1 | 2 |
|---|---|---|---|
| `scan` / `attack` / `report` | success | failed | — |
| `diff` | nothing got worse | the comparison itself broke | **the new run is worse** |

The 2 is kept separate from the 1 on purpose. A CI step that cannot tell
the two apart **treats a broken scanner as a clean report** — the same
confusion Stage 1 of this project's evolution spent itself eliminating
(`doc/security-scanner-evolucao.md` §6, "Stage 1 — Honesty"), re-staged
at the pipeline level.

What counts as "worse" is two things, and the second is what an ordinary
diff cannot see:

1. A new finding at or above `--fail-on`'s severity (default: `high`).
2. **Coverage that used to exist and no longer does.** A run that examines
   less than the one before it has regressed even with a shorter findings
   list — especially then, because that is what breaking the scanner looks
   like from the outside.

---

## Example workflow

```yaml
name: Security scan

on:
  schedule: [{cron: "0 6 * * 1"}]
  workflow_dispatch:

permissions:
  contents: read
  security-events: write   # required to publish the SARIF

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with: {go-version-file: go.mod}

      - name: Build the scanner
        run: go build -o scanner ./cmd/scanner

      # The target must be up and inside scope.allowed_hosts.
      - name: Start the target
        run: docker compose up -d --wait

      - name: Scan
        env:
          LAB_PASSWORD: ${{ secrets.LAB_PASSWORD }}
        run: |
          ./scanner scan   --spec docs/openapi.yaml --config ci.yaml --out findings.json
          ./scanner attack --in findings.json --config ci.yaml --out confirmed.json
          ./scanner report --in confirmed.json --out report.html --sarif report.sarif

      - name: Publish to Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with: {sarif_file: report.sarif}

      # The baseline comes from a previous run — an artifact, a commit,
      # whatever fits. Without it the gate has nothing to compare against,
      # and the step is skipped rather than passing by mistake.
      - name: Compare against the baseline
        if: hashFiles('baseline/confirmed.json') != ''
        run: ./scanner diff baseline/confirmed.json confirmed.json
```

---

## What SARIF carries, and what it cannot carry

**Location.** These findings live on routes of a running target, not lines
of a file. `artifactLocation.uri` is given the **URL of the request that
produced the finding**, which is true. Pointing at a source file the
scanner never read, just to make the annotation land on a line, would not
be — which is why the annotations show up in the Security tab without
anchoring to code.

**Severity.** Two scales: `level` (`error`/`warning`/`note`) and
`security-severity` (0–10), the number GitHub sorts and filters by.
Omitting the second throws every finding into the same bucket.

**Coverage.** Code Scanning has no concept of "could not examine", so a
naive SARIF writer **drops the `coverage` block** — and this would become
the one format where an empty list is indistinguishable from a clean
target. The gaps go into `invocations[].toolExecutionNotifications`,
SARIF's own place for the tool to say something about the run rather than
about the code.

They do not become code annotations — GitHub does not display them
alongside results. They stay in the file, for whoever reads it. It is less
than one might want, and it is the most the format allows without
inventing a location.
