# ssa-qa — black-box stability harness for the SSA engine

`ssa-qa` guards the standalone engine (`yak-ssa`) against silent output drift.
It never imports engine code: the contract is the `code-scan` CLI and its
report file. Each run happens in an isolated `YAKIT_HOME`; reports are
canonicalized and compared across repeated runs (determinism), across engine
versions (golden), and against performance budgets.

## Why this exists

Upstream churn and rule changes can quietly alter findings, hashes, or timing
and destabilize a downstream pipeline. `ssa-qa` turns "the scan still works" into
"the scan produces the same canonical result, or the change is explicitly
approved."

## Key canonicalization fact

The engine's risk **identity hash** (`CalcHash`, the `hash` field / `Risks` map
key in the irify report) is **non-deterministic across runs**, even with a fixed
`--program`: it folds in per-run `RuntimeId`/`ResultUUID`. Only the **feature
hash** (`risk_feature_hash` in irify, `yaklangRiskFeatureHash` in SARIF) and the
structural fields (type, severity, line, function, rule, source URL) are stable.

Therefore `canon` keys every finding by its **feature hash**, drops the identity
hash, strips the timestamped program-name prefix from source URLs, and sorts
findings. A stability baseline built on the identity hash would be falsely red
on every run.

## Commands

```bash
# execute cases; report determinism + perf, no golden comparison
ssa-qa run --binary /path/to/yak-ssa

# CI gate: run + diff vs goldens/allowlist, fail on unapproved drift / crash /
# non-determinism / SARIF schema break / budget overrun
ssa-qa verify --binary /path/to/yak-ssa

# rewrite goldens from the current engine (explicit; requires --confirm)
ssa-qa update-golden --binary /path/to/yak-ssa --confirm
```

Common flags: `--root` (repo root, default `.`), `--case <name>` (one case),
`--timeout`, `--golden-dir`, `--budgets`, `--allowlist`. `$SSA_QA_BINARY` supplies
the default binary.

Exit code is non-zero on any failure, so it drops into CI unchanged.

## Suites (expressed as cases)

A case is `cases/<name>/case.json` plus a corpus. One canonical pipeline covers
all five stability suites via case config:

| case | what it proves |
|------|----------------|
| `java` | **determinism + feature-hash golden**: 3 runs byte-identical after canon |
| `java-sarif` | **SARIF document golden + schema shape** (version 2.1.0, runs/results) |
| `java-incremental` | **incremental idempotency**: two passes on one DB give the same canonical result (second pass is fast) |
| `java-rules` | **rule loading/filter stability**: same findings when filtered to a rule keyword |

`case.json` fields: `name`, `language`, `corpus` (relative to the case dir),
`format` (`irify` default, or `sarif`), `program` (forced name; stabilizes source
URLs), `memory` (`--memory`, no DB), `runs` (determinism count, default 3),
`incremental` (reuse one home/DB for two passes), `extraArgs` (appended verbatim).

Configs are JSON (not YAML) on purpose: the harness has **zero external Go
dependencies** and builds offline.

## Goldens, allowlist, budgets

- `goldens/<case>.json` — canonical report per case (committed).
- `allowlist.json` — approved feature hashes with a required `reason`. An
  added/removed/changed finding whose feature hash is allowlisted downgrades the
  gate to a warning; anything else fails.
- `budgets.json` — per-case `max_ms`; exceeding it fails `verify`.

## Layout

```
ssa-qa/
  cmd/ssa-qa/          CLI: run | verify | update-golden
  internal/canon/      irify/SARIF -> canonical report; Compare; Hash
  internal/harness/    isolated black-box exec of yak-ssa
  corpus/              shared source fixtures (not imported; passed as --target)
  cases/<name>/        case.json
  goldens/             versioned canonical baselines
  budgets.json  allowlist.json
```
