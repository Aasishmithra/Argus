# argus

**A multi-scanner SAST orchestrator** — one CLI, seven scanners, one unified,
deduplicated, prioritised finding report.

Argus wraps six independent SAST engines (semgrep, opengrep, bearer,
drogonsec, gosec, bandit, skylos) behind a single command, runs them in
parallel on either a local directory or a GitLab repo, then normalises,
deduplicates and re-severity-scores every finding into a single reviewable
output (JSON / CSV / XLSX / SARIF).

Named for the hundred-eyed guardian — six scanners, one verdict.

---

## Highlights

- **Multi-scanner**, one report — automatic language + framework detection
  picks the applicable scanners per repo; missing scanner binaries are
  gracefully skipped, not fatal.
- **Two-pass cross-scanner dedup** — same file × same rule → one row; same
  vulnerability class × nearby lines → one row. Full per-line detail
  preserved in `raw_findings.json`.
- **File-rule roll-up** — when the same rule fires ≥3 times on the same
  file, the review view shows one summary row with an `occurrences` list;
  raw data still auditable.
- **CRITICAL upgrade logic** — hand-audited allowlist promotes high-blast-
  radius rules (Log4Shell, SQL injection, SSRF, insecure deserialization,
  secrets in production configs) to CRITICAL with corroboration checks.
- **Auto false-positive filter** — filters findings inside vendored
  dependencies, build artifacts, virtualenvs, prior scan output, and
  common syntactic-only FPs (template-var secrets, safe parameterized
  SQLAlchemy, struct-tag reflection).
- **Remediation guidance inline** — each finding carries a `remediation`
  field with a copy-pasteable fix pattern for the rule.
- **User-triaged suppressions** — commit a `sast_suppressions.json` with
  fingerprints; future scans respect the triage.
- **CI-friendly** — `--fail-on high` for gating, `--out-summary` for
  per-repo rollups, `--checkpoint` for resumable large sweeps.

---

## Directory layout

```
argus/
├── argus.py                              # main scanner engine (single file)
├── argus_exclude_rules.txt               # global rule exclusions (one id/line)
├── README.md                             # this file
├── COVERAGE.txt                          # what argus detects, catalogued
├── .gitignore                            # ignores scan output + caches
│
├── sast_rulepack.yml                     # bundled semgrep rulepacks —
├── sphere_llm_semgrep.yml                # auto-loaded from CWD at startup
├── sast_webhook_misconfig.semgrep.yml    # (see BUNDLED_RULEPACK_GLOBS in
├── idor.semgrep.yml                      #  argus.py — pattern-matched)
├── prod_config_antipatterns.semgrep.yml  #
│
└── rules/                                # imported semgrep rulepack tree
    ├── README.md
    ├── ONBOARDING.md
    ├── 30_high_confidence/               # rules argus flags as CRITICAL-worthy
    │   ├── auth/                         # missing authorization patterns
    │   ├── cicd/                         # token-leak in logs / CI configs
    │   ├── cloud/                        # AWS / IAM misconfigs
    │   ├── code_execution/               # Log4Shell, SpEL, reflection RCE
    │   ├── custom/                       # org-specific critical patterns
    │   ├── deserialization/              # ObjectInputStream, Jackson typing
    │   ├── iac/                          # Terraform / K8s / Dockerfile
    │   ├── injection/                    # SQLi / XSS / SSRF / XXE / path
    │   ├── jwt/                          # JWT alg=none, verify-skip, hardcoded
    │   ├── secrets/                      # hardcoded credentials
    │   └── tls/                          # weak TLS, HMAC non-const, hardcoded IV
    ├── cwe-400/                          # DoS / uncontrolled-resource rules
    ├── go/ java/ javascript/ kotlin/     # per-language rulepacks
    ├── nodejs/ python/ swift/
```

## Requirements

- **Python 3.10+**
- Python packages: `pip install requests openpyxl PyYAML`
- Scanner binaries on `$PATH` (missing ones are skipped, not fatal):
  ```
  brew install semgrep gitleaks bearer         # macOS
  pip install bandit skylos                     # python-focused
  go install github.com/securego/gosec/v2/cmd/gosec@latest
  # opengrep, drogonsec: see their own install docs
  ```
- `git` on PATH (only required for GitLab clone actions)

## Install

Argus itself is one Python file — no `pip install` needed:

```bash
git clone <your-remote>/argus.git
cd argus
pip install requests openpyxl PyYAML          # runtime deps
python3 argus.py --list-scanners              # verify install
```

## Quick start — scan a local directory

```bash
python3 /path/to/argus/argus.py \
    --path /path/to/target-repo \
    --reports-dir /tmp/argus_reports \
    --out-summary /tmp/argus_summary.csv
```

Outputs land under `<reports-dir>/<repo-name>-<hash>/`:

| File | Contents |
|---|---|
| `findings.xlsx` | 3 sheets — Raw / Deduplicated / False Positives Removed |
| `findings.json` | active deduped findings (Pydantic-friendly, includes `remediation` + `occurrences`) |
| `findings.csv` | same, spreadsheet-friendly |
| `raw_findings.json` / `.csv` | every scanner hit before dedup — audit trail |
| `suppressed.json` / `.csv` | findings the built-in FP filter dropped, with reasons |
| `merged.sarif` | unified SARIF for GitHub / GitLab code scanning |
| `semgrep.sarif`, `bandit.json`, ... | per-scanner raw outputs |
| `_argus_rulebundle.yml` | the merged rulepack argus built for this scan |

## Common flags

| Flag | Purpose |
|---|---|
| `--path DIR [DIR ...]` | scan local directories (no GitLab needed) |
| `--custom-rulepack PATH [PATH ...]` | extra rulepacks (files or dirs); additive |
| `--no-rulepack-filter` | skip per-repo language filter; pass every rule verbatim |
| `--no-auto-suppress` | disable built-in FP classifier |
| `--dedup-line-window N` | ±N lines for pass-2 semantic dedup (default 3) |
| `--profile-rules` | write `rule_profile.csv` with per-rule cost + finding count |
| `--scanners X Y ...` | restrict to specific scanners |
| `--skip X Y ...` | skip specific scanners |
| `--scanner-workers N` | parallel scanners within a repo (default 4) |
| `--fail-on {critical,high,medium,low}` | exit non-zero on severity threshold |
| `--suppressions FILE` | user-triaged suppression file (fingerprint-keyed) |
| `--action triage --findings PATH` | review + triage a previous scan's findings |
| `--action scan --repo group/project` | GitLab clone-and-scan flow |
| `--action crawl --group X` | list GitLab projects to a CSV |
| `--list-scanners` | print scanner + rulepack registry |
| `--help` | full flag reference |

## GitLab workflows

`argus.py` first asks what you want to do, then only prompts for the inputs
that choice actually needs — a local scan and triage never ask for a URL or
token, and credentials are requested (hidden input, never written to disk)
only for GitLab actions.

```bash
# Crawl every project the token can see, into a CSV
python3 argus.py --action crawl --group my-org --output projects.csv

# Scan a single GitLab project
python3 argus.py --action scan --repo my-org/my-project

# Scan every project from a crawl CSV, with checkpoint for resume
python3 argus.py --action scan --csv projects.csv \
    --checkpoint /tmp/argus_ckpt.txt \
    --reports-dir /tmp/argus_reports \
    --out-summary /tmp/argus_summary.csv
```

## Framework auto-detection

Argus reads `requirements.txt` / `pyproject.toml` / `go.mod` / `pom.xml` /
`package.json` / `Gemfile` / `composer.json` per target and:

1. Loads matching Semgrep Registry vendor packs (`p/fastapi`, `p/django`,
   `p/java`, `p/jwt`, ...) automatically.
2. Filters custom rulepacks to only those whose `languages:` field
   intersects the detected language set — Python rules never parse on a
   Go-only repo.
3. Loads `p/kubernetes` / `p/dockerfile` only when actual k8s manifests /
   Dockerfiles are present.

Framework detection is logged at scan time:

```
   Detected languages: java(1426), yaml(3), python(1), shell(1)
   Detected frameworks: java:[dropwizard,hibernate,jackson,jax-rs,kafka]
   Vendor packs auto-loaded: 7 (p/security-audit, p/owasp-top-ten, ...)
   External rulepacks: 6 registered, 40 rule file(s) match ['java', 'yaml']
   Excluded rules   : 93 loaded from argus_exclude_rules.txt
   Rulepack bundle  : merged 40 file(s) -> 98 unique rule(s)
   Per-scanner jobs : 2 (cores=10, concurrent=4)
```

## Rule exclusions — `argus_exclude_rules.txt`

Global rule-exclusion list applied on every scan. One rule ID per line;
`#` starts a comment; blank lines OK.

Populate by running `--profile-rules` on a representative repo (produces
`rule_profile.csv` with per-rule cost + finding count); append IDs of rules
that consistently cost time and never fire on your typical stack.

```
# argus/argus_exclude_rules.txt
java.spring.security.injection.tainted-sql-string.tainted-sql-string
java.lang.security.audit.formatted-sql-string.formatted-sql-string
# ... etc
```

Each entry saves that rule's `match_time` on every subsequent scan across
every repo.

## User-triaged suppressions

For per-finding triage decisions that survive across scans, use a
`sast_suppressions.json` — plain JSON, safe to commit alongside code:

```json
{
  "version": 1,
  "suppressions": [
    {"fingerprint": "3f2a9c0d1b2e4f56",
     "status": "false_positive",
     "reason": "input sanitized upstream in AuthMiddleware.verify()",
     "triaged_by": "alice", "triaged_at": "2026-08-12T10:00:00"}
  ],
  "rules": [
    {"rule_id": "B101", "path_glob": "tests/**",
     "status": "false_positive",
     "reason": "asserts are expected in tests"}
  ]
}
```

Interactive triage of a previous scan's findings:

```bash
python3 argus.py --action triage \
    --findings /tmp/argus_reports/my-project/findings.json
```

Or non-interactive:

```bash
python3 argus.py --action triage --findings <...> \
    --suppress-fingerprints 3f2a9c0d1b2e4f56 \
    --reason "sanitized upstream in AuthMiddleware.verify()"
```

## Rule authoring

Add new Semgrep-compatible YAML rules to either:

- **`rules/30_high_confidence/<category>/*.yaml`** — for high-blast-radius
  rules that should promote to CRITICAL when they fire. Add the rule id
  token to `_ALWAYS_CRITICAL_RULE_HINTS` in `argus.py` so the promotion
  logic picks it up.
- **`rules/by-language/<lang>/`** — for language-specific patterns.
- **`sast_rulepack.yml`** (top-level, bundled) — for stable, cross-cutting
  rules versioned with the engine itself.

Every rule pack is language-filtered per repo, so noise on unrelated stacks
is zero. Broken rules are skipped with a warning by semgrep at scan time —
run `semgrep --validate --config <yaml>` to check before commit.

To also add:
- Category + CWE mapping: `RULE_ID_CATEGORY_PATTERNS` in `argus.py`
- CRITICAL upgrade: `_ALWAYS_CRITICAL_RULE_HINTS` in `argus.py`
- Remediation template: `REMEDIATION_TEMPLATES` in `argus.py`

## Output columns (findings.csv / .xlsx)

| Column | Description |
|---|---|
| `fingerprint` | 16-hex stable ID (sha1 of file + line + rule/CWE) |
| `status` | `open` / `false_positive` / `accepted_risk` / `wont_fix` |
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` |
| `confidence` | `VERY HIGH` / `HIGH` / `MEDIUM` / `LOW` — cross-scanner corroboration |
| `category` | Coarse weakness bucket (`secrets`, `sql-injection`, `ssrf`, ...) |
| `scanner` | Primary reporter of this finding |
| `sources` | `;`-joined list of every scanner that flagged this |
| `rule_id` | Rule identifier (unwound from bundle sentinels if bundled) |
| `cwe` | `CWE-###`, backfilled from rule metadata if scanner didn't tag |
| `path`, `start_line`, `end_line` | Location |
| `occurrences` | Extra line numbers when the same rule fires 3+ times on this file |
| `message` | Scanner-provided description |
| `vulnerable_code` | The flagged code with real line numbers |
| `remediation` | Concrete fix guidance keyed on rule id |
| `suppress_reason` | Why the auto-FP filter or user store suppressed it |

## Exit codes

- `0` — scan completed, no threshold breached
- `1` — argument error / environment problem / interrupted input
- `2` — `--fail-on <sev>` threshold met by at least one finding
- `130` — SIGINT (Ctrl+C)

## Configuration files argus reads

| File | Purpose |
|---|---|
| `argus_exclude_rules.txt` | Global rule ids to skip (any semgrep-family scanner) |
| `sast_suppressions.json` | Per-finding user triage decisions (auto-loaded from CWD) |
| `sast_rulepack.yml` + `*_semgrep.yml` + `*.semgrep.yml` next to `argus.py` | Bundled custom rulepacks (auto-discovered at startup) |
| `rules/**/*.yaml` | Imported semgrep rulepack tree (auto-loaded) |
| `~/.medusa/`, `~/.semgrep/`, etc. | Scanner caches (managed by each scanner, ignored by argus) |

## Troubleshooting

- **`ModuleNotFoundError: No module named 'requests'`** — `pip install requests openpyxl PyYAML`.
- **Scanner reported skipped** — install the binary, re-run. Argus never fails on a missing binary.
- **Semgrep runs forever** — likely a taint-mode rule on a very large file.
  Run `--profile-rules` to see per-rule cost, and consider adding the slow
  rule to `argus_exclude_rules.txt`.
- **Same finding on every scan** — commit it to `sast_suppressions.json` via
  `--action triage`.
- **Bundle unwinds to weird rule ids** — argus's sentinel-preserving bundler
  will recover the original id in `parse_sarif`. If you see mangled ids in
  the CSV, file an issue with the bundle path.

## License

See LICENSE. (Argus itself is a thin orchestrator; the wrapped scanners are
licensed independently — see each scanner's own repo.)
