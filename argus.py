#!/usr/bin/env python3
"""
argus.py — ARGUS: Multi-scanner SAST orchestrator.

  "The hundred-eyed guardian." Six scanners, one CLI, one unified verdict.

ARGUS crawls GitLab or scans local repositories with a language-aware
multi-scanner SAST engine. No other files required.

It first asks what you want to do, then asks only for the inputs that choice
actually needs — a local scan and triage never prompt for a GitLab URL or
token, and credentials are requested only for the GitLab actions:

    1) Scan a local directory           -> multi-scanner SAST, no GitLab needed
    2) Scan GitLab repositories         -> clone + multi-scanner SAST
    3) Crawl GitLab projects            -> CSV
    4) Triage previous scan results     -> suppress false positives

For the GitLab actions it then asks for the base URL and a Personal Access
Token (hidden input, never written to disk) and verifies the token.

CRAWL paginates the GitLab REST API and lists every project the token can see
(optionally scoped to a group/umbrella), writing a CSV.

SCAN, for each selected repo, does: shallow-clone -> detect languages ->
select every applicable scanner (semgrep / opengrep / bandit / bearer /
gosec / drogonsec ...) -> run them in parallel -> normalize + deduplicate ->
write merged SARIF + JSON + CSV -> delete the clone. Scanner choice is driven
entirely by the languages detected in each repo. A checkpoint file makes long
runs resumable, and a rolling summary CSV records severity counts per repo.
The token is embedded transiently in each clone URL and never persisted.
Every finding carries the vulnerable code lines (line-numbered) in both the
CSV and JSON reports. Each repo also gets a findings.xlsx workbook with three
sheets — "Raw Findings" (every scanner hit before dedup), "Deduplicated"
(after cross-scanner merge), and "False Positives Removed" (triaged
suppressions with reasons) — when openpyxl is installed.

TRIAGE reviews a previous scan's deduplicated findings.json interactively,
records false-positive / accepted-risk / won't-fix decisions in a reusable
sast_suppressions.json, and rewrites the report files with those findings
suppressed (they move to suppressed.json/csv and are marked as suppressed in
SARIF). Later scans auto-load the suppression file, so triaged false
positives never reappear in findings.csv/json.

LOCAL runs the exact same scan engine against directories already on disk —
a working copy, an unpacked archive, or code that never lived in GitLab. No
URL, token, or network access is required, nothing is cloned or deleted, and
the outputs (including the suppression handling) are identical. Passing
--path implies this action.

Missing scanner binaries are reported and skipped (a repo still gets scanned
by whatever is installed). Every prompt can be pre-answered on the command
line, so the tool works interactively or in automation.

Requires: pip install requests   (plus git on PATH; scanner binaries on PATH
as needed).

Examples
--------
    python3 argus.py
    python3 argus.py --url https://gitlab.example.com --action crawl --group timor
    python3 argus.py --action scan --repo group/sub/project
    python3 argus.py --action scan --group timor --limit 20
    python3 argus.py --action scan --csv gitlab_projects.csv --scanners semgrep bandit
    python3 argus.py --path .                       # scan the current directory
    python3 argus.py --path ~/src/proj-a ~/src/proj-b --scanners bandit --fail-on high
    python3 argus.py --action triage --findings sast_reports/group__proj/findings.json
    python3 argus.py --action triage --findings sast_reports/group__proj/findings.json \\
        --suppress-fingerprints 3f2a9c0d1b2e4f56 --reason "input sanitized upstream"
    python3 argus.py --list-scanners
"""
from __future__ import annotations


import argparse
import concurrent.futures as futures
import csv
import dataclasses
import fnmatch
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Set

log = logging.getLogger("argus")

# --------------------------------------------------------------------------
# ARGUS — brand identity
# --------------------------------------------------------------------------
# ARGUS is the mythological hundred-eyed guardian; the tool is named for the
# same "many eyes on the code" principle: six SAST engines run in parallel and
# their output is reconciled into a single verdict. The banner + version print
# on every non-trivial invocation so operators know which build produced the
# report they're triaging.
ARGUS_VERSION = "1.0.0"
ARGUS_TAGLINE = "the hundred-eyed guardian — six scanners, one verdict"

ARGUS_BANNER = r"""
       █████╗ ██████╗  ██████╗ ██╗   ██╗███████╗
      ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔════╝
      ███████║██████╔╝██║  ███╗██║   ██║███████╗
      ██╔══██║██╔══██╗██║   ██║██║   ██║╚════██║
      ██║  ██║██║  ██║╚██████╔╝╚██████╔╝███████║
      ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
"""


def _print_argus_banner(compact: bool = False) -> None:
    """Emit the ARGUS banner to stdout. `compact` prints a one-line variant
    used by --list-scanners / --help contexts where the full art wastes rows."""
    if compact:
        print(f"ARGUS · v{ARGUS_VERSION} · {ARGUS_TAGLINE}")
        return
    print(ARGUS_BANNER, flush=True)
    print(f"      v{ARGUS_VERSION} · {ARGUS_TAGLINE}", flush=True)
    print("", flush=True)


# Where the script itself lives; used to locate all bundled Semgrep rulepack
# files that ship next to it. Any file matching one of BUNDLED_RULEPACK_GLOBS
# is auto-registered at startup — so dropping a new *_semgrep.yml into this
# directory is the only step needed to add a rule bundle.
SCRIPT_DIR = Path(__file__).parent.resolve()

# Filename patterns treated as bundled Semgrep-compatible rulepacks. Kept as
# explicit patterns (not a blanket *.yml) so unrelated YAML — README front-
# matter, editor settings, ansible playbooks — never gets shoved into semgrep
# by accident.
BUNDLED_RULEPACK_GLOBS = (
    "*_rulepack.yml", "*_rulepack.yaml",
    "*_semgrep.yml",  "*_semgrep.yaml",
    "*.semgrep.yml",  "*.semgrep.yaml",
)


def discover_bundled_rulepacks() -> "List[Path]":
    """Return every rulepack path bundled alongside argus.py:

    (1) top-level YAML files matching BUNDLED_RULEPACK_GLOBS
        (sast_rulepack.yml, sphere_llm_semgrep.yml, sast_webhook_misconfig.
        semgrep.yml, ...)

    (2) the imported-pack subdirectory `rules/` if it exists — passed as a
        single directory path so semgrep walks it recursively. The per-repo
        language filter applied inside `resolve_rulepack_configs` still
        prunes files whose `languages:` doesn't match the target repo.

    Sorted, deduplicated, and deterministic across runs."""
    seen: "Set[Path]" = set()
    packs: "List[Path]" = []
    # Top-level bundled files
    for pat in BUNDLED_RULEPACK_GLOBS:
        for p in sorted(SCRIPT_DIR.glob(pat)):
            rp = p.resolve()
            if rp in seen:
                continue
            seen.add(rp)
            packs.append(rp)
    # Imported / vendored rulepack subdirectory
    imported = SCRIPT_DIR / "rules"
    if imported.is_dir():
        rp = imported.resolve()
        if rp not in seen:
            seen.add(rp)
            packs.append(rp)
    return packs


# Preserved constant so older calls / external scripts referencing
# CUSTOM_RULEPACK still work. Points at the primary sast_rulepack.yml if it
# exists; otherwise falls back to whatever the discovery returned first.
_disc = discover_bundled_rulepacks()
CUSTOM_RULEPACK = (
    SCRIPT_DIR / "sast_rulepack.yml"
    if (SCRIPT_DIR / "sast_rulepack.yml").exists()
    else (_disc[0] if _disc else SCRIPT_DIR / "sast_rulepack.yml")
)
del _disc

# --------------------------------------------------------------------------------------
# Language model
# --------------------------------------------------------------------------------------

# extension -> language
EXT_LANG: Dict[str, str] = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".go": "go",
    ".rb": "ruby", ".rake": "ruby",
    ".java": "java",
    ".kt": "kotlin", ".kts": "kotlin",
    ".cs": "csharp",
    ".php": "php",
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hxx": "cpp",
    ".swift": "swift",
    ".rs": "rust",
    ".scala": "scala",
    ".ex": "elixir", ".exs": "elixir",
    ".sh": "shell", ".bash": "shell",
    ".tf": "terraform",
    ".yaml": "yaml", ".yml": "yaml",
}

# manifest filename -> language (raises confidence even with few source files)
MANIFEST_LANG: Dict[str, str] = {
    "requirements.txt": "python", "pyproject.toml": "python", "setup.py": "python", "Pipfile": "python",
    "package.json": "javascript", "tsconfig.json": "typescript",
    "go.mod": "go",
    "Gemfile": "ruby",
    "pom.xml": "java", "build.gradle": "java", "build.gradle.kts": "kotlin",
    "composer.json": "php",
    "Cargo.toml": "rust",
    "*.csproj": "csharp",
}

# directories never worth crawling
IGNORE_DIRS: Set[str] = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "out", "target",
    ".venv", "venv", "env", "__pycache__", ".mypy_cache", ".pytest_cache", ".tox",
    ".idea", ".vscode", ".gradle", "bin", "obj", "coverage", ".next", ".nuxt",
    # This tool's own scan output + common vendored / build noise. Keeping these
    # here means the *language detector* skips them; the built-in auto-FP filter
    # below also drops any scanner hit whose path lands inside one of them, so a
    # rescan on top of a previous report directory stays clean.
    "sast_reports", "SAST_Scan", "sast-reports", "site-packages",
    ".ruff_cache", ".terraform", ".serverless",
}

# --------------------------------------------------------------------------------------
# Framework auto-detection
#
# For every scanned repo we sniff the top-level manifests to learn WHICH web
# frameworks / ORMs / SDKs are in play. The result flows two ways:
#   1) It's logged so a human eyeballing the scan can confirm the tool
#      understood the stack.
#   2) It scopes which external rulepack files get passed to semgrep /
#      opengrep. Rule files whose `languages:` don't intersect this repo's
#      detected languages are dropped before scan time — a JAX-RS Java rule
#      never gets parsed while scanning a pure-Go repo.
# The map is intentionally shallow (a substring match against manifest text),
# because manifests have widely divergent syntax across languages and a full
# parser per format is overkill for coarse framework tagging.
# --------------------------------------------------------------------------------------

# Structure: language -> {"manifests": [filename patterns],
#                         "frameworks": {framework_tag: [substring markers]}}
FRAMEWORK_MARKERS: Dict[str, Dict[str, object]] = {
    "python": {
        "manifests": ["requirements.txt", "requirements-*.txt", "pyproject.toml",
                      "setup.py", "setup.cfg", "Pipfile", "Pipfile.lock",
                      "poetry.lock", "uv.lock"],
        "frameworks": {
            "fastapi":    ["fastapi"],
            "flask":      ["flask"],
            "django":     ["django"],
            "starlette":  ["starlette"],
            "tornado":    ["tornado"],
            "aiohttp":    ["aiohttp"],
            "sqlalchemy": ["sqlalchemy", "sqlmodel"],
            "pymongo":    ["pymongo"],
            "pydantic":   ["pydantic"],
            "celery":     ["celery"],
            "kafka":      ["kafka-python", "confluent-kafka", "aiokafka"],
            "jinja2":     ["jinja2"],
            "openai":     ["openai"],
            "anthropic":  ["anthropic"],
            "langchain":  ["langchain"],
            "boto3":      ["boto3"],
        },
    },
    "go": {
        "manifests": ["go.mod", "go.sum"],
        "frameworks": {
            "gin":         ["gin-gonic/gin"],
            "beego":       ["beego/beego", "astaxie/beego"],
            "echo":        ["labstack/echo"],
            "fiber":       ["gofiber/fiber"],
            "chi":         ["go-chi/chi"],
            "gorilla-mux": ["gorilla/mux"],
            "net-http":    ["net/http"],
            "gorm":        ["gorm.io/gorm", "jinzhu/gorm"],
            "sqlx":        ["jmoiron/sqlx"],
            "kafka":       ["confluent-kafka-go", "segmentio/kafka-go", "sarama"],
            "aws-sdk-go":  ["aws/aws-sdk-go"],
            "google-cloud": ["cloud.google.com/go"],
        },
    },
    "java": {
        "manifests": ["pom.xml", "build.gradle", "build.gradle.kts",
                      "settings.gradle", "settings.gradle.kts"],
        "frameworks": {
            "spring-boot":      ["spring-boot"],
            "spring-web":       ["spring-web", "spring-webmvc", "org.springframework.web"],
            "spring-security":  ["spring-security"],
            "jax-rs":           ["javax.ws.rs", "jakarta.ws.rs", "resteasy", "jersey"],
            "dropwizard":       ["dropwizard"],
            "struts":           ["struts"],
            "hibernate":        ["hibernate"],
            "jpa":              ["jakarta.persistence", "javax.persistence"],
            "jackson":          ["jackson-databind", "jackson-core"],
            "log4j":            ["log4j"],
            "logback":          ["logback"],
            "kafka":            ["kafka-clients", "spring-kafka"],
            "jwt":              ["jjwt", "java-jwt", "nimbus-jose-jwt"],
        },
    },
    "kotlin": {
        "manifests": ["pom.xml", "build.gradle", "build.gradle.kts"],
        "frameworks": {
            "ktor":            ["io.ktor"],
            "spring-boot":     ["spring-boot"],
            "android":         ["com.android.application", "com.android.library"],
        },
    },
    "javascript": {
        "manifests": ["package.json", "package-lock.json", "yarn.lock",
                      "pnpm-lock.yaml"],
        "frameworks": {
            "express":  ["\"express\""],
            "next":     ["\"next\""],
            "nest":     ["@nestjs/core"],
            "koa":      ["\"koa\""],
            "fastify":  ["\"fastify\""],
            "hapi":     ["@hapi/hapi"],
            "react":    ["\"react\""],
            "vue":      ["\"vue\""],
            "angular":  ["@angular/core"],
            "axios":    ["\"axios\""],
            "mongoose": ["\"mongoose\""],
            "prisma":   ["@prisma/client"],
            "jsonwebtoken": ["\"jsonwebtoken\""],
        },
    },
    "typescript": {
        "manifests": ["package.json", "tsconfig.json"],
        "frameworks": {
            "nest":     ["@nestjs/core"],
            "next":     ["\"next\""],
            "express":  ["\"express\""],
            "fastify":  ["\"fastify\""],
            "typeorm":  ["\"typeorm\""],
            "prisma":   ["@prisma/client"],
        },
    },
    "ruby": {
        "manifests": ["Gemfile", "Gemfile.lock", "*.gemspec"],
        "frameworks": {
            "rails":   ["rails", "actionpack"],
            "sinatra": ["sinatra"],
            "hanami":  ["hanami"],
            "grape":   ["grape"],
            "sequel":  ["sequel"],
        },
    },
    "php": {
        "manifests": ["composer.json", "composer.lock"],
        "frameworks": {
            "laravel": ["laravel/framework"],
            "symfony": ["symfony/"],
            "slim":    ["slim/slim"],
            "codeigniter": ["codeigniter/"],
        },
    },
    "csharp": {
        "manifests": ["*.csproj", "*.sln", "packages.config"],
        "frameworks": {
            "aspnet-core": ["Microsoft.AspNetCore"],
            "ef-core":     ["Microsoft.EntityFrameworkCore"],
        },
    },
}

# Manifest filenames to check at any depth (subject to IGNORE_DIRS pruning),
# capped at MAX_MANIFEST_DEPTH so the walk is bounded on huge repos.
MAX_MANIFEST_DEPTH = 4


def _iter_manifests(root: Path, patterns: List[str],
                    max_depth: int = MAX_MANIFEST_DEPTH):
    """Yield paths under `root` whose basename matches any pattern (fnmatch),
    stopping the walk beneath IGNORE_DIRS and beyond `max_depth`."""
    if not root.exists() or not root.is_dir():
        return
    root_parts = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        depth = len(Path(dirpath).parts) - root_parts
        if depth > max_depth:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames
                       if d not in IGNORE_DIRS and not d.startswith(".")]
        for fname in filenames:
            for pat in patterns:
                if fname == pat or ("*" in pat and fnmatch.fnmatch(fname, pat)):
                    yield Path(dirpath) / fname
                    break


def detect_frameworks(root: Path) -> Dict[str, Set[str]]:
    """Detect frameworks in-play per language. Returns a dict keyed by the
    language whose manifest was found; empty dict when nothing recognisable
    lives in the repo.

    Detection is lower-cased-substring over the concatenated manifest text.
    That's coarse on purpose — accurate enough to gate rulepack file loading
    without maintaining a full parser for each of npm / poetry / maven /
    gradle / go.mod / Gemfile / composer.json."""
    result: Dict[str, Set[str]] = {}
    for lang, spec in FRAMEWORK_MARKERS.items():
        manifest_patterns: List[str] = list(spec.get("manifests", []))  # type: ignore
        texts: List[str] = []
        for p in _iter_manifests(root, manifest_patterns):
            try:
                texts.append(p.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue
        if not texts:
            continue
        combined = "\n".join(texts).lower()
        fw_spec: Dict[str, List[str]] = spec.get("frameworks", {})  # type: ignore
        found: Set[str] = set()
        for fw_name, markers in fw_spec.items():
            if any(m.lower() in combined for m in markers):
                found.add(fw_name)
        result[lang] = found
    return result


# --------------------------------------------------------------------------------------
# Unified severity
# --------------------------------------------------------------------------------------

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
RANK_SEV = {v: k for k, v in SEV_RANK.items()}


def sev_from_security_severity(num: float) -> str:
    """GitHub 'security-severity' numeric (0-10) -> unified bucket."""
    if num >= 9.0:
        return "CRITICAL"
    if num >= 7.0:
        return "HIGH"
    if num >= 4.0:
        return "MEDIUM"
    if num > 0.0:
        return "LOW"
    return "INFO"


def sev_from_sarif_level(level: str) -> str:
    return {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "INFO"}.get(
        (level or "").lower(), "MEDIUM"
    )


def norm_severity(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    r = raw.strip().upper()
    aliases = {
        "ERROR": "HIGH", "WARNING": "MEDIUM", "WARN": "MEDIUM", "NOTE": "LOW",
        "INFORMATIONAL": "INFO", "INFORMATION": "INFO", "MODERATE": "MEDIUM",
        "BLOCKER": "CRITICAL", "MAJOR": "HIGH", "MINOR": "LOW", "TRIVIAL": "INFO",
    }
    if r in SEV_RANK:
        return r
    return aliases.get(r)


# --------------------------------------------------------------------------------------
# Semantic category system
#
# Different scanners fire different rule_ids for the same underlying weakness
# (e.g. drogonsec LEAK-010 "Google API Key", drogonsec LEAK-121 "Generic API
# Key", opengrep "detected-generic-api-key", bearer "hardcoded_secret") and
# only some emit a CWE. The primary fingerprint therefore misses most
# cross-scanner duplicates. `infer_category` normalises rule_id + CWE + message
# into a coarse-grained bucket which the second-pass dedup uses to merge
# same-file, same-category, nearby-line hits from different tools.
# --------------------------------------------------------------------------------------

# CWE -> category. Kept scoped to CWEs the scanners actually emit against the
# codebases argus scans; extend when a new scanner brings a new CWE class.
CWE_TO_CATEGORY: Dict[str, str] = {
    "CWE-798": "secrets", "CWE-259": "secrets", "CWE-321": "secrets",
    "CWE-89":  "sql-injection",
    "CWE-79":  "xss",
    "CWE-22":  "path-traversal",
    "CWE-77":  "command-injection", "CWE-78": "command-injection",
    "CWE-94":  "code-injection",
    "CWE-502": "insecure-deserialization",
    "CWE-327": "weak-crypto", "CWE-328": "weak-crypto", "CWE-916": "weak-crypto",
    "CWE-330": "weak-random", "CWE-338": "weak-random",
    "CWE-295": "insecure-tls", "CWE-297": "insecure-tls", "CWE-319": "insecure-tls",
    "CWE-611": "xxe",
    "CWE-918": "ssrf",
    "CWE-352": "csrf",
    "CWE-601": "open-redirect",
    "CWE-732": "insecure-permissions", "CWE-276": "insecure-permissions",
    "CWE-703": "assert-used",
    # Backfilled 2026-09-23 for the argus-native CRITICAL rulepack in
    # semgrep-master/30_high_confidence/. Each maps to a category argus's
    # dedup + severity-upgrade logic already understands.
    "CWE-117": "code-injection",           # improper log neutralization → Log4Shell-class
    "CWE-917": "code-injection",           # expression-language injection (Log4Shell root CWE)
    "CWE-470": "code-injection",           # unsafe reflection: class name from user input
    # Added 2026-09-23 for the additional-coverage rulepack.
    "CWE-347": "auth",                     # improper signature verification (JWT)
    "CWE-434": "unrestricted-file-upload", # unrestricted upload of file with dangerous type
    # Backfilled 2026-09-23 after finding 98% of scanner findings had no CWE
    # and pass-2 dedup couldn't cluster them. Every CWE the rule-id patterns
    # below now emit must be mappable here so cluster-by-category works.
    "CWE-862": "access-control",           # missing authorization
    "CWE-639": "access-control",           # IDOR / authorization by user-controlled key
    "CWE-284": "access-control",           # improper access control
    "CWE-532": "info-disclosure",          # sensitive info in log
    "CWE-209": "info-disclosure",          # error-message info leak
    "CWE-208": "timing-attack",            # observable timing discrepancy
    "CWE-400": "dos",                      # uncontrolled resource consumption
    "CWE-770": "dos",                      # allocation of resources without limits
    "CWE-190": "integer-overflow",         # integer overflow / wraparound
    "CWE-681": "integer-overflow",         # incorrect conversion between numeric types
    "CWE-1333": "redos",                   # inefficient regex complexity
    "CWE-20":  "input-validation",         # improper input validation
    "CWE-1188": "auth",                    # insecure default init of resource
    "CWE-377": "insecure-tempfile",        # insecure temp file
    "CWE-378": "insecure-tempfile",
    "CWE-390": "error-handling",           # detection of error without action
    "CWE-252": "error-handling",           # unchecked return value
    "CWE-676": "correctness",              # use of dangerous function
    "CWE-758": "correctness",              # reliance on undefined behavior
}

# Rule-ID substring / prefix -> (category, cwe_or_None). Three-tuple format
# lets us backfill BOTH the category (used by pass-2 semantic dedup) AND the
# CWE (used by SARIF export, severity-upgrade logic, and CWE_TO_CATEGORY
# lookup) from a single source of truth. Prefix match against a lowercased
# rule_id; None means "no known/authoritative CWE for this pattern".
RULE_ID_CATEGORY_PATTERNS: List[tuple] = [
    # --- secrets -----------------------------------------------------------
    ("leak-",                          "secrets",                 "CWE-798"),
    ("hardcoded_secret",               "secrets",                 "CWE-798"),
    ("hardcoded-secret",               "secrets",                 "CWE-798"),
    ("detected-generic-api-key",       "secrets",                 "CWE-798"),
    ("detected-generic-secret",        "secrets",                 "CWE-798"),
    ("hardcoded_password",             "secrets",                 "CWE-798"),
    ("b105",                           "secrets",                 "CWE-798"),  # bandit hardcoded_password_string
    ("b106",                           "secrets",                 "CWE-798"),
    ("b107",                           "secrets",                 "CWE-798"),
    ("aws-access-key",                 "secrets",                 "CWE-798"),
    ("gcp-service-account",            "secrets",                 "CWE-798"),
    ("private-key",                    "secrets",                 "CWE-798"),
    ("py-003",                         "secrets",                 "CWE-798"),  # drogonsec generic secret
    # --- injection ---------------------------------------------------------
    ("path_traversal",                 "path-traversal",          "CWE-22"),
    ("path-traversal",                 "path-traversal",          "CWE-22"),
    ("directory_traversal",            "path-traversal",          "CWE-22"),
    ("filereadtaint",                  "path-traversal",          "CWE-22"),
    ("g304",                           "path-traversal",          "CWE-22"),   # gosec: file inclusion via variable
    ("sql_injection",                  "sql-injection",           "CWE-89"),
    ("sql-injection",                  "sql-injection",           "CWE-89"),
    ("sqli",                           "sql-injection",           "CWE-89"),
    ("command_injection",              "command-injection",       "CWE-78"),
    ("command-injection",              "command-injection",       "CWE-78"),
    ("os_command",                     "command-injection",       "CWE-78"),
    ("subprocess_",                    "command-injection",       "CWE-78"),
    ("b602",                           "command-injection",       "CWE-78"),   # subprocess w/ shell=True
    ("b603",                           "command-injection",       "CWE-78"),
    ("b605",                           "command-injection",       "CWE-78"),
    ("b606",                           "command-injection",       "CWE-78"),
    ("b607",                           "command-injection",       "CWE-78"),
    ("code_injection",                 "code-injection",          "CWE-94"),
    ("code-injection",                 "code-injection",          "CWE-94"),
    ("b307",                           "code-injection",          "CWE-94"),   # eval
    ("b102",                           "code-injection",          "CWE-94"),   # exec
    # Added 2026-09-23 — argus-native RCE-class rules from
    # rules/30_high_confidence/code_execution/.
    ("log4j-message-lookup-injection", "code-injection",          "CWE-917"),  # Log4Shell / CVE-2021-44228
    ("log4shell",                      "code-injection",          "CWE-917"),
    ("spring-spel-tainted-input",      "code-injection",          "CWE-94"),   # SpEL RCE (Spring4Shell class)
    ("spring-spel",                    "code-injection",          "CWE-94"),
    ("spel-injection",                 "code-injection",          "CWE-94"),
    ("unsafe-reflection-class-forname","code-injection",          "CWE-470"),  # Class.forName on tainted input
    ("unsafe-reflection",              "code-injection",          "CWE-470"),
    # --- JWT / auth (added 2026-09-23) -----------------------------------
    ("jwt-decode-without-verification","auth",                    "CWE-347"),
    ("jwt-decode-without",             "auth",                    "CWE-347"),
    ("jwt-none-alg",                   "auth",                    "CWE-347"),
    ("jwt-hardcode",                   "auth",                    "CWE-798"),
    # --- File upload (added 2026-09-23) ----------------------------------
    ("unrestricted-file-upload",       "unrestricted-file-upload","CWE-434"),
    ("file-upload-user-filename",      "unrestricted-file-upload","CWE-434"),
    # --- Timing / crypto (added 2026-09-23) ------------------------------
    ("hmac-comparison-non-constant-time","timing-attack",         "CWE-208"),
    ("hardcoded-crypto-iv",            "weak-crypto",             "CWE-330"),
    ("hardcoded-iv",                   "weak-crypto",             "CWE-330"),
    ("static-iv",                      "weak-crypto",             "CWE-330"),
    ("static-salt",                    "weak-crypto",             "CWE-330"),
    ("xss",                            "xss",                     "CWE-79"),
    ("cross-site-scripting",           "xss",                     "CWE-79"),
    ("html-002",                       "xss",                     "CWE-79"),   # drogonsec HTML XSS
    # --- XXE (added 2026-09-23) — argus-native Java XXE variants -----------
    ("xxe-java-documentbuilder",       "xxe",                     "CWE-611"),
    ("xxe-java-saxparser",             "xxe",                     "CWE-611"),
    ("xxe-java-xmlinputfactory",       "xxe",                     "CWE-611"),
    ("xxe-java-",                      "xxe",                     "CWE-611"),  # catch-all for xxe-java-*
    ("javax-xml-xxe",                  "xxe",                     "CWE-611"),
    # --- SSRF (added 2026-09-23) — argus-native tainted-URL rules ---------
    ("ssrf-tainted-url-java",          "ssrf",                    "CWE-918"),
    ("ssrf-tainted-url-go",            "ssrf",                    "CWE-918"),
    ("ssrf-tainted-url",               "ssrf",                    "CWE-918"),
    ("ssrf-",                          "ssrf",                    "CWE-918"),  # catch-all for ssrf-* rules
    ("ssrf_",                          "ssrf",                    "CWE-918"),
    # --- deserialization ---------------------------------------------------
    ("deserialization",                "insecure-deserialization","CWE-502"),
    ("pickle",                         "insecure-deserialization","CWE-502"),
    ("b301",                           "insecure-deserialization","CWE-502"),
    ("b403",                           "insecure-deserialization","CWE-502"),
    ("yaml_load",                      "insecure-deserialization","CWE-502"),
    ("b506",                           "insecure-deserialization","CWE-502"),  # yaml.load
    ("default-resteasy-provider-abuse","insecure-deserialization","CWE-502"),
    # Added 2026-09-23 — argus-native rules from
    # rules/30_high_confidence/deserialization/.
    ("objectinputstream",              "insecure-deserialization","CWE-502"),  # Java native serialization sink
    ("java-objectinputstream",         "insecure-deserialization","CWE-502"),
    ("jackson-enable-default-typing",  "insecure-deserialization","CWE-502"),
    ("jackson-default-typing",         "insecure-deserialization","CWE-502"),
    # --- crypto ------------------------------------------------------------
    ("weak_hash",                      "weak-crypto",             "CWE-327"),
    ("weak-hash",                      "weak-crypto",             "CWE-327"),
    ("md5",                            "weak-crypto",             "CWE-327"),
    ("sha1",                           "weak-crypto",             "CWE-327"),
    ("b303",                           "weak-crypto",             "CWE-327"),  # md5
    ("b304",                           "weak-crypto",             "CWE-327"),  # insecure ciphers
    ("b324",                           "weak-crypto",             "CWE-327"),  # hashlib.new insecure
    # --- TLS / transport ---------------------------------------------------
    ("weak_tls",                       "insecure-tls",            "CWE-295"),
    ("weak-tls",                       "insecure-tls",            "CWE-295"),
    ("insecure_ssl",                   "insecure-tls",            "CWE-295"),
    ("ssl_verify_none",                "insecure-tls",            "CWE-295"),
    ("verify=false",                   "insecure-tls",            "CWE-295"),
    ("b501",                           "insecure-tls",            "CWE-295"),
    ("usessl-false",                   "insecure-tls",            "CWE-319"),  # JDBC without TLS
    ("usessl_false",                   "insecure-tls",            "CWE-319"),
    ("insecure_websocket",             "insecure-transport",      "CWE-319"),
    ("insecure-websocket",             "insecure-transport",      "CWE-319"),
    # --- randomness --------------------------------------------------------
    ("weak-random",                    "weak-random",             "CWE-338"),
    ("weak_random",                    "weak-random",             "CWE-338"),
    ("b311",                           "weak-random",             "CWE-338"),  # random.random
    # --- test-file / silent exception --------------------------------------
    ("assert_used",                    "assert-used",             "CWE-703"),
    ("b101",                           "assert-used",             "CWE-703"),
    ("try_except_pass",                "silent-exception",        "CWE-703"),
    ("b110",                           "silent-exception",        "CWE-703"),
    ("b112",                           "silent-exception",        "CWE-703"),
    # --- tempfile ----------------------------------------------------------
    ("hardcoded_tmp",                  "insecure-tempfile",       "CWE-377"),
    ("b108",                           "insecure-tempfile",       "CWE-377"),
    ("bad-tmp-file-creation",          "insecure-tempfile",       "CWE-377"),
    # --- access control (NEW 2026-09-23 — top uncategorized-rule cluster) --
    ("handler-missing-authz-annotation","access-control",         "CWE-862"),  # 239 hits/scan
    ("idor-handler-fetch-by-id-no-authz","access-control",        "CWE-639"),  # 195+171+44 hits/scan
    ("missing-authz",                  "access-control",          "CWE-862"),
    ("missing_authz",                  "access-control",          "CWE-862"),
    ("no-authz",                       "access-control",          "CWE-862"),
    ("access-control",                 "access-control",          "CWE-284"),
    ("access_control",                 "access-control",          "CWE-284"),
    ("idor",                           "access-control",          "CWE-639"),
    ("dev-qa-token-accepted-in-prod",  "auth",                    "CWE-1188"),
    # --- DoS / resource exhaustion ----------------------------------------
    ("cwe-400-unbounded-async",        "dos",                     "CWE-400"),  # 129 hits/scan
    ("cwe-400-",                       "dos",                     "CWE-400"),
    ("unbounded-",                     "dos",                     "CWE-770"),
    ("unbounded_",                     "dos",                     "CWE-770"),
    ("pydantic.unbounded",             "dos",                     "CWE-770"),
    # --- ReDoS -------------------------------------------------------------
    ("redos",                          "redos",                   "CWE-1333"),
    ("user-controlled-pattern",        "redos",                   "CWE-1333"),
    # --- info disclosure via logs -----------------------------------------
    ("token-logged",                   "info-disclosure",         "CWE-532"),  # 24 hits/scan
    ("logger_leak",                    "info-disclosure",         "CWE-532"),
    ("logger-leak",                    "info-disclosure",         "CWE-532"),
    ("credential-disclosure",          "info-disclosure",         "CWE-532"),
    ("stacktrace-in-response",         "info-disclosure",         "CWE-209"),
    # --- timing-attack ----------------------------------------------------
    ("observable_timing",              "timing-attack",           "CWE-208"),
    ("observable-timing",              "timing-attack",           "CWE-208"),
    ("timing-attack",                  "timing-attack",           "CWE-208"),
    # --- input validation --------------------------------------------------
    ("unvalidated-json-message",       "input-validation",        "CWE-20"),
    ("unvalidated_input",              "input-validation",        "CWE-20"),
    # --- prompt-injection (LLM) -------------------------------------------
    ("prompt-injection",               "prompt-injection",        None),
    ("prompt_injection",               "prompt-injection",        None),
    ("llm.prompt-injection",           "prompt-injection",        None),
    # --- gosec numeric rules ----------------------------------------------
    ("g101",                           "secrets",                 "CWE-798"),  # gosec hardcoded creds
    ("g104",                           "error-handling",          "CWE-252"),  # unchecked errors
    ("g115",                           "integer-overflow",        "CWE-190"),  # integer overflow
    ("g301",                           "insecure-permissions",    "CWE-732"),  # dir permissions
    ("g302",                           "insecure-permissions",    "CWE-732"),  # chmod permissions
    ("g306",                           "insecure-permissions",    "CWE-732"),  # write file perms
    ("g307",                           "insecure-permissions",    "CWE-732"),
    ("g601",                           "correctness",             "CWE-758"),  # memory aliasing in range
    # --- Go correctness bugs -----------------------------------------------
    ("exported_loop_pointer",          "correctness",             "CWE-758"),  # 81 hits/scan
    ("exported-loop-pointer",          "correctness",             "CWE-758"),
    ("memory_aliasing",                "correctness",             "CWE-758"),
    ("memory-aliasing",                "correctness",             "CWE-758"),
    ("incorrect-default-permission",   "insecure-permissions",    "CWE-732"),
    # --- skylos ------------------------------------------------------------
    ("sky-d211",                       "sql-injection",           "CWE-89"),
    ("sky-d217",                       "sql-injection",           "CWE-89"),
    ("sky-d215",                       "path-traversal",          "CWE-22"),
    ("sky-d325",                       "path-traversal",          "CWE-22"),
    ("sky-d216",                       "ssrf",                    "CWE-918"),
    ("sky-d213",                       "command-injection",       "CWE-78"),
    ("sky-d218",                       "insecure-deserialization","CWE-502"),
    ("sky-d222",                       "hallucinated-dep",        None),
    ("sky-d223",                       "missing-dep",             None),
    ("sky-l012",                       "undefined-import",        None),
    ("sky-u-",                         "dead-code",               None),
    ("unused_function",                "dead-code",               None),
    ("unused_class",                   "dead-code",               None),
    ("unused_import",                  "dead-code",               None),
    ("unused_variable",                "dead-code",               None),
    ("unused_parameter",               "dead-code",               None),
    ("unused_file",                    "dead-code",               None),
]

# Free-text keywords in message/rule_id -> category. Only used when CWE and
# rule_id patterns didn't match; safeguards against over-eager bucketing.
CATEGORY_KEYWORDS: Dict[str, List[str]] = {
    "secrets": [
        "api key", "api_key", "apikey", "hardcoded secret", "hardcoded password",
        "hardcoded key", "hardcoded token", "generic api key", "aws access key",
        "google api key", "secret detected", "leaked credential", "access token",
        "bearer token",
    ],
    "sql-injection":   ["sql injection", "sql inject"],
    "xss":             ["cross-site scripting", "cross site scripting"],
    "path-traversal":  ["path traversal", "directory traversal", "path injection"],
    "command-injection": ["command injection", "shell injection", "os.system", "shell=true"],
    "insecure-deserialization": ["insecure deserialization", "unsafe deserialization",
                                 "pickle.load", "yaml.load"],
    "weak-crypto":     ["weak hash", "weak cipher", "insecure hash", "insecure cipher",
                        "broken crypto"],
    "weak-random":     ["weak random", "insecure random", "predictable random"],
    "insecure-tls":    ["tls verification", "certificate verification", "verify=false",
                        "sslv2", "sslv3"],
    "assert-used":     ["assert statement", "assert used"],
}


def infer_cwe(rule_id: Optional[str]) -> Optional[str]:
    """Return the CWE argus knows for `rule_id` — or None.

    Called by the scanner parsers when the scanner itself didn't attach a
    CWE to the finding (which is ~98% of the time in practice — scanners
    ship rules faster than they tag CWE metadata). The resulting CWE feeds
    infer_category via CWE_TO_CATEGORY, and also lands in the SARIF /
    findings.csv output so downstream triage can filter by CWE."""
    rid = (rule_id or "").lower()
    if not rid:
        return None
    for entry in RULE_ID_CATEGORY_PATTERNS:
        # Entries are (needle, category, cwe). Skip cwe-less entries.
        if len(entry) < 3 or entry[2] is None:
            continue
        needle = entry[0]
        if needle in rid:
            return entry[2]
    return None


# Rule-id substring → concrete remediation snippet. Keyed by the same
# substring convention as RULE_ID_CATEGORY_PATTERNS. First match wins.
# Every entry should give a copy-pasteable fix, not just "sanitize input".
REMEDIATION_TEMPLATES: List[tuple] = [
    # --- secrets / credentials --------------------------------------------
    ("hardcoded_secret",
     "Move the value to an environment variable or KMS-managed secret. "
     "Reference it as ${VAR_NAME} in this config file so deployment "
     "substitutes at runtime and the value never lives in source."),
    ("hardcoded-secret",
     "Move the value to an environment variable or KMS-managed secret. "
     "Reference it as ${VAR_NAME} in this config file so deployment "
     "substitutes at runtime and the value never lives in source."),
    ("leak-",
     "Rotate the credential immediately (it's now in git history). "
     "Then replace with a ${VAR} substitution loaded from a secret manager."),
    ("hardcoded_password", "See `hardcoded-secret` remediation above."),
    ("dev-qa-token-accepted-in-prod",
     "Remove DEV_TOKEN / QA_TOKEN / STAGING_TOKEN entries from production "
     "app-token configs. Production should only accept prod-scoped tokens; "
     "dev/qa/staging tokens are for their respective environments."),
    # --- injection --------------------------------------------------------
    ("sql_injection",
     "Use parameterized queries. e.g. `session.execute(text('SELECT * FROM t "
     "WHERE id = :id'), {'id': user_id})` (SQLAlchemy) or "
     "`stmt.setString(1, userId)` (JDBC PreparedStatement). Never build the "
     "query string via `+` or f-string interpolation on user input."),
    ("sql-injection",
     "Use parameterized queries — see `sql_injection` remediation above."),
    ("sqli", "See `sql-injection` remediation above."),
    ("command_injection",
     "Never pass user input to a shell. Use argv-form exec: "
     "`subprocess.run(['git', 'clone', repo_url], shell=False)` — no `shell=True`. "
     "If a shell is unavoidable, shlex.quote() every user-controlled value."),
    ("command-injection", "See `command_injection` remediation above."),
    ("path_traversal",
     "Canonicalize the path with `os.path.realpath()` / `Path.resolve()` and "
     "verify it stays inside the intended base dir. Reject any path with "
     "`..`, absolute paths, or symlinks pointing outside base."),
    ("path-traversal", "See `path_traversal` remediation above."),
    ("g304",
     "Wrap file path in `filepath.Clean()` and verify it stays inside an "
     "allowed base directory: `if !strings.HasPrefix(clean, base) { reject }`. "
     "For inputs from HTTP requests, add an allowlist of file names."),
    # --- SSRF -------------------------------------------------------------
    ("ssrf",
     "Validate the URL host against an allowlist. Resolve DNS and reject "
     "private/link-local/loopback IPs (10.0/8, 172.16/12, 192.168/16, "
     "127/8, 169.254/16). Disallow file://, gopher://, dict:// schemes. "
     "Disable redirect following or re-validate after each redirect."),
    ("ssrf-tainted-url", "See `ssrf` remediation above."),
    # --- deserialization --------------------------------------------------
    ("deserialization",
     "Replace Java native serialization with JSON / Protobuf. If you must "
     "keep ObjectInputStream, add ObjectInputFilter (Java 9+): "
     "`ois.setObjectInputFilter(ObjectInputFilter.allowFilter(cls -> "
     "ALLOWED.contains(cls.getName()), ObjectInputFilter.Status.REJECTED));`"),
    ("objectinputstream", "See `deserialization` remediation above."),
    ("jackson-enable-default-typing",
     "Replace `enableDefaultTyping()` / `activateDefaultTyping()` with "
     "explicit `@JsonTypeInfo(use = Id.NAME)` + `@JsonSubTypes({...})` "
     "declaring an allowlist of expected subtypes. If polymorphism is "
     "unavoidable, use a strict `PolymorphicTypeValidator`."),
    ("pickle",
     "Never pickle.loads() untrusted bytes — pickle allows arbitrary code "
     "execution by design. Switch to JSON for cross-service payloads."),
    ("yaml_load",
     "Use `yaml.safe_load()` instead of `yaml.load()` — the default loader "
     "instantiates arbitrary Python objects."),
    # --- crypto -----------------------------------------------------------
    ("weak_hash",
     "Replace MD5/SHA1 with SHA-256/SHA-3 for integrity, and bcrypt/argon2 "
     "for passwords. MD5 has practical collisions; SHA1 is deprecated."),
    ("md5", "See `weak_hash` remediation above."),
    ("sha1", "See `weak_hash` remediation above."),
    # --- TLS --------------------------------------------------------------
    ("usessl-false",
     "Change JDBC URL to `useSSL=true&requireSSL=true&"
     "verifyServerCertificate=true`. Ensure the DB server has TLS enabled "
     "and the client trust-store includes the DB certificate CA."),
    ("usessl_false", "See `usessl-false` remediation above."),
    ("verify=false",
     "Never disable TLS verification in production. Add the server's CA to "
     "the client trust store: `requests.get(url, verify='/path/to/ca.pem')`."),
    ("insecure_ssl", "See `verify=false` remediation above."),
    # --- code execution ---------------------------------------------------
    ("code_injection",
     "Remove eval()/exec()/Function() on user input. Refactor to a whitelist "
     "of allowed operations (e.g. Map<String, Handler> dispatch)."),
    ("log4j-message-lookup-injection",
     "Upgrade log4j to >= 2.17.0 AND set `-Dlog4j2.formatMsgNoLookups=true`. "
     "Never log request headers/bodies/tokens directly — log a request id "
     "and look up the value out-of-band via structured tracing."),
    ("spring-spel-tainted-input",
     "Don't evaluate user input as SpEL. If you must parse expressions, "
     "use `SimpleEvaluationContext.forReadOnlyDataBinding().build()` and "
     "validate input against an allowlist first."),
    ("unsafe-reflection-class-forname",
     "Replace `Class.forName(userInput)` with a Map<String, Supplier<T>> or "
     "a switch statement over a known allowlist of type names."),
    # --- XXE --------------------------------------------------------------
    ("xxe-java-",
     "Before creating the parser/builder, disable DTD and external entities: "
     "`dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", "
     "true);` (recommended) or the full OWASP-safe combination — see "
     "OWASP XXE Prevention Cheat Sheet."),
    # --- access-control ---------------------------------------------------
    ("idor-handler-fetch-by-id-no-authz",
     "Add an ownership check before the DB fetch: "
     "`authz.CheckOwnership(ctx, id)` (Go) or scope the query itself: "
     "`db.Where(\"id = ? AND owner_id = ?\", id, currentUserId).First(&obj)`."),
    ("handler-missing-authz-annotation",
     "Annotate the handler with `@RolesAllowed({\"role\"})` (JAX-RS) / "
     "`@PreAuthorize(\"hasRole('ROLE')\")` (Spring). If the endpoint is "
     "intentionally public, mark it explicitly with `@PermitAll` so future "
     "reviewers know the omission was deliberate."),
    # --- info-disclosure --------------------------------------------------
    ("token-logged",
     "Don't log secrets. Log a fingerprint (SHA-256 first 8 hex chars) or "
     "the token id, not the token itself. Add a redactor at the log-appender "
     "layer that masks `Bearer <...>` and `password=...`."),
    ("logger_leak", "See `token-logged` remediation above."),
    # --- misconfig --------------------------------------------------------
    ("beego-runmode-dev-in-prod",
     "Change `runmode` to `\"prod\"` in production configs. Dev mode enables "
     "stack traces, swagger UI, and pprof."),
    ("beego-admin-enabled-in-prod",
     "Set `enableadmin: false` in production configs — the admin endpoints "
     "(pprof, /listconf, /healthcheck, /routers) leak runtime state and "
     "should never be network-reachable in prod."),
    # --- Added 2026-09-23 for the additional-coverage rulepack -----------
    ("jwt-decode-without-verification",
     "Always verify the JWT signature. PyJWT: `jwt.decode(token, key=SECRET, "
     "algorithms=['HS256'])`. node-jsonwebtoken: `jwt.verify(token, secret, "
     "{ algorithms: ['HS256'] })`. Nimbus (Java): `SignedJWT.parse(t).verify(new "
     "MACVerifier(secret))` then check the returned bool. Never use `.decode()`, "
     "`get_unverified_claims`, or `Parse(t, nil)` on user-supplied tokens."),
    ("unrestricted-file-upload",
     "(1) Sanitize the filename: `secure_filename(name)` (Werkzeug) / "
     "`filepath.Base(name)` (Go) / `basename($name)` (PHP) — strips path "
     "components. (2) Validate extension against a strict allowlist. "
     "(3) Verify actual content with server-side magic-byte sniff (Apache "
     "Tika / python-magic) — NEVER trust the Content-Type header. "
     "(4) Enforce max file size upfront. (5) Store with a server-side name "
     "(UUID) so client input never becomes a filesystem path component."),
    ("hmac-comparison-non-constant-time",
     "Replace `==` / `.equals()` with a constant-time compare. Python: "
     "`hmac.compare_digest(expected, actual)`. Node: `crypto.timingSafeEqual("
     "Buffer.from(a), Buffer.from(b))`. Java: `MessageDigest.isEqual(a, b)`. "
     "Go: `subtle.ConstantTimeCompare(a, b) == 1` from `crypto/subtle`."),
    ("hardcoded-crypto-iv",
     "Generate a fresh cryptographically random IV / nonce per message: "
     "Python `os.urandom(12)` for GCM / `os.urandom(16)` for CBC. Java "
     "`byte[] iv = new byte[12]; new SecureRandom().nextBytes(iv);`. Node "
     "`crypto.randomBytes(12)`. Go `rand.Read(iv)` from `crypto/rand`. "
     "Prepend the IV to the ciphertext — IVs are public, they only need "
     "to be unique per (key, message)."),
]


def infer_remediation(rule_id: Optional[str]) -> str:
    """Return the first matching remediation template for `rule_id`, or empty
    string if the rule is not in our template list. Called at parse time to
    populate Finding.remediation before dedup / severity upgrade / report."""
    rid = (rule_id or "").lower()
    if not rid:
        return ""
    for needle, text in REMEDIATION_TEMPLATES:
        if needle in rid:
            return text
    return ""


def infer_category(rule_id: str, message: str, cwe: Optional[str]) -> Optional[str]:
    """Return a coarse category slug for a finding, or None if unclassifiable.

    Precedence: CWE -> rule_id substring -> keyword scan of the message.
    Anything unclassifiable stays outside the second-pass dedup, so it can
    never trigger an over-merge. Prefer calling with an already-populated
    `cwe` (either scanner-provided or backfilled by infer_cwe) so the CWE
    branch fires first and hits the CWE_TO_CATEGORY fast path."""
    if cwe:
        c = CWE_TO_CATEGORY.get(cwe.strip().upper())
        if c:
            return c
    rid = (rule_id or "").lower()
    for entry in RULE_ID_CATEGORY_PATTERNS:
        needle, cat = entry[0], entry[1]
        if needle in rid:
            return cat
    msg = (message or "").lower()
    for cat, needles in CATEGORY_KEYWORDS.items():
        if any(n in msg for n in needles):
            return cat
    return None


# --------------------------------------------------------------------------------------
# Finding model
# --------------------------------------------------------------------------------------

@dataclasses.dataclass
class Finding:
    scanner: str
    rule_id: str
    message: str
    severity: str          # unified: CRITICAL/HIGH/MEDIUM/LOW/INFO
    path: str              # normalized, relative to scan root when possible
    start_line: int
    end_line: int
    cwe: Optional[str] = None
    sources: List[str] = dataclasses.field(default_factory=list)  # ["semgrep:rule", ...]
    snippet: str = ""      # the actual vulnerable code (from the tool, else read from disk)
    status: str = "open"          # open | false_positive | accepted_risk | wont_fix
    suppress_reason: str = ""     # triage note explaining why the finding was suppressed
    category: str = ""            # coarse weakness bucket (secrets / xss / ...); "" = unclassified
    # Fix F (2026-09-23): concrete remediation guidance for this rule id.
    # Populated by REMEDIATION_TEMPLATES at parse time when the rule id maps
    # to a known fix; empty otherwise. Surfaces in findings.csv / .xlsx /
    # merged.sarif so reviewers see the fix inline with the bug.
    remediation: str = ""
    # Fix A (2026-09-23): when the same rule fires multiple times on the same
    # file, the file-rule roll-up pass collapses them into a single row and
    # lists the extra line numbers here. `start_line` remains the first (or
    # canonical) hit; `occurrences` extends the reader's view without them
    # having to open raw_findings.json.
    occurrences: List[int] = dataclasses.field(default_factory=list)

    def fingerprint(self) -> str:
        """
        Deterministic cross-scanner fingerprint = rule/CWE + location.
        (The architecture's 'fingerprint = rule + normalized location + snippet hash';
        snippet is not always available across tools, so we key on rule/CWE + file + line.)
        """
        rule_token = (self.cwe or self.rule_id.split(".")[-1] or self.rule_id).lower().strip()
        key = f"{self.path}|{self.start_line}|{rule_token}"
        return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]


# --------------------------------------------------------------------------------------
# Output parsers (SARIF is the common case; Bandit uses JSON)
# --------------------------------------------------------------------------------------

def _rel(path: str, root: Path) -> str:
    if not path:
        return path
    p = path.replace("file://", "")
    try:
        return str(Path(p).resolve().relative_to(root.resolve()))
    except Exception:
        return p.lstrip("./")


_SNIPPET_MAX_LINES = 20
_SNIPPET_MAX_CHARS = 2000
_SNIPPET_FILE_CACHE: Dict[str, List[str]] = {}


def _read_snippet(root: Path, rel_path: str, start_line: int, end_line: int) -> str:
    """Fallback: read lines [start_line, end_line] from disk when the scanner didn't ship a snippet."""
    if not rel_path or start_line <= 0:
        return ""
    p = Path(rel_path)
    if not p.is_absolute():
        p = root / rel_path
    key = str(p)
    lines = _SNIPPET_FILE_CACHE.get(key)
    if lines is None:
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            lines = []
        _SNIPPET_FILE_CACHE[key] = lines
    if not lines:
        return ""
    end = max(end_line, start_line)
    end = min(end, start_line + _SNIPPET_MAX_LINES - 1, len(lines))
    start = min(start_line, len(lines))
    text = "\n".join(lines[start - 1:end])
    if len(text) > _SNIPPET_MAX_CHARS:
        text = text[:_SNIPPET_MAX_CHARS] + " ...[truncated]"
    return text


def format_snippet_with_lines(snippet: str, start_line: int) -> str:
    """Render the vulnerable code with its real line numbers, e.g. '  42 | code'."""
    if not snippet:
        return ""
    base = max(start_line, 1)
    return "\n".join(
        f"{base + i:>5} | {line}" for i, line in enumerate(snippet.splitlines())
    )


def _cwe_from_tags(tags: Sequence[str]) -> Optional[str]:
    for t in tags or []:
        tu = str(t).upper().replace("_", "-")
        if tu.startswith("CWE-"):
            return tu.split(":")[0].strip()
        if tu.startswith("EXTERNAL/CWE/CWE-"):
            return "CWE-" + tu.rsplit("CWE-", 1)[-1]
    return None


def parse_sarif(out_path: Path, scanner: str, root: Path) -> List[Finding]:
    findings: List[Finding] = []
    # Fast path: a SARIF file with no findings is a well-formed skeleton
    # ({"$schema":..., "version":"2.1.0", "runs":[{"tool":..., "results":[]}]})
    # around ~250 bytes. Anything below that either has no results or is
    # truncated; either way, json.loads + the "runs -> results" walk are pure
    # overhead. Guard here so parse cost stays near zero for silent scanners.
    try:
        size = out_path.stat().st_size
    except OSError:
        return findings
    if size < 220:
        return findings
    try:
        data = json.loads(out_path.read_text(encoding="utf-8"))
    except Exception as e:
        log.warning("[%s] could not read SARIF %s: %s", scanner, out_path, e)
        return findings

    for run in data.get("runs", []):
        # index rule metadata for defaults (level / security-severity / cwe)
        rule_meta: Dict[str, dict] = {}
        driver = (run.get("tool") or {}).get("driver") or {}
        for rule in driver.get("rules", []) or []:
            rid = rule.get("id") or rule.get("name")
            if rid:
                rule_meta[rid] = rule

        for res in run.get("results", []) or []:
            # semgrep's mangled rule id (bundle-path prefix + sentinel-wrapped
            # namespace + original id). Keep this shape for the rule_meta
            # lookup because rule_meta is keyed by the SAME mangled id — the
            # SARIF driver.rules block uses semgrep's own id directly.
            raw_rid = res.get("ruleId") or (res.get("rule") or {}).get("id") or "unknown"
            meta = rule_meta.get(raw_rid, {})
            # Unwind bundle rewriting for the finding's downstream id: bundled
            # rules ship as
            #   <BUNDLE_NS_START>.<original_ns>.<BUNDLE_NS_END>.<original_id>
            # and semgrep further prepends the bundle file's absolute path as
            # dots. Reading between the sentinels gives us back the pre-bundle
            # rule id shape so cross-scanner dedup, FP filters and CRITICAL
            # promotion hints match. `meta` above is already resolved — that
            # lookup MUST happen before the rewrite.
            rid = raw_rid
            start_tok = f".{BUNDLE_NS_START}."
            end_tok = f".{BUNDLE_NS_END}."
            i_start = rid.find(start_tok)
            if i_start == -1 and rid.startswith(f"{BUNDLE_NS_START}."):
                # No leading dot when semgrep didn't add a path prefix.
                i_start = 0
                start_len = len(BUNDLE_NS_START) + 1
            else:
                start_len = len(start_tok)
            if i_start != -1:
                after_start = rid[i_start + start_len:]
                i_end = after_start.find(end_tok)
                if i_end != -1:
                    ns_between = after_start[:i_end]
                    original_id = after_start[i_end + len(end_tok):]
                    rid = f"{ns_between}.{original_id}" if ns_between else original_id

            # message
            msg = ""
            m = res.get("message") or {}
            if isinstance(m, dict):
                msg = m.get("text") or m.get("markdown") or ""
            msg = (msg or meta.get("shortDescription", {}).get("text", "") or rid).strip()

            # location
            path, sl, el = "", 0, 0
            snippet = ""
            locs = res.get("locations") or []
            if locs:
                pl = (locs[0].get("physicalLocation") or {})
                art = (pl.get("artifactLocation") or {})
                path = art.get("uri") or ""
                region = pl.get("region") or {}
                sl = int(region.get("startLine", 0) or 0)
                el = int(region.get("endLine", sl) or sl)
                # Prefer scanner-provided snippet; fall back to contextRegion.
                snippet = ((region.get("snippet") or {}).get("text") or "").strip()
                if not snippet:
                    ctx = (pl.get("contextRegion") or {}).get("snippet") or {}
                    snippet = (ctx.get("text") or "").strip()
            path = _rel(path, root)
            if not snippet:
                snippet = _read_snippet(root, path, sl, el)

            # severity: prefer numeric security-severity, else level, else rule default
            sev = None
            props = res.get("properties") or {}
            ss = props.get("security-severity") or (meta.get("properties") or {}).get("security-severity")
            if ss is not None:
                try:
                    sev = sev_from_security_severity(float(ss))
                except (TypeError, ValueError):
                    sev = None
            if sev is None:
                lvl = res.get("level") or meta.get("defaultConfiguration", {}).get("level")
                sev = sev_from_sarif_level(lvl) if lvl else "MEDIUM"

            # CWE from tags/taxa; if the scanner didn't tag one, backfill from
            # argus's rule-id → CWE mapping so downstream dedup / SARIF export
            # / severity-upgrade rules all see a CWE for known rule shapes.
            tags = (props.get("tags") or []) + ((meta.get("properties") or {}).get("tags") or [])
            cwe = _cwe_from_tags(tags) or infer_cwe(str(rid))

            findings.append(Finding(
                scanner=scanner, rule_id=str(rid), message=msg, severity=sev,
                path=path, start_line=sl, end_line=el, cwe=cwe,
                sources=[f"{scanner}:{rid}"], snippet=snippet,
                category=infer_category(str(rid), msg, cwe) or "",
                remediation=infer_remediation(str(rid)),
            ))
    return findings


def parse_bandit_json(out_path: Path, scanner: str, root: Path) -> List[Finding]:
    findings: List[Finding] = []
    # Same rationale as parse_sarif: bandit emits an envelope even with no
    # results; a real hit adds several KB. Bail out before loading the JSON
    # if there's nothing worth parsing.
    try:
        size = out_path.stat().st_size
    except OSError:
        return findings
    if size < 200:
        return findings
    try:
        data = json.loads(out_path.read_text(encoding="utf-8"))
    except Exception as e:
        log.warning("[%s] could not read JSON %s: %s", scanner, out_path, e)
        return findings
    for r in data.get("results", []) or []:
        sl = int(r.get("line_number", 0) or 0)
        rng = r.get("line_range") or [sl]
        el = int(rng[-1]) if rng else sl
        cwe = None
        c = r.get("issue_cwe") or {}
        if isinstance(c, dict) and c.get("id"):
            cwe = f"CWE-{c['id']}"
        # Bandit populates CWE for most B1xx-B7xx rules, but not always;
        # backfill from argus's rule-id map for the miss cases.
        if not cwe:
            cwe = infer_cwe(str(r.get("test_id") or r.get("test_name") or ""))
        rel_path = _rel(r.get("filename", ""), root)
        # Prefer reading the exact lines from disk: bandit's own "code" field is
        # pre-numbered context (line before/after), which would misalign the
        # line-numbered vulnerable_code output. Fall back to it, de-numbered.
        snippet = _read_snippet(root, rel_path, sl, el)
        if not snippet:
            raw = (r.get("code") or "").strip()
            cleaned = []
            for ln in raw.splitlines():
                num, _, rest = ln.partition(" ")
                cleaned.append(rest if num.isdigit() else ln)
            snippet = "\n".join(cleaned)
        rid = r.get("test_id") or r.get("test_name") or "bandit"
        msg = (r.get("issue_text") or "").strip()
        findings.append(Finding(
            scanner=scanner,
            rule_id=rid,
            message=msg,
            severity=norm_severity(r.get("issue_severity")) or "MEDIUM",
            path=rel_path,
            start_line=sl, end_line=el, cwe=cwe,
            sources=[f"{scanner}:{r.get('test_id')}"], snippet=snippet,
            category=infer_category(rid, msg, cwe) or "",
            remediation=infer_remediation(rid),
        ))
    return findings


PARSERS: Dict[str, Callable[[Path, str, Path], List[Finding]]] = {
    "sarif": parse_sarif,
    "bandit-json": parse_bandit_json,
}

# --------------------------------------------------------------------------------------
# Scanner adapters
# --------------------------------------------------------------------------------------

ALL_LANGS = "ALL"


@dataclasses.dataclass
class Adapter:
    name: str
    binary: str
    languages: object                 # ALL_LANGS or set[str]
    fmt: str                          # key into PARSERS
    # cmd is built from a template; {target} and {output} are substituted.
    cmd_template: List[str]
    out_ext: str = "sarif"
    target_override: Optional[str] = None   # e.g. gosec wants "./..."
    run_in_target_cwd: bool = False         # e.g. gosec must run inside the module
    # If True, `{output}` is materialised as a hidden dotfile inside the
    # target dir. The runner (`run_adapter`) moves it to the canonical
    # `out_dir/<name>.<ext>` location after the scan completes. This exists
    # for scanners like skylos whose --sarif flag refuses to write outside
    # the workspace being scanned.
    stage_output_in_target: bool = False
    # If set, the scanner writes to a directory (not a single file) and picks
    # its own filename inside it (e.g. `scan-<timestamp>.json`). The runner
    # substitutes {output_dir} in the cmd template with `out_dir`, and after
    # the scan finishes it globs for `output_glob_fallback` inside that
    # directory and renames the newest match to the canonical
    # `out_dir/<name>.<ext>` argus expects.
    output_glob_fallback: Optional[str] = None
    install_hint: str = ""

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def applies_to(self, langs: Set[str]) -> bool:
        if self.languages == ALL_LANGS:
            return bool(langs)
        return bool(self.languages & langs)

    def staged_output_path(self, target: Path) -> Path:
        """Path used at scan time when stage_output_in_target=True."""
        return target / f".argus_{self.name}.{self.out_ext}"

    def build_cmd(self, target: Path, output: Path,
                  extra_configs: Optional[Sequence[str]] = None,
                  exclude_rules: Optional[Sequence[str]] = None,
                  jobs: Optional[int] = None) -> List[str]:
        tgt = self.target_override if self.target_override else str(target)
        # For scanners that refuse to write outside their workspace, the
        # visible command line points at a hidden file inside the target;
        # run_adapter moves it to `output` after the scan finishes.
        out = str(self.staged_output_path(target) if self.stage_output_in_target
                  else output)
        # Some scanners expect an output DIRECTORY and pick their own
        # timestamped filename inside it (paired with output_glob_fallback
        # below). `{output_dir}` gives them the parent of the canonical
        # `{output}` file, which is always the per-repo reports dir argus
        # already creates.
        out_dir_str = str(output.parent)
        cmd = [tok.replace("{target}", tgt)
                  .replace("{output_dir}", out_dir_str)
                  .replace("{output}", out)
               for tok in self.cmd_template]
        if extra_configs:
            # Splice extra --config args immediately after the last existing
            # --config in the template. For adapters whose template has no
            # --config (bandit, gosec, ...) the extras are silently ignored:
            # they're only meaningful to the semgrep-family scanners.
            last_cfg = max((i for i, tok in enumerate(cmd) if tok == "--config"),
                           default=-1)
            if last_cfg >= 0:
                insert_at = last_cfg + 2
                for cfg in reversed(list(extra_configs)):
                    cmd[insert_at:insert_at] = ["--config", str(cfg)]
        # --exclude-rule <id> is a semgrep-family flag (semgrep + opengrep).
        # Skip silently on other scanners since it would be an unknown flag.
        # Inserted just before the target token so the CLI is well-formed.
        if exclude_rules and self.name in SEMGREP_FAMILY_ADAPTERS:
            # Locate the trailing {target} — always the last token in the
            # semgrep/opengrep templates.
            insert_at = len(cmd) - 1
            if insert_at < 0 or cmd[insert_at] != tgt:
                insert_at = len(cmd)
            for rid in reversed(list(exclude_rules)):
                cmd[insert_at:insert_at] = ["--exclude-rule", str(rid)]
        # Cap per-scanner parallelism so N scanners running side-by-side don't
        # each grab all cores and thrash on context-switches. Semgrep-family
        # uses --jobs; bearer uses --parallel; others (bandit/gosec/drogonsec/
        # skylos) have no equivalent flag or default to 1, so we skip them.
        if jobs and jobs >= 1:
            if self.name in SEMGREP_FAMILY_ADAPTERS:
                insert_at = len(cmd) - 1
                if insert_at < 0 or cmd[insert_at] != tgt:
                    insert_at = len(cmd)
                cmd[insert_at:insert_at] = ["--jobs", str(jobs)]
            elif self.name == "bearer":
                cmd.extend(["--parallel", str(jobs)])
        return cmd


# Default registry. Commands aim at current CLIs; override via --config if yours differ.
ADAPTERS: List[Adapter] = [
    Adapter(
        name="semgrep", binary="semgrep", languages=ALL_LANGS, fmt="sarif",
        # NOTE: `--config auto` requires metrics on; we use explicit registry
        # packs so `--metrics=off` is compatible. Loading multiple packs is
        # additive — semgrep aggregates rules from every --config.
        #   p/default        : the base pack (~340 rules). Restored 2026-09
        #                      after a cross-repo comparison showed derawan-oms
        #                      lost coverage without it — not a strict subset
        #                      of p/security-audit.
        #   p/security-audit : broader audit ruleset.
        #   p/secrets        : dedicated secret-scanning rules.
        # The bundled sast_rulepack.yml (next to this script) is appended at
        # module-init time when the file exists — see below the ADAPTERS list.
        # --exclude patterns skip prior SAST output and vendored code so scans
        # don't waste time re-processing files that would be dropped by the
        # auto-FP filter anyway. Repeat --exclude as needed for extra dirs.
        cmd_template=["semgrep", "scan",
                      "--config", "p/default",
                      "--config", "p/security-audit",
                      "--config", "p/secrets",
                      "--sarif", "--sarif-output={output}",
                      "--metrics=off", "--quiet",
                      "--exclude=sast_reports", "--exclude=SAST_Scan",
                      "--exclude=sast-reports", "--exclude=site-packages",
                      "--exclude=.venv", "--exclude=venv", "--exclude=env",
                      "--exclude=node_modules", "--exclude=vendor",
                      "--exclude=dist", "--exclude=build", "--exclude=target",
                      "--exclude=__pycache__", "--exclude=.tox",
                      "--exclude=.terraform", "--exclude=*.min.js",
                      "--exclude=*.min.css", "--exclude=*.sarif",
                      "{target}"],
        install_hint="pip install semgrep",
    ),
    Adapter(
        name="opengrep", binary="opengrep", languages=ALL_LANGS, fmt="sarif",
        # opengrep is a semgrep fork; --exclude and --config use the same
        # semantics. The bundled sast_rulepack.yml is appended below when
        # present.
        cmd_template=["opengrep", "scan",
                      "--config", "auto",
                      "--sarif-output={output}", "--quiet",
                      "--exclude=sast_reports", "--exclude=SAST_Scan",
                      "--exclude=sast-reports", "--exclude=site-packages",
                      "--exclude=.venv", "--exclude=venv", "--exclude=env",
                      "--exclude=node_modules", "--exclude=vendor",
                      "--exclude=dist", "--exclude=build", "--exclude=target",
                      "--exclude=__pycache__", "--exclude=.tox",
                      "--exclude=.terraform", "--exclude=*.min.js",
                      "--exclude=*.min.css", "--exclude=*.sarif",
                      "{target}"],
        install_hint="https://github.com/opengrep/opengrep (adjust --config to your ruleset)",
    ),
    Adapter(
        name="bandit", binary="bandit", languages={"python"}, fmt="bandit-json",
        # -x takes a comma-separated list of fnmatch patterns; bare names match
        # any directory of that name in the tree.
        cmd_template=["bandit", "-r", "{target}", "-f", "json", "-o", "{output}", "-q",
                      "-x",
                      "sast_reports,SAST_Scan,sast-reports,site-packages,"
                      ".venv,venv,env,node_modules,vendor,dist,build,target,"
                      "__pycache__,.tox,.terraform,tests,test"],
        out_ext="json",
        install_hint="pip install bandit",
    ),
    Adapter(
        name="bearer", binary="bearer",
        languages={"javascript", "typescript", "ruby", "java", "php", "go", "python"},
        fmt="sarif",
        # bearer's --skip-path takes ONE comma-separated string (not the
        # repeated flag semgrep uses). Same directory list as semgrep's
        # --exclude set so both scanners ignore the same build artifacts,
        # vendored deps, prior SAST output and virtualenvs. Cut bearer
        # wall-clock significantly on repos with big target/ or vendor/
        # trees (a Java repo's `target/` after mvn package is often the
        # biggest thing bearer scans).
        cmd_template=["bearer", "scan", "{target}", "--format", "sarif",
                      "--output", "{output}", "--quiet", "--exit-code", "0",
                      "--skip-path",
                      "sast_reports,SAST_Scan,sast-reports,site-packages,"
                      ".venv,venv,env,node_modules,vendor,dist,build,target,"
                      "__pycache__,.tox,.terraform,.git,tests,test,"
                      "**/target/**,**/node_modules/**,**/vendor/**,"
                      "**/build/**,**/dist/**,**/.git/**,**/*.min.js,"
                      "**/*.min.css"],
        install_hint="https://github.com/Bearer/bearer",
    ),
    Adapter(
        name="gosec", binary="gosec", languages={"go"}, fmt="sarif",
        cmd_template=["gosec", "-fmt", "sarif", "-out", "{output}", "-no-fail", "-quiet", "{target}"],
        target_override="./...", run_in_target_cwd=True,
        install_hint="go install github.com/securego/gosec/v2/cmd/gosec@latest",
    ),
    Adapter(
        name="drogonsec", binary="drogonsec", languages=ALL_LANGS, fmt="sarif",
        cmd_template=["drogonsec", "scan", "{target}", "--format", "sarif", "--output", "{output}"],
        install_hint="https://github.com/filipi86/drogonsec",
    ),
    Adapter(
        # skylos brings four bug classes the other scanners are blind to:
        #   SSRF taint tracking, hallucinated PyPI deps, undefined
        #   cross-module imports (SKY-L012), and dead code.
        # Kept scoped to Python for the first rollout — skylos claims broader
        # language support, but its security-flow rules are strongest there.
        name="skylos", binary="skylos", languages={"python"}, fmt="sarif",
        # --danger      → path-traversal / SSRF / injection / deserial (SKY-D2xx)
        # --ai-defects  → hallucinated deps + broken imports (SKY-D22x / L012)
        # --sca         → CVE-flagged dependencies (bytes overlap zero with argus)
        # NOTE: no --quality — that emits ~1500 type-annotation nags on a
        # 22 KLOC repo and would drown the dedup pass. If a downstream fleet
        # actually enforces mypy, expose it as a scanner-level opt-in later.
        # Skylos refuses to write --sarif outside its workspace, so we stage
        # the file inside the target and let run_adapter move it out.
        cmd_template=["skylos", "{target}",
                      "--danger", "--ai-defects", "--sca",
                      "--sarif", "{output}",
                      "--no-cache",
                      "--exclude", "sast_reports",
                      "--exclude", "SAST_Scan",
                      "--exclude", "sast-reports",
                      "--exclude", ".venv",
                      "--exclude", "venv",
                      "--exclude", "env",
                      "--exclude", "node_modules",
                      "--exclude", "vendor",
                      "--exclude", "dist",
                      "--exclude", "build",
                      "--exclude", "__pycache__",
                      "--exclude", ".tox",
                      "--exclude", "protobuf"],
        stage_output_in_target=True,
        install_hint="pip install skylos",
    ),
]

ADAPTERS_BY_NAME = {a.name: a for a in ADAPTERS}

# Adapters that accept semgrep's `--exclude-rule RULE_ID` flag (both semgrep
# itself and opengrep, which is a semgrep-engine fork). Used to gate the
# per-repo dead-rule exclude list (.argus-exclude-rules) so we don't hand
# an unknown flag to bandit / gosec / bearer / drogonsec.
SEMGREP_FAMILY_ADAPTERS: Set[str] = {"semgrep", "opengrep"}


# Global rule exclusion list — one file that ships alongside argus.py and
# applies to every scan. Rebuild it by running `--profile-rules` on a
# representative repo, then appending IDs of rules that measurably cost
# time and never produce findings on your typical stack. Format: one rule
# ID per line; `#` starts a comment; blank lines OK. Missing file = no
# exclusions.
#
# Kept in the argus folder (not the target repo) so scans never write or
# require config inside the code they're scanning.
EXCLUDE_RULES_PATH = SCRIPT_DIR / "argus_exclude_rules.txt"


def _load_exclude_rules() -> List[str]:
    """Read the global exclude list next to argus.py (EXCLUDE_RULES_PATH).

    Deduplicates preserving order; strips inline `# comments`. Missing file
    returns an empty list — the list is optional and only useful once a
    team has profiled a real scan and identified rules to drop."""
    if not EXCLUDE_RULES_PATH.is_file():
        return []
    excludes: List[str] = []
    seen: Set[str] = set()
    try:
        for raw_line in EXCLUDE_RULES_PATH.read_text(encoding="utf-8",
                                                     errors="replace").splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            if line not in seen:
                seen.add(line)
                excludes.append(line)
    except Exception as e:  # noqa: BLE001
        log.warning("could not read %s: %s", EXCLUDE_RULES_PATH, e)
        return []
    return excludes


# --------------------------------------------------------------------------------------
# Custom rulepack registry — language-filtered per repo
#
# Instead of mutating semgrep/opengrep's cmd_template at start-up (which forces
# every repo through every rule file), rulepack PATHS are registered once and
# resolved to a per-repo file list at scan time. The resolver reads each rule
# file's `languages:` field and drops files whose rules can't match any
# language present in the target repo. On a Go-only repo this means Java /
# Python / Swift rulepack files are never even parsed by semgrep — the scan is
# faster and the SARIF output is smaller.
#
# `_USER_RULEPACKS` is a list-preserving-order (auto-loaded default first,
# then --custom-rulepack args in the order given), so command output is
# deterministic.
# --------------------------------------------------------------------------------------

# --------------------------------------------------------------------------------------
# Semgrep Registry vendor-pack auto-loader
#
# Beyond the three packs baked into the semgrep/opengrep cmd_template
# (p/default, p/security-audit, p/secrets), the registry ships dozens of
# language- and framework-specific packs that are free to load. Wiring them to
# the framework detector means every repo automatically picks up the packs
# relevant to its stack — a Python + FastAPI project pulls p/python + p/fastapi;
# a Java project pulls p/java + p/insecure-transport; nobody hand-authored any
# of it, and the rules stay maintained by the ecosystem.
#
# Only packs verified to load with >0 rules against the current semgrep are
# listed. Non-existent packs (e.g. p/spring, p/log4j) are deliberately absent
# so we don't ship broken --config args downstream.
# --------------------------------------------------------------------------------------

# Always load these on every semgrep/opengrep invocation, regardless of what's
# in the repo. Covers OWASP Top 10, CWE Top 25, transport-layer weaknesses,
# and deep secret scanning.
#
# NOTE: p/sql-injection, p/command-injection and p/xss used to live here but
# were strict subsets of p/security-audit (loaded via the semgrep adapter
# template), so their rules were parsed twice per scan. Dropped 2026-09
# after profiling showed ~15s of duplicate rule-parse cost per run.
DEFAULT_VENDOR_PACKS: List[str] = [
    "p/owasp-top-ten",       # ~560 rules — broadest coverage across classes
    "p/cwe-top-25",          # ~216 rules — CWE-mapped
    "p/insecure-transport",  #  ~53 rules — TLS / verify=False / SSLv2/3
    "p/gitleaks",            # ~175 rules — deep secret detection
]

# language-tag -> [pack, ...]. Loaded when a language shows up in the repo.
# p/nodejsscan was previously listed under "python" — it targets Node.js
# source, not Python, so it loaded on any repo with a single .py file.
# Removed 2026-09 for the same profiling reason as the DEFAULT_VENDOR_PACKS
# cleanup above.
LANGUAGE_TO_VENDOR_PACKS: Dict[str, List[str]] = {
    "python":     ["p/python"],
    "javascript": ["p/javascript", "p/nodejsscan"],
    "typescript": ["p/typescript", "p/nodejsscan"],
    "java":       ["p/java"],
    "go":         ["p/gosec"],
    "kotlin":     ["p/kotlin"],
    "ruby":       ["p/ruby"],
    "php":        ["p/php"],
    "scala":      ["p/scala"],
    "csharp":     ["p/csharp"],
    "terraform":  ["p/terraform"],
    # YAML/Dockerfile packs are gated on real manifest presence by the
    # detect_infra_manifests() detector below — a Spring config yaml has
    # no business loading p/kubernetes; a repo with no Dockerfile
    # shouldn't pay for p/docker's parse cost.
}

# Infra-manifest tag -> [pack, ...]. Loaded only when detect_infra_manifests
# finds actual Kubernetes / Helm / Dockerfile content in the tree, replacing
# the old blanket "yaml file present => load p/kubernetes + p/dockerfile"
# behaviour (which fired for every repo with any CI or Spring config file).
INFRA_TO_VENDOR_PACKS: Dict[str, List[str]] = {
    "kubernetes": ["p/kubernetes"],
    "dockerfile": ["p/dockerfile"],
}

# Directory basenames whose presence anywhere in the tree strongly suggests
# Kubernetes / Helm manifests. Kept small on purpose — a false positive here
# loads a rulepack that finds nothing (mild cost); a false negative silently
# drops k8s coverage (real risk), so bias toward inclusion.
_K8S_DIR_HINTS = ("k8s", "kubernetes", "charts", "helm", "manifests")


def detect_infra_manifests(root: Path) -> Set[str]:
    """Return {'kubernetes'?, 'dockerfile'?} based on actual manifest presence.

    Used to gate p/kubernetes and p/dockerfile in resolve_vendor_packs.
    Cheap: no file reads, just basename + path-substring matching on the
    same string iterator that feeds detect_languages."""
    found: Set[str] = set()
    target_tags = set(INFRA_TO_VENDOR_PACKS)
    for name in _iter_file_names(root):
        norm = name.replace(os.sep, "/").lower()
        base = norm.rsplit("/", 1)[-1]
        if base == "dockerfile" or base.startswith("dockerfile.") or base.endswith(".dockerfile"):
            found.add("dockerfile")
        if any(f"/{d}/" in "/" + norm for d in _K8S_DIR_HINTS):
            found.add("kubernetes")
        if found >= target_tags:
            break  # nothing more to discover
    return found

# framework-tag -> [pack, ...]. Loaded when the framework detector says so.
# Only tags with a proven-existing registry pack are here; the rest fall back
# to whatever your bundled semgrep-master rulepack provides.
FRAMEWORK_TO_VENDOR_PACKS: Dict[str, List[str]] = {
    "fastapi":       ["p/fastapi"],
    "flask":         ["p/flask"],
    "django":        ["p/django"],
    "react":         ["p/react"],
    "koa":           ["p/koa"],
    "jwt":           ["p/jwt"],
    "jsonwebtoken":  ["p/jwt"],
}


def resolve_vendor_packs(langs: Set[str],
                        frameworks_by_lang: Dict[str, Set[str]],
                        infra_manifests: Optional[Set[str]] = None) -> List[str]:
    """Return the semgrep/opengrep --config vendor-pack list for a given repo.

    Deduplicated, order-preserving: defaults first, then per-language packs
    (in a stable language order), then per-framework packs, finally
    infra-manifest packs (k8s, dockerfile) if the manifest detector found
    matching files. This ordering ensures the broadest rules always parse
    first so a rule that appears in multiple packs is loaded from the
    highest-authority source."""
    picked: List[str] = []
    seen: Set[str] = set()

    def _add(packs: List[str]) -> None:
        for p in packs:
            if p not in seen:
                picked.append(p)
                seen.add(p)

    _add(DEFAULT_VENDOR_PACKS)
    for lang in sorted(langs):
        _add(LANGUAGE_TO_VENDOR_PACKS.get(lang, []))
    all_frameworks: Set[str] = set()
    for fw_set in frameworks_by_lang.values():
        all_frameworks.update(fw_set)
    for fw in sorted(all_frameworks):
        _add(FRAMEWORK_TO_VENDOR_PACKS.get(fw, []))
    for tag in sorted(infra_manifests or ()):
        _add(INFRA_TO_VENDOR_PACKS.get(tag, []))
    return picked


_USER_RULEPACKS: List[Path] = []


def register_rulepack(rulepack: Path) -> None:
    """Add a rulepack file or directory to the global registry. Missing paths
    are silently ignored so the CLI stays forgiving across environments."""
    if rulepack is None:
        return
    if not rulepack.exists():
        return
    if rulepack in _USER_RULEPACKS:
        return
    _USER_RULEPACKS.append(rulepack)


# Common Semgrep language aliases → canonical names used inside this tool.
_SEMGREP_LANG_ALIASES = {
    "js": "javascript", "ts": "typescript", "py": "python", "yml": "yaml",
    "c++": "cpp",
}


def _extract_rule_languages(path: Path) -> Set[str]:
    """Return the set of `languages:` values declared by rules inside a
    Semgrep rule file. Best-effort — PyYAML when available, a small regex
    scanner as fallback so this module can still run without PyYAML at
    import time (semgrep itself always ships it)."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return set()

    langs: Set[str] = set()
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(text)
        if isinstance(data, dict):
            for rule in data.get("rules", []) or []:
                if not isinstance(rule, dict):
                    continue
                lv = rule.get("languages")
                if isinstance(lv, list):
                    langs.update(str(l).strip().lower() for l in lv)
                elif isinstance(lv, str):
                    langs.add(lv.strip().lower())
    except ImportError:
        # Fallback: scan the raw text for "languages: [a, b]" blocks. This
        # doesn't understand block scalars, but the vast majority of rule
        # files in the wild use inline lists.
        import re as _re
        for m in _re.finditer(r"languages\s*:\s*\[([^\]]+)\]", text):
            for tok in m.group(1).split(","):
                tok = tok.strip().strip("'\"")
                if tok:
                    langs.add(tok.lower())

    return {_SEMGREP_LANG_ALIASES.get(l, l) for l in langs if l}


def filter_rulepack_for_languages(path: Path, langs: Set[str]) -> List[Path]:
    """Return the subset of YAML rule files under `path` that target at least
    one of the languages actually present in the repo. A single-file rulepack
    is always returned as-is; a directory is walked recursively. Files with
    no parseable `languages:` field are included conservatively — a broken
    rule wastes semgrep parse time but never causes a scanner to miss a hit."""
    if not path.exists():
        return []
    if not langs:
        return []
    if path.is_file():
        # Filter even single-file packs so a Python-only rulepack passed
        # against a Go repo doesn't force semgrep to load Python rules.
        # `generic` is semgrep's language-agnostic regex mode — treat it as a
        # universal match so text-based rulepacks (config-file scans, secret
        # detection, etc.) apply to every repo regardless of source language.
        file_langs = _extract_rule_languages(path)
        if not file_langs or "generic" in file_langs or (file_langs & langs):
            return [path]
        return []
    files: List[Path] = []
    for suffix in ("*.yml", "*.yaml"):
        for p in path.rglob(suffix):
            if any(part in IGNORE_DIRS for part in p.relative_to(path).parts):
                continue
            files.append(p)
    matched: List[Path] = []
    for f in files:
        file_langs = _extract_rule_languages(f)
        if not file_langs or "generic" in file_langs or (file_langs & langs):
            matched.append(f)
    return matched


def resolve_rulepack_configs(rulepacks: List[Path], langs: Set[str],
                             apply_filter: bool = True) -> List[str]:
    """Expand every registered rulepack to the concrete --config paths that
    semgrep + opengrep should load for a given repo's language set.

    When `apply_filter` is False every rulepack path is passed as-is (files
    verbatim, directories as directories) — the escape hatch used by
    `--no-rulepack-filter` for debugging / when the language detector guesses
    wrong."""
    configs: List[str] = []
    for rp in rulepacks:
        if not rp.exists():
            continue
        if not apply_filter:
            configs.append(str(rp))
            continue
        for p in filter_rulepack_for_languages(rp, langs):
            configs.append(str(p))
    return configs


def _iter_local_rule_files(configs: List[str]):
    """Yield individual rule YAML files from a mixed --config list.

    Registry names ("p/security-audit"), missing paths and non-YAML files are
    skipped. Directories are walked recursively (matching how semgrep would
    resolve them). Yields Path objects in a stable order for deterministic
    bundle output."""
    for cfg in configs:
        s = str(cfg)
        if s.startswith("p/") or "://" in s:
            continue  # registry pack, not a local file
        p = Path(s)
        if not p.exists():
            continue
        if p.is_file():
            if p.suffix.lower() in (".yml", ".yaml"):
                yield p
        elif p.is_dir():
            for suffix in ("*.yml", "*.yaml"):
                for sub in sorted(p.rglob(suffix)):
                    if any(part in IGNORE_DIRS for part in sub.relative_to(p).parts):
                        continue
                    yield sub


BUNDLE_FILENAME = "_argus_rulebundle.yml"

# Sentinels woven into every bundled rule ID so parse_sarif can unwind
# semgrep's path-based prefixing back to the original rule identifier.
# Without this, a rule loaded from a bundle at `/private/tmp/.../out_dir/
# _argus_rulebundle.yml` shows up in SARIF as
# `private.tmp....out_dir.<original_id>`, which breaks cross-scanner dedup
# (opengrep uses the clean id) and never merges into one finding.
# Rewritten shape: `<sentinel_start>.<original_ns>.<sentinel_end>.<original_id>`
# Two markers so the namespace (which itself contains dots) can be extracted
# unambiguously — parse_sarif takes what's between them.
BUNDLE_NS_START = "__argus_ns_start__"
BUNDLE_NS_END = "__argus_ns_end__"


def _bundle_namespace_for(rule_file: Path) -> str:
    """Reconstruct the dot-namespace semgrep would have used for a rule
    loaded from its ORIGINAL file location, so we can preserve the pre-
    bundle rule id shape after unwinding the sentinel in parse_sarif.

    Semgrep's convention (observed): take the file's parent directory
    relative to the invocation anchor, dots-separated. For rules that ship
    inside SCRIPT_DIR (`rules/cwe-400/foo.yml`) that gives us the pre-edit
    `rules.CWE-400` prefix exactly. External rulepacks fall back to
    `custom` — we can't reverse-engineer their original namespace."""
    try:
        rel = rule_file.resolve().relative_to(SCRIPT_DIR)
    except (ValueError, OSError):
        return "custom"
    parent = str(rel.parent).replace(os.sep, ".").strip(".")
    return parent or "custom"


def bundle_local_rulepacks(configs: List[str], out_dir: Path
                           ) -> "tuple[List[str], Optional[Path], int, int]":
    """Merge every local rule YAML in `configs` into one bundle file.

    Returns (new_configs, bundle_path, files_merged, rules_written):
      new_configs   — original list with all local files/dirs replaced by
                      [bundle_path]; registry packs (p/*) pass through.
      bundle_path   — the bundle file argus wrote, or None if nothing merged.
      files_merged  — count of rule files whose content ended up in the bundle.
      rules_written — count of unique rules in the bundle after de-dup by id.

    Why bundle: passing 40+ `--config <file>` args forces semgrep to open,
    parse and validate every file separately. One `--config bundle.yml`
    cuts that cold-start cost, and dedup-by-id removes rules that were
    loaded twice via overlapping rulepack directories.

    Rule IDs are rewritten to `<original_namespace>.<sentinel>.<id>` so
    parse_sarif can strip semgrep's added bundle-path prefix and recover
    the pre-bundle rule id shape — otherwise cross-scanner dedup would
    treat semgrep and opengrep hits on the same code as separate findings.

    Falls back gracefully — on any parse error or missing PyYAML, returns
    the original config list unchanged so the scan still runs correctly."""
    try:
        import yaml  # type: ignore
    except ImportError:
        return configs, None, 0, 0

    registry_configs = [c for c in configs
                        if str(c).startswith("p/") or "://" in str(c)]
    local_rule_files = list(_iter_local_rule_files(configs))
    if not local_rule_files:
        return configs, None, 0, 0

    merged_rules: List[dict] = []
    seen_originals: Set[str] = set()
    files_merged = 0
    for rule_file in local_rule_files:
        try:
            data = yaml.safe_load(rule_file.read_text(encoding="utf-8",
                                                     errors="replace"))
        except Exception as e:  # noqa: BLE001
            log.warning("[bundle] could not parse %s: %s", rule_file, e)
            continue
        if not isinstance(data, dict):
            continue
        raw_rules = data.get("rules")
        if not isinstance(raw_rules, list):
            continue
        ns = _bundle_namespace_for(rule_file)
        contributed = False
        for rule in raw_rules:
            if not isinstance(rule, dict):
                continue
            original_id = rule.get("id")
            if original_id is None:
                continue
            # Semgrep only prepends the file-path namespace when the rule's
            # own id is a bare token (e.g. `cwe-400-unbounded-async`). If the
            # id already contains dots — a fully-namespaced form like
            # `mhealth.go.access-control.idor-handler-fetch-by-id-no-authz` —
            # semgrep uses it verbatim. Mirror that here: only wrap a
            # namespace around bare ids, so parse_sarif recovers the exact
            # pre-bundle rule id shape.
            effective_ns = "" if "." in str(original_id) else ns
            original_key = (f"{effective_ns}.{original_id}"
                            if effective_ns else str(original_id))
            if original_key in seen_originals:
                continue  # same rule declared under same namespace twice
            seen_originals.add(original_key)
            # Rewrite id to bracket the (possibly empty) original namespace
            # with sentinels. Semgrep will still prepend its own bundle-path
            # prefix on output; parse_sarif reads the namespace from between
            # the sentinels and the original id from after the closing
            # sentinel, dropping the semgrep-added prefix entirely.
            rule = dict(rule)
            rule["id"] = (f"{BUNDLE_NS_START}.{effective_ns}.{BUNDLE_NS_END}."
                          f"{original_id}")
            merged_rules.append(rule)
            contributed = True
        if contributed:
            files_merged += 1

    if not merged_rules:
        return configs, None, 0, 0

    bundle_path = out_dir / BUNDLE_FILENAME
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        bundle_path.write_text(
            yaml.safe_dump({"rules": merged_rules}, sort_keys=False,
                           allow_unicode=True),
            encoding="utf-8",
        )
    except Exception as e:  # noqa: BLE001
        log.warning("[bundle] could not write %s: %s", bundle_path, e)
        return configs, None, 0, 0

    new_configs = registry_configs + [str(bundle_path)]
    return new_configs, bundle_path, files_merged, len(merged_rules)


# --------------------------------------------------------------------------------------
# Language detection (crawl)
# --------------------------------------------------------------------------------------

def _iter_files(root: Path):
    """Prefer git-tracked files (fast, respects .gitignore); else walk with ignores."""
    if shutil.which("git") and (root / ".git").exists():
        try:
            out = subprocess.run(
                ["git", "-C", str(root), "ls-files"],
                capture_output=True, text=True, timeout=60, check=True,
            ).stdout
            for line in out.splitlines():
                p = root / line
                if p.is_file():
                    yield p
            return
        except Exception:
            pass  # fall back to walk
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS and not d.startswith(".")]
        for fn in filenames:
            yield Path(dirpath) / fn


def _iter_file_names(root: Path):
    """Yield relative file-name STRINGS (no Path stat) — for callers that only
    need extension/basename lookups. On a 20k-file tree this saves ~1–2s of
    stat syscalls vs `_iter_files`, which pays `Path.is_file()` per entry."""
    if shutil.which("git") and (root / ".git").exists():
        try:
            out = subprocess.run(
                ["git", "-C", str(root), "ls-files"],
                capture_output=True, text=True, timeout=60, check=True,
            ).stdout
            for line in out.splitlines():
                if line:
                    yield line  # git ls-files only reports tracked files → no stat needed
            return
        except Exception:
            pass
    root_str = str(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS and not d.startswith(".")]
        rel = os.path.relpath(dirpath, root_str)
        for fn in filenames:
            yield fn if rel == "." else f"{rel}{os.sep}{fn}"


# Cap for language detection on huge monorepos. Beyond this many files, the
# language mix has stabilised — a further walk changes nothing but adds cost.
# Sized so the walk itself stays sub-second even without git ls-files.
LANG_DETECT_SAMPLE_CAP = 8000


def detect_languages(root: Path) -> Dict[str, int]:
    """Return {language: file_count}. Manifests contribute a strong signal.

    Uses cheap string operations on filenames (no per-file stat), and early-
    exits once LANG_DETECT_SAMPLE_CAP entries have been seen — on a 50k-file
    monorepo the language mix is fully determined long before that ceiling."""
    counts: Dict[str, int] = {}
    manifest_exact = {m: l for m, l in MANIFEST_LANG.items() if not m.startswith("*")}
    manifest_glob = [(m[1:], l) for m, l in MANIFEST_LANG.items() if m.startswith("*")]
    seen = 0
    for name_str in _iter_file_names(root):
        seen += 1
        if seen > LANG_DETECT_SAMPLE_CAP:
            break
        # Extension: cheap rfind, no Path allocation.
        dot = name_str.rfind(".")
        if dot != -1:
            ext = name_str[dot:].lower()
            lang = EXT_LANG.get(ext)
            if lang is not None:
                counts[lang] = counts.get(lang, 0) + 1
        # Manifest: basename only.
        slash = max(name_str.rfind("/"), name_str.rfind(os.sep))
        basename = name_str[slash + 1:] if slash != -1 else name_str
        mlang = manifest_exact.get(basename)
        if mlang is not None:
            counts[mlang] = counts.get(mlang, 0) + 5
        else:
            for suffix, mlang in manifest_glob:
                if basename.endswith(suffix):
                    counts[mlang] = counts.get(mlang, 0) + 5
                    break
    return dict(sorted(counts.items(), key=lambda kv: kv[1], reverse=True))


# --------------------------------------------------------------------------------------
# Planning + execution
# --------------------------------------------------------------------------------------

@dataclasses.dataclass
class ScanResult:
    scanner: str
    status: str            # "ok" | "error" | "skipped"
    findings: List[Finding]
    returncode: Optional[int] = None
    duration_s: float = 0.0
    detail: str = ""


def select_adapters(langs: Set[str], only: Optional[Set[str]], skip: Set[str]) -> List[Adapter]:
    chosen = []
    for a in ADAPTERS:
        if only is not None and a.name not in only:
            continue
        if a.name in skip:
            continue
        if a.applies_to(langs):
            chosen.append(a)
    return chosen


def _status(msg: str) -> None:
    """Stage-wise status line, always visible (independent of log level)."""
    print(msg, flush=True)


# --------------------------------------------------------------------------------------
# Live progress reporting
#
# A run with 5–7 scanners on a large repo can spend 60–600s inside the parallel
# scanner pool with no visible activity between the per-scanner [START]/[DONE]
# lines. `ProgressTracker` fills that gap with:
#   • a completion line every time a scanner finishes (X/N, %, findings, elapsed)
#   • a heartbeat every HEARTBEAT_SECONDS while scanners are still running,
#     showing overall %, currently-running scanner names, and their per-scanner
#     elapsed time
#
# The tracker is thread-safe (scanners run in a ThreadPoolExecutor) and is a
# strict addition — the existing [START]/[PARSE]/[DONE] lines from run_adapter
# stay as-is.
# --------------------------------------------------------------------------------------

PROGRESS_HEARTBEAT_SECONDS = 15.0
PROGRESS_BAR_WIDTH = 20


def _progress_bar(pct: float, width: int = PROGRESS_BAR_WIDTH) -> str:
    filled = int(round((pct / 100.0) * width))
    filled = max(0, min(width, filled))
    return "[" + "█" * filled + "░" * (width - filled) + "]"


class ProgressTracker:
    """Thread-safe live progress printer for a per-repo scan run."""

    def __init__(self, total: int, repo_label: str = "",
                 heartbeat_s: float = PROGRESS_HEARTBEAT_SECONDS):
        self.total = max(int(total), 0)
        self.repo_label = repo_label
        self.heartbeat_s = heartbeat_s
        self.completed = 0
        self.findings_so_far = 0
        self._running: Dict[str, float] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._t0 = time.time()

    # --- lifecycle -------------------------------------------------------
    def start(self) -> None:
        if self.total == 0:
            return
        label = f" for {self.repo_label}" if self.repo_label else ""
        _status(f"   [PROGRESS]   0% {_progress_bar(0)} (0/{self.total}) "
                f"— scan starting{label} …")
        self._thread = threading.Thread(target=self._heartbeat_loop,
                                        name="argus-progress", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        if self.total == 0:
            return
        elapsed = time.time() - self._t0
        _status(f"   [PROGRESS] 100% {_progress_bar(100)} "
                f"({self.completed}/{self.total}) — done in {elapsed:5.1f}s, "
                f"{self.findings_so_far} raw findings")

    # --- per-scanner hooks ----------------------------------------------
    def mark_start(self, scanner: str) -> None:
        with self._lock:
            self._running[scanner] = time.time()

    def mark_done(self, scanner: str, findings_count: int,
                  status: str = "ok") -> None:
        with self._lock:
            self._running.pop(scanner, None)
            self.completed += 1
            self.findings_so_far += max(int(findings_count), 0)
            pct = (self.completed / self.total) * 100 if self.total else 100.0
            elapsed = time.time() - self._t0
            still_running = ",".join(sorted(self._running)) or "-"
        _status(f"   [PROGRESS] {pct:5.1f}% {_progress_bar(pct)} "
                f"({self.completed}/{self.total}) — {scanner} {status} "
                f"({findings_count} findings) — elapsed {elapsed:5.1f}s "
                f"— running: {still_running}")

    # --- heartbeat -------------------------------------------------------
    def _heartbeat_loop(self) -> None:
        while not self._stop.wait(self.heartbeat_s):
            with self._lock:
                if not self._running:
                    continue  # nothing in flight; per-scanner lines will cover it
                now = time.time()
                pct = (self.completed / self.total) * 100 if self.total else 100.0
                elapsed = now - self._t0
                running_desc = ", ".join(
                    f"{name}({now - start:.0f}s)"
                    for name, start in sorted(self._running.items(),
                                              key=lambda kv: kv[1])
                )
            _status(f"   [PROGRESS] {pct:5.1f}% {_progress_bar(pct)} "
                    f"({self.completed}/{self.total}) — running: "
                    f"{running_desc} — elapsed {elapsed:5.1f}s")


def _compute_scanner_jobs(scanner_workers: int, chosen: List[Adapter]) -> int:
    """Fair-share the machine's cores among the scanners running in parallel.

    We run min(scanner_workers, len(chosen)) subprocesses concurrently, and
    each defaults to using every core it can see. Without a cap, running
    N scanners × M cores each = N*M workers competing for M cores — pure
    thrash. Capping at cpu_count // concurrent_scanners gives every scanner
    a fair slice with no over-subscription."""
    try:
        cores = os.cpu_count() or 4
    except Exception:
        cores = 4
    concurrent = max(1, min(scanner_workers, len(chosen)))
    return max(1, cores // concurrent)


def run_adapter(a: Adapter, target: Path, out_dir: Path, timeout: int,
                extra_configs: Optional[Sequence[str]] = None,
                tracker: Optional[ProgressTracker] = None,
                exclude_rules: Optional[Sequence[str]] = None,
                jobs: Optional[int] = None) -> ScanResult:
    if not a.available():
        _status(f"   [SKIP ] {a.name:<10} binary '{a.binary}' not found on PATH")
        if tracker is not None:
            tracker.mark_done(a.name, 0, status="skipped")
        return ScanResult(a.name, "skipped", [], detail=f"binary '{a.binary}' not found on PATH")
    out_file = out_dir / f"{a.name}.{a.out_ext}"
    cmd = a.build_cmd(target, out_file, extra_configs=extra_configs,
                      exclude_rules=exclude_rules, jobs=jobs)
    cwd = str(target) if a.run_in_target_cwd else None
    _status(f"   [START] {a.name:<10} scanning ...")
    log.info("[%s] running: %s", a.name, " ".join(cmd))
    if tracker is not None:
        tracker.mark_start(a.name)
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        dur = time.time() - t0
        _status(f"   [ERROR] {a.name:<10} timed out after {timeout}s ({dur:4.1f}s)")
        if tracker is not None:
            tracker.mark_done(a.name, 0, status="timeout")
        return ScanResult(a.name, "error", [], detail=f"timed out after {timeout}s",
                          duration_s=dur)
    except Exception as e:  # noqa: BLE001
        dur = time.time() - t0
        _status(f"   [ERROR] {a.name:<10} failed to launch: {e} ({dur:4.1f}s)")
        if tracker is not None:
            tracker.mark_done(a.name, 0, status="error")
        return ScanResult(a.name, "error", [], detail=f"failed to launch: {e}",
                          duration_s=dur)
    dur = time.time() - t0

    # For scanners that had to write into the target dir (skylos --sarif
    # refuses paths outside its workspace), pull the file back to argus's
    # canonical output location so the rest of the pipeline is unaware.
    if a.stage_output_in_target:
        staged = a.staged_output_path(target)
        if staged.exists():
            try:
                staged.replace(out_file)
            except Exception as e:  # noqa: BLE001
                log.warning("[%s] could not move staged SARIF %s → %s: %s",
                            a.name, staged, out_file, e)

    # For scanners that write to a directory with a self-chosen filename
    # (e.g. `scan-<timestamp>.json`), pick the newest match of the fallback
    # glob inside out_dir and rename it to out_file so the rest of the
    # pipeline sees a stable path. Newest wins so a stale file from a prior
    # run doesn't shadow the current scan's output.
    if a.output_glob_fallback and not out_file.exists():
        candidates = sorted(
            out_dir.glob(a.output_glob_fallback),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if candidates:
            try:
                candidates[0].replace(out_file)
            except Exception as e:  # noqa: BLE001
                log.warning("[%s] could not rename %s → %s: %s",
                            a.name, candidates[0], out_file, e)

    # Robust success rule: many scanners exit non-zero merely because findings exist.
    # Treat as success if an output file was produced and parses.
    produced = out_file.exists() and out_file.stat().st_size > 0
    if not produced:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-3:]
        _status(f"   [ERROR] {a.name:<10} no output produced (rc={rc}) ({dur:4.1f}s)")
        if tracker is not None:
            tracker.mark_done(a.name, 0, status="error")
        return ScanResult(a.name, "error", [], returncode=rc, duration_s=dur,
                          detail=f"no output produced (rc={rc}). " + " | ".join(tail))
    _status(f"   [PARSE] {a.name:<10} scan finished ({dur:4.1f}s), parsing output ...")
    parser = PARSERS[a.fmt]
    findings = parser(out_file, a.name, target)
    _status(f"   [DONE ] {a.name:<10} {len(findings):>4} findings  ({dur:4.1f}s)")
    if tracker is not None:
        tracker.mark_done(a.name, len(findings), status="ok")
    return ScanResult(a.name, "ok", findings, returncode=rc, duration_s=dur,
                      detail=f"{len(findings)} findings")


# --------------------------------------------------------------------------------------
# Deduplicate + aggregate
# --------------------------------------------------------------------------------------

DEFAULT_DEDUP_LINE_WINDOW = 3   # ±lines within which same-category findings collapse


def _merge_into(cur: Finding, other: Finding) -> None:
    """Fold `other` into `cur` in place: max severity, union of sources, fill blanks."""
    if SEV_RANK.get(other.severity, 0) > SEV_RANK.get(cur.severity, 0):
        cur.severity = other.severity
    for s in other.sources:
        if s not in cur.sources:
            cur.sources.append(s)
    if not cur.cwe and other.cwe:
        cur.cwe = other.cwe
    if not cur.snippet and other.snippet:
        cur.snippet = other.snippet
    if not cur.category and other.category:
        cur.category = other.category


def deduplicate(findings: List[Finding],
                line_window: int = DEFAULT_DEDUP_LINE_WINDOW) -> List[Finding]:
    """Two-pass cross-scanner dedup.

    Pass 1 (exact fingerprint): merges hits whose (path, start_line, rule_token)
    fingerprint matches — the original, high-precision behaviour. Kept intact so
    existing suppression files by fingerprint still hit.

    Pass 2 (semantic bucket): for the survivors of pass 1, groups by
    (path, category) — where `category` normalises different scanners'
    rule_ids/CWEs into one bucket (secrets, path-traversal, ...) — and collapses
    clusters whose start_lines lie within ±line_window of each other. This
    catches the big class of cross-scanner duplicates the original fingerprint
    misses: same secret at line 89 flagged simultaneously as drogonsec LEAK-010,
    LEAK-121, opengrep detect-generic-api-key, bearer hardcoded_secret. All
    collapse into a single row whose `sources` list carries every scanner that
    reported it.

    Findings with no inferable category skip pass 2 (never over-merged)."""
    # ---- Pass 1: exact fingerprint dedup --------------------------------------
    primary: Dict[str, Finding] = {}
    for f in findings:
        fp = f.fingerprint()
        if fp not in primary:
            primary[fp] = dataclasses.replace(f, sources=list(f.sources))
            continue
        _merge_into(primary[fp], f)
    stage1 = list(primary.values())

    # ---- Pass 2: same-file, same-category, nearby-line semantic dedup ---------
    classified: Dict[tuple, List[Finding]] = {}
    unclassified: List[Finding] = []
    for f in stage1:
        if not f.category:
            unclassified.append(f)
            continue
        classified.setdefault((f.path, f.category), []).append(f)

    merged: List[Finding] = list(unclassified)
    for (_path, _cat), group in classified.items():
        group.sort(key=lambda x: (x.start_line, x.rule_id))
        # Chain-cluster: two findings collapse if their start_lines are within
        # line_window of each other (or the last member of the running cluster).
        cluster: List[Finding] = []
        last_line = None
        for f in group:
            if last_line is None or (f.start_line - last_line) <= line_window:
                cluster.append(f)
            else:
                merged.append(_collapse_cluster(cluster))
                cluster = [f]
            last_line = f.start_line
        if cluster:
            merged.append(_collapse_cluster(cluster))
    return merged


def _collapse_cluster(cluster: List[Finding]) -> Finding:
    """Pick the highest-severity finding as the anchor; fold the rest into it."""
    if len(cluster) == 1:
        return cluster[0]
    anchor = max(cluster, key=lambda f: (SEV_RANK.get(f.severity, 0), -f.start_line))
    for f in cluster:
        if f is anchor:
            continue
        _merge_into(anchor, f)
    return anchor


# Fix A (2026-09-23): threshold above which a (file, rule) cluster gets
# rolled up into a single output row. Below this it stays as separate rows.
# 3 chosen so the typical "one architectural bug × two adjacent handlers"
# case still surfaces both rows, but "same missing-authz-annotation × 46
# handlers in one file" collapses to one row + occurrences list.
FILE_RULE_ROLLUP_THRESHOLD = 3


def collapse_file_rule_clusters(findings: List[Finding],
                                threshold: int = FILE_RULE_ROLLUP_THRESHOLD) -> List[Finding]:
    """Group deduped findings by (path, rule_id). For groups with `threshold`
    or more members, collapse into a single anchor row whose `occurrences`
    field lists every OTHER line the same rule fired on. The anchor keeps
    the highest-severity finding's shape; extra lines surface as a compact
    list the reader can jump to.

    Groups smaller than `threshold` pass through untouched.

    Rationale: after cross-scanner dedup, a rule can still legitimately fire
    on N distinct lines in one file (e.g. every mutating handler in a JAX-RS
    resource class missing @RolesAllowed). Reviewers don't want 46 rows for
    one architectural bug; they want one row saying "46 hits at lines 42,
    89, 156, ..." with the fix once. Full per-line detail stays in
    raw_findings.json for anyone who needs it."""
    groups: Dict[tuple, List[Finding]] = {}
    passthrough: List[Finding] = []
    for f in findings:
        # rule id families collapse under one key. Handle the argus-bundle
        # sentinel-unwound form and the semgrep-namespaced form the same:
        # the last dot-segment is the actual rule name.
        rid_leaf = (f.rule_id or "").split(".")[-1]
        key = (f.path, rid_leaf)
        groups.setdefault(key, []).append(f)

    out: List[Finding] = []
    for key, cluster in groups.items():
        if len(cluster) < threshold:
            out.extend(cluster)
            continue
        # Sort by (severity desc, line asc) so the anchor is the highest
        # severity hit and occurrences list reads in file order.
        cluster.sort(key=lambda f: (-SEV_RANK.get(f.severity, 0), f.start_line))
        anchor = cluster[0]
        others = cluster[1:]
        # Fold others' sources into the anchor; take max severity; union CWE.
        # Then attach the extra line numbers as occurrences.
        for other in others:
            _merge_into(anchor, other)
        extra_lines = sorted({f.start_line for f in others})
        # Keep occurrences list stable + de-duped; skip the anchor's own line.
        anchor.occurrences = [ln for ln in extra_lines if ln != anchor.start_line]
        # Compose a summary message so a reader who only sees this row knows
        # the multiplicity — e.g. "[46 hits on this file at lines 42, 89,
        # 156, ...]". Prepend to preserve the original scanner message tail.
        n = len(cluster)
        first_five = extra_lines[:5]
        more = "" if len(extra_lines) <= 5 else f", +{len(extra_lines)-5} more"
        summary = (f"[{n} hits on this file — first at line "
                   f"{anchor.start_line}, others at "
                   f"{', '.join(str(l) for l in first_five)}{more}] ")
        anchor.message = summary + (anchor.message or "")
        out.append(anchor)
    return out


# --------------------------------------------------------------------------------------
# Triage / false-positive suppression
#
# After findings from all tools are normalized and DEDUPLICATED, this module removes
# the ones a human has triaged as false positives (or accepted risk / won't fix).
#
# The suppression file is plain JSON, shared across scans, and safe to commit:
#
#   {
#     "version": 1,
#     "suppressions": [
#       {"fingerprint": "3f2a9c...", "status": "false_positive",
#        "reason": "input sanitized upstream", "rule_id": "python.lang.security...",
#        "path": "app/db.py", "line": 42,
#        "triaged_by": "alice", "triaged_at": "2026-08-12T10:00:00"}
#     ],
#     "rules": [
#       {"rule_id": "B101", "path_glob": "tests/**", "status": "false_positive",
#        "reason": "asserts are expected in tests"}
#     ]
#   }
#
# * "suppressions" match a specific deduped finding by its fingerprint.
# * "rules" are broad matchers (glob on rule_id / path, exact cwe / scanner);
#   every field present in a rule must match, and at least one field is required.
# --------------------------------------------------------------------------------------

DEFAULT_SUPPRESSIONS_FILE = "sast_suppressions.json"
SUPPRESS_STATUSES = ("false_positive", "accepted_risk", "wont_fix")


# --------------------------------------------------------------------------------------
# Built-in automatic false-positive classifier
#
# On a plain scan (with no user-provided sast_suppressions.json) the tool used
# to keep every finding, so ~96% of the actionable set on a typical repo was
# noise: findings inside prior scan reports, inside virtualenvs / node_modules,
# inside build artifacts, or B101 asserts in tests. `classify_auto_fp` is the
# out-of-the-box filter that catches those before they reach findings.csv/json
# and moves them to the "False Positives Removed" sheet instead. It's opt-out
# via --no-auto-suppress.
# --------------------------------------------------------------------------------------

# (substring, reason). Substring is matched against the forward-slash-normalised
# repo-relative path; the leading and trailing "/" anchor to path segments.
_AUTO_FP_PATH_SEGMENTS: List[tuple] = [
    ("sast_reports/",   "own scan output (sast_reports)"),
    ("sast-reports/",   "own scan output (sast-reports)"),
    ("SAST_Scan/",      "prior SAST report tree"),
    ("/site-packages/", "vendored dependency (site-packages)"),
    ("/node_modules/",  "vendored dependency (node_modules)"),
    ("/venv/",          "virtualenv"),
    ("/.venv/",         "virtualenv"),
    ("/env/",           "virtualenv (env/)"),
    ("/vendor/",        "vendored dependency (vendor/)"),
    ("/bower_components/", "vendored dependency (bower_components)"),
    ("/dist/",          "build artifact (dist/)"),
    ("/build/",         "build artifact (build/)"),
    ("/target/",        "build artifact (target/)"),
    ("/.tox/",          "tox virtualenv"),
    ("/__pycache__/",   "python bytecode cache"),
    ("/.gradle/",       "gradle cache"),
    ("/.terraform/",    "terraform vendored providers"),
]

# Exact tail-of-path matches: the tool's own report files, minified assets, etc.
_AUTO_FP_PATH_SUFFIXES: List[tuple] = [
    (".sarif",             "SARIF report file"),
    ("/merged.sarif",      "own merged SARIF"),
    ("/findings.json",     "own findings dump"),
    ("/findings.csv",      "own findings dump"),
    ("/raw_findings.json", "own raw findings dump"),
    ("/raw_findings.csv",  "own raw findings dump"),
    ("/suppressed.json",   "own suppressed findings"),
    ("/suppressed.csv",    "own suppressed findings"),
    ("/bandit.json",       "raw bandit output"),
    ("/semgrep.sarif",     "raw semgrep output"),
    ("/opengrep.sarif",    "raw opengrep output"),
    ("/bearer.sarif",      "raw bearer output"),
    ("/drogonsec.sarif",   "raw drogonsec output"),
    ("/gosec.sarif",       "raw gosec output"),
    ("/skylos.sarif",      "raw skylos output"),
    (".min.js",            "minified JavaScript"),
    (".min.css",           "minified CSS"),
    (".bundle.js",         "bundled JavaScript"),
    (".map",               "sourcemap"),
    ("argus.py",           "this SAST tool's own source"),
]

# Rule + path pairs. Bandit B101 (assert_used) in test files is the classic
# example: assertions are the standard testing idiom, not a bug.
_TEST_PATH_MARKERS = ("/tests/", "/test/", "test_", "_test.py", "conftest.py",
                      "/tests_", "spec/", "/__tests__/")

_AUTO_FP_RULE_IN_TEST: Dict[str, str] = {
    "B101": "assert_used in test file (idiomatic in pytest/unittest)",
    "B105": "hardcoded string flagged in test file (usually test data)",
    "B106": "hardcoded arg flagged in test file (usually test data)",
    "B311": "random.random() in test file (usually seed/reproducibility helper)",
}

# (rule_id_uppercase, basename_glob, reason). Suppresses a specific rule
# only on files whose basename matches the glob. Introduced for skylos:
# SKY-L012 / SKY-D223 fire on protobuf-generated modules where classes are
# injected at module-load time, which skylos's static resolver can't see.
_AUTO_FP_RULE_IN_PATH: List[tuple] = [
    ("SKY-L012", "*_pb2.py",
     "protobuf-generated module (dynamic symbol injection at load)"),
    ("SKY-L012", "*_pb2_grpc.py",
     "gRPC-generated module (dynamic symbol injection at load)"),
    ("SKY-D223", "*_pb2.py",
     "protobuf-generated import; not tracked in requirements by design"),
    ("SKY-D223", "*_pb2_grpc.py",
     "grpc-generated import; not tracked in requirements by design"),
]

# Snippet-content-based auto-FP: rule-id substring → list of (needle_predicate,
# reason) tuples. `needle_predicate` is a callable that receives the finding's
# snippet text and returns True if the snippet indicates a known-safe pattern.
# Used to filter FPs that pattern-based scanners can't tell apart from the
# unsafe variant of the same shape (e.g. hardcoded password vs env-var
# substitution, safe SQLAlchemy parameterized text() vs concatenated SQL).
#
# Keeps semantic knowledge in one place — the classifier stays declarative and
# every entry documents the specific FP class it kills.
_AUTO_FP_RULE_SNIPPET: "List[tuple]" = [
    # drogonsec LEAK-120 fires on any `password=` / `token=` / `secret=` /
    # `key=` in config files, without recognising that a `${VAR}` substitution
    # means the actual value is loaded from an env var / secret manager at
    # deploy time. Ship 14 FPs on consultation-master's Kafka SASL config.
    ("LEAK-120",
     lambda s: any(kw in (s or "").lower() for kw in
                   ("password=", "token=", "secret=", "key=", "passwd="))
               and ("${" in (s or "")),
     "credential field value is a ${VAR} template substituted at deploy time"),
    # Same shape from drogonsec's other secret rules — LEAK-010 (generic API
    # key), LEAK-121 (generic secret), PY-003 (python secret pattern).
    ("LEAK-010",
     lambda s: any(kw in (s or "").lower() for kw in
                   ("password=", "token=", "secret=", "key=", "passwd="))
               and ("${" in (s or "")),
     "credential field value is a ${VAR} template substituted at deploy time"),
    ("LEAK-121",
     lambda s: any(kw in (s or "").lower() for kw in
                   ("password=", "token=", "secret=", "key=", "passwd="))
               and ("${" in (s or "")),
     "credential field value is a ${VAR} template substituted at deploy time"),
    # semgrep `avoid-sqlalchemy-text` fires on ANY text(f"...") without
    # inspecting whether the f-string only interpolates bind-placeholder
    # names (":r0, :r1") vs user input. The safe pattern uses a placeholders
    # variable that's assembled from `f":r{i}"` / `f":p{i}"` — recognise
    # that shape and treat as safe.
    ("avoid-sqlalchemy-text",
     lambda s: (":r{" in (s or "") or ":p{" in (s or "")
                or 'f":r' in (s or "") or 'f":p' in (s or "")
                or "placeholders" in (s or "").lower()),
     "SQLAlchemy text() uses bind-placeholder interpolation only, not user input"),
    # argus's own `ssrf-tainted-url-go` — semgrep cross-file taint tracks a
    # value from `ctx.Input.Query(field)` (where `field` came from struct-tag
    # reflection in a for-loop over model fields) to any downstream http.Get.
    # But the tainted value is a query-parameter VALUE, used as a search
    # filter — never constructed into a URL. The struct-tag reflection loop
    # is the giveaway: real SSRF has the tainted string flow into url string
    # construction, not into a search-request struct.
    ("ssrf-tainted-url-go",
     lambda s: ("val.type()" in (s or "").lower()
                or ".type().field(" in (s or "").lower()
                or ".tag.get(" in (s or "").lower()
                or "reflect.type" in (s or "").lower()),
     "struct-tag reflection loop — value is a search filter, not a URL"),
    # Fix B (2026-09-23): HIGH-level FP reducers ----------------------------
    # Findings inside single-line NOSONAR / nosemgrep / noqa suppression
    # comments are explicit developer opt-outs — scanners still emit them,
    # argus should honour the intent. Applied to any rule.
    ("",  # empty token = match any rule id
     lambda s: any(marker in (s or "").lower() for marker in
                   ("//nosonar", "// nosonar", "# nosonar",
                    "# noqa", "//noqa", "nosemgrep", "no-sonar")),
     "explicit developer opt-out comment on this line"),
    # Any secret-detection rule fires on a "value" that is really a
    # placeholder / example / empty string / xxx / TODO. Attackers can't
    # extract a secret from `"xxxxxxxxxx"` or `"YOUR_KEY_HERE"`.
    ("hardcoded_secret",
     lambda s: any(kw in (s or "").lower() for kw in
                   ('="xxxx', '="your-', '="your_', '=" your ', '=""',
                    "='xxxx", "='your-", "='your_", "=''",
                    "= 'xxxx", "= \"xxxx",
                    "todo", "fixme", "example",
                    "placeholder", "changeme", "change_me", "change-me",
                    "your-api-key", "your_api_key", "yourapikey",
                    "test-key", "test_key", "dummy", "sample")),
     "placeholder / example / TODO value — not a real secret"),
    ("hardcoded-secret",
     lambda s: any(kw in (s or "").lower() for kw in
                   ('="xxxx', '="your-', '="your_', '=" your ', '=""',
                    "='xxxx", "='your-", "='your_", "=''",
                    "todo", "fixme", "example",
                    "placeholder", "changeme", "your-api-key",
                    "test-key", "dummy", "sample")),
     "placeholder / example / TODO value — not a real secret"),
]


def _norm_path_for_match(path: str) -> str:
    """Forward slashes + leading slash so path-segment substrings match anywhere."""
    p = (path or "").replace("\\", "/")
    if not p.startswith("/"):
        p = "/" + p
    return p


def classify_auto_fp(f: "Finding") -> Optional[tuple]:
    """Return (status, reason) if `f` matches a built-in false-positive rule.

    Precedence:
      1. Path segment inside a known-noise directory.
      2. Path suffix pointing at the tool's own output / minified assets.
      3. Rule-id + test-file combination (B101 / B105 / ...).
      4. Rule-id + basename-glob (protobuf-generated python etc.).
      5. Rule-id + snippet-content predicate (${VAR} template substitution,
         SQLAlchemy safe-parameterized text(), ...). This is the surgical
         filter for scanners that can't distinguish safe vs unsafe variants
         of the same syntactic shape.

    Returns None if the finding is not auto-classifiable — normal scan behaviour."""
    p = _norm_path_for_match(f.path)
    for seg, reason in _AUTO_FP_PATH_SEGMENTS:
        # Use "/" boundaries so /site-packages/ never matches /site-packagesX/.
        if seg in p:
            return ("false_positive", reason)
    for suf, reason in _AUTO_FP_PATH_SUFFIXES:
        if p.endswith(suf):
            return ("false_positive", reason)
    rid_up = (f.rule_id or "").upper()
    if rid_up in _AUTO_FP_RULE_IN_TEST:
        lower = p.lower()
        if any(m in lower for m in _TEST_PATH_MARKERS):
            return ("false_positive", _AUTO_FP_RULE_IN_TEST[rid_up])
    basename = p.rsplit("/", 1)[-1]
    for rule_id, glob, reason in _AUTO_FP_RULE_IN_PATH:
        if rid_up == rule_id.upper() and fnmatch.fnmatch(basename, glob):
            return ("false_positive", reason)
    # Snippet-content predicates — walk _AUTO_FP_RULE_SNIPPET entries whose
    # rule-id token is a substring of this finding's rule_id (case-insensitive).
    # The predicate then inspects the snippet text to classify.
    rid_lc = (f.rule_id or "").lower()
    snippet = f.snippet or ""
    for token, predicate, reason in _AUTO_FP_RULE_SNIPPET:
        if token.lower() in rid_lc:
            try:
                if predicate(snippet):
                    return ("false_positive", reason)
            except Exception:
                continue  # predicate bug shouldn't affect the scan
    return None


def _rule_matches(rule: dict, f: "Finding") -> bool:
    matched_any = False
    if rule.get("rule_id"):
        if not fnmatch.fnmatch(f.rule_id, str(rule["rule_id"])):
            return False
        matched_any = True
    if rule.get("cwe"):
        if (f.cwe or "").upper() != str(rule["cwe"]).upper().strip():
            return False
        matched_any = True
    if rule.get("path_glob"):
        if not fnmatch.fnmatch(f.path, str(rule["path_glob"])):
            return False
        matched_any = True
    if rule.get("scanner"):
        scanners = {s.split(":", 1)[0] for s in f.sources} | {f.scanner}
        if str(rule["scanner"]) not in scanners:
            return False
        matched_any = True
    return matched_any  # an empty rule matches nothing


class SuppressionStore:
    """Loads / saves the suppression file and matches findings against it."""

    def __init__(self, path) -> None:
        self.path = Path(path)
        self.by_fingerprint: Dict[str, dict] = {}
        self.rules: List[dict] = []
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception as e:
                raise SystemExit(f"Could not parse suppression file {self.path}: {e}")
            for e in data.get("suppressions", []) or []:
                fp = str(e.get("fingerprint", "")).strip()
                if fp:
                    self.by_fingerprint[fp] = e
            self.rules = [r for r in (data.get("rules", []) or []) if isinstance(r, dict)]

    def __len__(self) -> int:
        return len(self.by_fingerprint) + len(self.rules)

    def save(self) -> None:
        payload = {
            "version": 1,
            "suppressions": sorted(self.by_fingerprint.values(),
                                   key=lambda e: (e.get("path", ""), e.get("fingerprint", ""))),
            "rules": self.rules,
        }
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def add(self, f: "Finding", status: str, reason: str, triaged_by: str = "") -> dict:
        entry = {
            "fingerprint": f.fingerprint(),
            "status": status,
            "reason": reason,
            # Context fields (informational; matching is by fingerprint only):
            "scanner": f.scanner,
            "rule_id": f.rule_id,
            "cwe": f.cwe,
            "path": f.path,
            "line": f.start_line,
            "message": (f.message or "")[:160],
            "triaged_by": triaged_by or getpass.getuser(),
            "triaged_at": datetime.now().isoformat(timespec="seconds"),
        }
        self.by_fingerprint[entry["fingerprint"]] = entry
        return entry

    def add_fingerprint(self, fingerprint: str, status: str, reason: str,
                        triaged_by: str = "") -> dict:
        entry = {
            "fingerprint": fingerprint,
            "status": status,
            "reason": reason,
            "triaged_by": triaged_by or getpass.getuser(),
            "triaged_at": datetime.now().isoformat(timespec="seconds"),
        }
        self.by_fingerprint[fingerprint] = entry
        return entry

    def match(self, f: "Finding") -> Optional[dict]:
        entry = self.by_fingerprint.get(f.fingerprint())
        if entry:
            return entry
        for rule in self.rules:
            if _rule_matches(rule, f):
                return {
                    "status": rule.get("status", "false_positive"),
                    "reason": rule.get("reason", "suppressed by rule"),
                }
        return None


def apply_suppressions(findings: List["Finding"],
                       store: Optional[SuppressionStore],
                       auto_fp: bool = True):
    """Split deduplicated findings into (active, suppressed).

    Order of precedence:
      1. User-triaged suppression file (exact fingerprint or user rule).
      2. Built-in auto-FP classifier (own scan output / vendored code / test-
         file idioms). Opt out via auto_fp=False.

    Suppressed findings come back with status/suppress_reason filled in so they
    can still be reported separately (suppressed.json / suppressed.csv / SARIF
    'suppressions' / the "False Positives Removed" xlsx sheet) instead of
    silently disappearing.
    """
    active: List[Finding] = []
    suppressed: List[Finding] = []
    for f in findings:
        # 1) explicit user triage wins over built-in heuristics
        entry = store.match(f) if store is not None else None
        if entry:
            g = dataclasses.replace(f, sources=list(f.sources))
            g.status = entry.get("status") or "false_positive"
            g.suppress_reason = entry.get("reason", "") or ""
            suppressed.append(g)
            continue
        # 2) built-in classifier: known-noise paths and test-file idioms
        if auto_fp:
            hit = classify_auto_fp(f)
            if hit is not None:
                status, reason = hit
                g = dataclasses.replace(f, sources=list(f.sources))
                g.status = status
                g.suppress_reason = f"[auto] {reason}"
                suppressed.append(g)
                continue
        active.append(f)
    return active, suppressed


def load_suppression_store(explicit_path: Optional[str]) -> Optional[SuppressionStore]:
    """--suppressions wins; otherwise pick up ./sast_suppressions.json if present."""
    if explicit_path:
        return SuppressionStore(explicit_path)
    if Path(DEFAULT_SUPPRESSIONS_FILE).exists():
        return SuppressionStore(DEFAULT_SUPPRESSIONS_FILE)
    return None


def write_all_reports(findings: List["Finding"], store: Optional[SuppressionStore],
                      out_dir: Path, raw: Optional[List["Finding"]] = None,
                      auto_fp: bool = True):
    """Apply suppressions to deduped findings and (re)write every report file.

    `raw` is the pre-deduplication finding list (all scanners). During a scan it
    is passed in directly; it is persisted to raw_findings.json so that a later
    triage session can rebuild the workbook. When `raw` is None (e.g. triage on
    an old report dir), raw_findings.json is loaded if present, else the raw
    view degrades to the deduplicated set.

    `auto_fp` toggles the built-in false-positive classifier; True by default so
    a plain scan already ships a useful "False Positives Removed" sheet."""
    active, suppressed = apply_suppressions(findings, store, auto_fp=auto_fp)
    out_dir.mkdir(parents=True, exist_ok=True)

    raw_json = out_dir / "raw_findings.json"
    if raw is not None:
        write_json(raw, raw_json)
    elif raw_json.exists():
        try:
            raw = load_findings_json(raw_json)
        except SystemExit:
            raw = None
    if raw is None:
        raw = active + suppressed  # best available approximation of "raw"

    sup_json, sup_csv = out_dir / "suppressed.json", out_dir / "suppressed.csv"
    if not suppressed:
        # do not leave stale suppressed reports behind after re-triage
        for p in (sup_json, sup_csv):
            if p.exists():
                p.unlink()

    # Report writers are independent (each targets a different output file) and
    # spend most of their time in disk I/O plus openpyxl serialisation, which
    # releases the GIL during writes. Fan them out so XLSX doesn't block the
    # JSON/CSV/SARIF path — on a 5k-finding scan this cuts write time from
    # ~4s to ~1.5s.
    tasks: List[Callable[[], None]] = [
        lambda: write_merged_sarif(active + suppressed, out_dir / "merged.sarif"),
        lambda: write_json(active, out_dir / "findings.json"),
        lambda: write_csv(active, out_dir / "findings.csv"),
        lambda: write_csv(raw, out_dir / "raw_findings.csv"),
        # One workbook, three sheets: Raw Findings / Deduplicated / False Positives Removed.
        lambda: write_xlsx_workbook(raw, active + suppressed, suppressed,
                                     out_dir / "findings.xlsx"),
    ]
    if suppressed:
        tasks.append(lambda: write_json(suppressed, sup_json))
        tasks.append(lambda: write_csv(suppressed, sup_csv))

    with futures.ThreadPoolExecutor(max_workers=min(len(tasks), 6)) as pool:
        # Materialise .result() on each future so exceptions surface here
        # rather than getting silently swallowed by the pool.
        for fut in [pool.submit(t) for t in tasks]:
            fut.result()
    return active, suppressed


# --------------------------------------------------------------------------------------
# Output writers
# --------------------------------------------------------------------------------------

def write_merged_sarif(findings: List[Finding], path: Path) -> None:
    rules_index: Dict[str, dict] = {}
    results = []
    for f in findings:
        if f.rule_id not in rules_index:
            rules_index[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.message[:120] or f.rule_id},
            }
        sev_num = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.0", "LOW": "2.0", "INFO": "0.0"}[f.severity]
        level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}[f.severity]
        region = {"startLine": max(f.start_line, 1), "endLine": max(f.end_line, f.start_line, 1)}
        if f.snippet:
            region["snippet"] = {"text": f.snippet}
        result = {
            "ruleId": f.rule_id,
            "level": level,
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path},
                    "region": region,
                }
            }],
            "partialFingerprints": {"multiSastFingerprint/v1": f.fingerprint()},
            "properties": {
                "security-severity": sev_num,
                "unified-severity": f.severity,
                "sources": f.sources,
                "cwe": f.cwe,
                "triage-status": f.status,
            },
        }
        # SARIF-native suppression: viewers (GitLab, GitHub, VS Code) hide these.
        if f.status != "open":
            result["suppressions"] = [{
                "kind": "external",
                "status": "accepted",
                "justification": f.suppress_reason or f.status,
            }]
        results.append(result)
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "multi-sast",
                "informationUri": "https://example.internal/multi-sast",
                "version": "1.0.0",
                "rules": list(rules_index.values()),
            }},
            "results": results,
        }],
    }
    path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")


def write_json(findings: List[Finding], path: Path) -> None:
    # Sort so triage tools (and this file when eyeballed) see highest-confidence
    # findings first — same ordering as the xlsx / csv writers.
    payload = []
    for f in _report_sorted(findings):
        d = dataclasses.asdict(f)
        d["fingerprint"] = f.fingerprint()
        # Independence-weighted corroboration tier (see _confidence).
        conf_label, conf_score = _confidence(f.sources)
        d["confidence"] = conf_label
        d["confidence_score"] = round(conf_score, 2)
        # Raw code is in "snippet"; "vulnerable_code" carries real line numbers.
        d["vulnerable_code"] = format_snippet_with_lines(f.snippet, f.start_line)
        payload.append(d)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


# --------------------------------------------------------------------------------------
# Confidence — independence-weighted cross-scanner agreement
# --------------------------------------------------------------------------------------
# The `sources` list on a deduped finding tells us WHICH scanners fired. Naive
# corroboration (count entries) over-weights semgrep + opengrep because opengrep
# is a fork of semgrep and runs the same YAML rules — a hit from both is one
# independent signal, not two.
#
# SCANNER_FAMILY groups scanners by detection engine. Distinct families =
# genuinely independent signals; entries within a family collapse to one vote:
#
#   semgrep, opengrep     → semgrep-family (pattern SAST, shared rule syntax)
#   bandit                → Python AST rule catalog
#   bearer                → data-flow taint tracking
#   gosec                 → Go AST rule catalog
#   drogonsec             → Halodoc-internal pattern rules
#
# Confidence tier is derived from the count of distinct families reporting the
# finding (see `_confidence`). VERY HIGH means 3+ genuinely different engines
# converged; LOW means a single-scanner hit — which is not automatically wrong
# (some real bugs are only catchable by one scanner) but demands more triage.
# --------------------------------------------------------------------------------------

SCANNER_FAMILY: Dict[str, str] = {
    "semgrep":   "semgrep-family",
    "opengrep":  "semgrep-family",
    "bandit":    "bandit",
    "bearer":    "bearer",
    "gosec":     "gosec",
    "drogonsec": "drogonsec",
}


def _distinct_families(sources: Sequence[str]) -> Set[str]:
    """Extract the set of distinct scanner FAMILIES from a finding's `sources`
    list (each source is 'scanner:rule_id' or bare 'scanner')."""
    fams: Set[str] = set()
    for s in sources or []:
        if not s:
            continue
        scanner = s.split(":", 1)[0].strip()
        if scanner:
            fams.add(SCANNER_FAMILY.get(scanner, scanner))
    return fams


def _confidence(sources: Sequence[str]) -> "tuple[str, float]":
    """Return (label, score in 0.0-1.0) computed from independence-weighted
    corroboration:

        VERY HIGH  ≥ 3 independent scanner families
        HIGH       = 2 independent scanner families
        MEDIUM     = 1 non-semgrep family AND semgrep-family also fired,
                     OR both semgrep + opengrep fired (2 engines, 1 family)
        LOW        = single scanner hit

    Score is monotonic within tier so triagers can sort finer-grained."""
    fams = _distinct_families(sources)
    n_fams = len(fams)
    # Count distinct raw scanners too, so semgrep+opengrep (1 family, 2
    # scanners) reads as MEDIUM instead of LOW — same rule matched by both
    # engines is a marginal but real corroboration signal.
    scanners: Set[str] = set()
    for s in sources or []:
        if not s:
            continue
        scanners.add(s.split(":", 1)[0].strip())
    n_scanners = len(scanners)

    if n_fams >= 3:
        return ("VERY HIGH", 0.95)
    if n_fams == 2:
        return ("HIGH", 0.75)
    if n_fams == 1 and n_scanners >= 2:
        # only shape that lands here: semgrep + opengrep both fired
        return ("MEDIUM", 0.55)
    return ("LOW", 0.35)


CONFIDENCE_RANK = {"VERY HIGH": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


# --------------------------------------------------------------------------------------
# CRITICAL severity upgrade
#
# Every underlying scanner emits SARIF `level: error` (mapped to HIGH) as its top
# tier — none of them ever emits `security-severity: >= 9.0` or a raw "CRITICAL"
# label. As a result the raw pipeline produces zero CRITICAL findings even for
# RCE-class bugs. The rules below promote a small, high-precision subset of
# already-HIGH findings to CRITICAL after dedup so triagers see truly urgent
# bugs at the top of the report.
#
# Promotion is deliberately conservative: category-based upgrades require multi-
# family corroboration, and single-rule upgrades are limited to a hand-audited
# allowlist of RCE-class rule tokens. Everything else stays HIGH.
# --------------------------------------------------------------------------------------

# Semantic categories where any HIGH+ confidence hit is a blast-radius bug
# and warrants CRITICAL. Kept curated on purpose — every entry here should
# be a "if this is a true positive, an attacker owns the box" class.
_RCE_CRITICAL_CATEGORIES: Set[str] = {
    "code-injection",              # CWE-94: eval / exec / Runtime.exec on tainted input
    "command-injection",           # CWE-77 / CWE-78
    "insecure-deserialization",    # CWE-502: pickle / yaml.load / Jackson defaultTyping
    "sql-injection",               # CWE-89: only when scanner claims a taint chain
    "ssti",                        # server-side template injection
    "xxe",                         # CWE-611
    # Added 2026-09-23 after cross-repo audit showed these categories
    # producing HIGH findings that a triager consistently rated as
    # exploitable / equivalent-blast-radius to the classic RCE bucket.
    "path-traversal",              # CWE-22: arbitrary file R/W = data exfil + code write
    "ssrf",                        # CWE-918: cloud-metadata leak → creds → RCE
}

# Categories that indicate a broken auth boundary. Handlers matching the
# rules that emit these categories (idor-handler-*, handler-missing-authz-*)
# only fire on HTTP handler methods, so the path check is redundant — if the
# rule matched, the code IS on a public attack surface. Multi-family
# corroboration still required to keep the promotion conservative.
_AUTH_BYPASS_CATEGORIES: Set[str] = {
    "access-control",              # CWE-284 / CWE-639 / CWE-862
}

# Categories that are HIGH by default but genuinely CRITICAL when they land
# inside a production-scoped file. Weak crypto in a test file is a nag; weak
# crypto in prod config is an incident. Same for TLS-verification-off and
# credential/token-in-logs.
_PROD_SCOPED_CRITICAL_CATEGORIES: Set[str] = {
    "secrets",                     # original scoping
    "weak-crypto",                 # CWE-327: MD5 for passwords, AES-ECB, DES etc.
    "insecure-tls",                # CWE-295 / CWE-319: verify=false, useSSL=false in prod
    "info-disclosure",             # CWE-532: tokens/creds logged in prod
}

# Rule-ID substrings that a single-scanner hit is enough to justify CRITICAL.
# These are known-good, RCE-class rules where a true positive is inherently
# critical regardless of scanner independence.
_ALWAYS_CRITICAL_RULE_HINTS: tuple = (
    "jinja2-ssti",                 # unsandboxed Jinja2 Environment RCE
    "avoid_pickle",                # bandit B301 / B403 pickle deserialization
    "unsafe-yaml-load",            # yaml.load without SafeLoader
    "yaml_load",                   # bandit B506 yaml.load
    "exec-used",                   # bandit B102 exec
    "eval-used",                   # bandit B307 eval
    "hardcoded-aws-key",           # any AWS credential leak
    "detected-aws-account-id",     # scoped: only in prod files (secondary check)
    "detected-private-key",        # PEM / RSA private-key leak
    "detected-ssh-privkey",
    "detected-gcp-service-account",
    "google-api-key",              # LEAK-010 / LEAK-121 in prod scope
    "leak-010", "leak-121",        # drogonsec generic API key patterns (prod scope)
    "b301", "b307", "b506",        # bandit RCE-class test IDs
    "b608",                        # bandit SQL injection
    "javax-xml-xxe",
    "objectinputstream",           # Java insecure-deserialization sink
    # Custom prod-config rulepack (prod_config_antipatterns.semgrep.yml)
    "beego-runmode-dev-in-prod",
    "beego-admin-enabled-in-prod",
    "dev-qa-token-accepted-in-prod",
    "webhook-handler-missing-signature-check",
    # Added 2026-09-23 — high-blast-radius rules where a single-scanner hit
    # is inherently critical (Log4Shell class, template-eval, XXE variants).
    #
    # NOTE: `log4j-message-lookup-injection` and `log4shell` were removed
    # from this allowlist after a validation pass. The custom rule fires on
    # any user-data-to-logger flow, which is a real CWE-117 bug (log
    # injection / PII disclosure) but only true RCE if log4j < 2.17.0 is on
    # the classpath — a codebase-level fact we can't verify from source.
    # Findings still surface at HIGH severity via the rule's own ERROR level;
    # they simply don't force-CRITICAL.
    "spring-eval",                      # Spring SpEL evaluation on tainted input
    "user-eval-format-string",          # Django user-controlled eval
    "user-exec-format-string",
    "tainted-code-exec",                # semgrep aws-lambda code-exec sink
    "insecure-resteasy-deserialization",# JAX-RS insecure provider
    # Added 2026-09-23 — the CRITICAL-only rulepack in
    # semgrep-master/30_high_confidence/ that argus ships with. Each of
    # these detects an RCE-class pattern where a single-scanner hit is
    # inherently critical.
    "spring-spel-tainted-input",              # SpEL parseExpression from user input
    "unsafe-reflection-class-forname",        # Class.forName on tainted input
    "java-objectinputstream-untrusted",       # readObject on HTTP bytes
    "jackson-enable-default-typing",          # polymorphic-deser RCE gadget
    "xxe-java-documentbuilder-unsafe",        # DocumentBuilder default = XXE
    "xxe-java-saxparser-unsafe",              # SAXParser default = XXE
    "xxe-java-xmlinputfactory-unsafe",        # XMLInputFactory default = XXE
    "ssrf-tainted-url-java",                  # HTTP client with tainted URL (Java)
    "ssrf-tainted-url-go",                    # HTTP client with tainted URL (Go)
    # Fix D-continued (2026-09-23): additional custom rulepack detectors.
    "jwt-decode-without-verification",        # JWT payload trusted with no signature check
    "unrestricted-file-upload-",              # any of the per-language file-upload rules
)

# Path substrings that scope a HIGH finding into a production risk. Applied
# to any category in _PROD_SCOPED_CRITICAL_CATEGORIES.
_PROD_PATH_HINTS: tuple = (
    "config-prod", "config_prod", "prod.yml", "prod.yaml",
    "application_config_prod", "application-config-prod",
    "portal-d-prod", "sphere-prod", "sphere_prod",
    ".prod.env", "production.env", "env.prod",
    "dockerfile",                  # any Dockerfile that lands secrets in image
    "helm/prod", "k8s/prod", "manifests/prod",
    "-prod.yml", "-prod.yaml",     # e.g. bintan-consultation-prod.yml
    "_prod.yml", "_prod.yaml",
)


def _should_upgrade_to_critical(f: "Finding", confidence_label: str) -> Optional[str]:
    """Decide whether a finding should be re-labelled CRITICAL. Returns the
    promotion reason if yes, else None.

    HIGH is the normal candidate tier. MEDIUM is ALSO considered but only for
    clauses (d) and (e) — the explicit rule/message allowlist — because those
    are hard signals of blast-radius that override scanner-provided severity
    (some scanners downgrade or fail to tag security-severity even for RCE-
    class rules). Category-based clauses stay HIGH-only to keep them
    conservative.

    Promotion paths, evaluated in order:
      (a) RCE-class category (code-injection, command-injection,
          insecure-deserialization, sql-injection, ssti, xxe, path-traversal,
          ssrf) + ≥2 independent scanner FAMILIES agreeing. HIGH only.
      (b) Auth-bypass class (access-control) + ≥2 independent families.
          HIGH only.
      (c) HIGH finding in a production-scoped file (config-prod.yml,
          Dockerfile, helm/prod, ...) if category is secrets, weak-crypto,
          insecure-tls, or info-disclosure. HIGH only.
      (d) Explicit RCE-class rule allowlist — single-scanner is enough
          because the rule itself carries the blast-radius signal. Also
          accepts MEDIUM findings so scanner-severity misses don't hide
          Log4Shell / SSRF / etc.
      (e) Message-level phrase match — HIGH+MEDIUM fallback for rules with
          unrecognised IDs but explicit RCE language in the message."""
    sev = f.severity
    if sev not in {"HIGH", "MEDIUM"}:
        return None

    rule_lc = (f.rule_id or "").lower()
    msg_lc = (f.message or "").lower()
    path_lc = (f.path or "").lower()
    cat = (f.category or "").lower()

    # Clauses (a)-(c) require HIGH severity — they're the conservative,
    # category-based promotion paths. MEDIUM findings fall through to the
    # rule/message allowlists below.
    if sev == "HIGH":
        # (a) RCE-class category corroborated by ≥2 independent scanner families.
        if cat in _RCE_CRITICAL_CATEGORIES and confidence_label in {"HIGH", "VERY HIGH"}:
            return f"rce-class category '{cat}' corroborated by {confidence_label} confidence"

        # (b) Auth-bypass on HTTP handler surface with cross-family corroboration.
        if cat in _AUTH_BYPASS_CATEGORIES and confidence_label in {"HIGH", "VERY HIGH"}:
            return f"auth-bypass category '{cat}' corroborated by {confidence_label} confidence"

        # (c) HIGH severity in a production-scoped file (secrets, weak-crypto,
        #     insecure-tls, info-disclosure). Prod scoping is enough on its own.
        if cat in _PROD_SCOPED_CRITICAL_CATEGORIES and any(h in path_lc for h in _PROD_PATH_HINTS):
            return f"{cat or 'finding'} in production-scoped path"

    # (d) Explicit RCE-class rule allowlist: single-scanner is enough because the
    #     rule itself carries the blast-radius signal. Accepts HIGH or MEDIUM.
    for hint in _ALWAYS_CRITICAL_RULE_HINTS:
        if hint in rule_lc:
            return f"RCE-class rule token '{hint}'"

    # (e) Message-level pattern for cross-scanner phrases that hard-signal
    # RCE. Kept intentionally short — one entry per phrase that a triager
    # would treat as a hard signal. `log4shell` / `jndi lookup` were
    # removed 2026-09-23 after validation showed those phrases in argus's
    # own log4j rule's descriptive message text, double-promoting findings
    # already surfaced by the rule allowlist path — leading to CRITICAL
    # inflation on log-injection findings that are really CWE-117, not RCE.
    for phrase in ("remote code execution", "deserialization of untrusted data",
                   "arbitrary command execution", "template injection",
                   "unsandboxed jinja",
                   "server-side request forgery",
                   "path traversal to arbitrary"):
        if phrase in msg_lc:
            return f"RCE-class phrase '{phrase}'"

    return None


def upgrade_severities(findings: "List[Finding]") -> "tuple[int, Dict[str, int]]":
    """Apply CRITICAL upgrade rules in-place. Returns (n_upgrades, per_reason
    counts) for logging."""
    upgrades = 0
    reasons: Dict[str, int] = {}
    for f in findings:
        conf_label, _ = _confidence(f.sources)
        reason = _should_upgrade_to_critical(f, conf_label)
        if reason:
            f.severity = "CRITICAL"
            upgrades += 1
            # Bucket the reason for the summary line. Strip variable tails —
            # scanner-confidence noun ("HIGH confidence"), path noise, etc. —
            # so counts group by trigger clause, not by finding.
            key = reason.split(" corroborated", 1)[0]
            key = key.split(" in production", 1)[0] + (
                " in production-scoped path" if " in production" in reason else ""
            )
            key = key.split(" '", 1)[0]
            reasons[key] = reasons.get(key, 0) + 1
    return upgrades, reasons


CSV_COLUMNS = [
    "fingerprint", "status", "severity", "confidence",
    "category", "scanner", "sources",
    "rule_id", "cwe", "path", "start_line", "end_line",
    # Added 2026-09-23: file-rule roll-up puts extra hit line numbers here.
    "occurrences",
    "message",
    "vulnerable_code",
    # Added 2026-09-23: concrete fix guidance keyed off rule_id.
    "remediation",
    "suppress_reason",
]


def _report_sorted(findings: List[Finding]) -> List[Finding]:
    """Sort for triage: HIGHEST-confidence first, then most-severe, then by
    file/line. Confidence takes precedence because a VERY HIGH-confidence
    MEDIUM finding is almost always a truer positive than a LOW-confidence
    HIGH finding — so triagers see the near-certain bugs at the top of the
    spreadsheet."""
    def key(f: Finding):
        conf_label, conf_score = _confidence(f.sources)
        return (
            -CONFIDENCE_RANK.get(conf_label, 0),
            -conf_score,
            -SEV_RANK.get(f.severity, 0),
            f.path, f.start_line, f.rule_id,
        )
    return sorted(findings, key=key)


def _report_row(f: Finding) -> dict:
    conf_label, conf_score = _confidence(f.sources)
    return {
        "fingerprint": f.fingerprint(),
        "status": f.status,
        "severity": f.severity,
        "confidence": conf_label,
        "category": f.category or "",
        "scanner": f.scanner,
        "sources": ";".join(f.sources),
        "rule_id": f.rule_id,
        "cwe": f.cwe or "",
        "path": f.path,
        "start_line": f.start_line,
        "end_line": f.end_line,
        # File-rule roll-up: comma-separated extra hit lines from the same
        # (path, rule_id) cluster. Empty for singleton findings.
        "occurrences": ", ".join(str(l) for l in (f.occurrences or [])),
        # Collapse newlines so each finding stays on a single row.
        "message": (f.message or "").replace("\r", " ").replace("\n", " ").strip(),
        # The vulnerable code with real line numbers; multi-line cells are fine
        # in quoted CSV and in xlsx.
        "vulnerable_code": format_snippet_with_lines(f.snippet, f.start_line),
        # Concrete remediation guidance from REMEDIATION_TEMPLATES.
        "remediation": (f.remediation or "").replace("\r", " ").replace("\n", " ").strip(),
        "suppress_reason": f.suppress_reason or "",
    }


def write_csv(findings: List[Finding], path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, quoting=csv.QUOTE_MINIMAL)
        w.writeheader()
        for f in _report_sorted(findings):
            w.writerow(_report_row(f))


# Workbook sheet titles (one workbook per repo: findings.xlsx).
XLSX_SHEETS = ("Raw Findings", "Deduplicated", "False Positives Removed")

_XLSX_COL_WIDTHS = {
    "fingerprint": 18, "status": 14, "severity": 10, "confidence": 12,
    "category": 20, "scanner": 10, "sources": 24, "rule_id": 32, "cwe": 10,
    "path": 36, "start_line": 10, "end_line": 9, "message": 60,
    "vulnerable_code": 70, "suppress_reason": 36,
}


def write_xlsx_workbook(raw: List[Finding], deduped: List[Finding],
                        suppressed: List[Finding], path: Path) -> bool:
    """Write findings.xlsx with three sheets:

      1. Raw Findings            — every finding from every scanner, before dedup
      2. Deduplicated            — after cross-scanner deduplication (open + suppressed,
                                   distinguished by the 'status' column)
      3. False Positives Removed — findings suppressed by triage, with reasons

    Requires openpyxl; if it isn't installed the workbook is skipped (the CSV/
    JSON/SARIF reports are still written) and a hint is printed once.
    """
    try:
        import openpyxl
        from openpyxl.styles import Alignment, Font, PatternFill
        from openpyxl.utils import get_column_letter
    except ImportError:
        global _XLSX_HINTED
        if not _XLSX_HINTED:
            _status("   [NOTE ] openpyxl not installed -> findings.xlsx skipped "
                    "(pip install openpyxl to enable the 3-sheet workbook)")
            _XLSX_HINTED = True
        return False

    header_font = Font(name="Arial", bold=True, color="FFFFFF")
    header_fill = PatternFill("solid", fgColor="4472C4")
    body_font = Font(name="Arial", size=10)
    code_font = Font(name="Courier New", size=9)
    wrap = Alignment(wrap_text=True, vertical="top")
    top = Alignment(vertical="top")
    sev_fill = {
        "CRITICAL": PatternFill("solid", fgColor="C00000"),
        "HIGH": PatternFill("solid", fgColor="ED7D31"),
        "MEDIUM": PatternFill("solid", fgColor="FFD966"),
    }
    sev_font_white = Font(name="Arial", size=10, bold=True, color="FFFFFF")
    sev_font_dark  = Font(name="Arial", size=10, bold=True)
    # Confidence colouring — deeper green = higher independence-weighted
    # corroboration; grey = single-scanner hit (still worth triaging, just
    # not backed by cross-engine consensus).
    conf_fill = {
        "VERY HIGH": PatternFill("solid", fgColor="15803D"),  # green
        "HIGH":      PatternFill("solid", fgColor="13A5A0"),  # teal
        "MEDIUM":    PatternFill("solid", fgColor="EAB308"),  # amber
        "LOW":       PatternFill("solid", fgColor="9CA3AF"),  # grey
    }
    conf_font_white = Font(name="Arial", size=10, bold=True, color="FFFFFF")
    conf_font_dark  = Font(name="Arial", size=10, bold=True)

    wb = openpyxl.Workbook()
    wb.remove(wb.active)
    for title, rows in zip(XLSX_SHEETS, (raw, deduped, suppressed)):
        ws = wb.create_sheet(title)
        ws.append(CSV_COLUMNS)
        for cell in ws[1]:
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = top
        for f in _report_sorted(rows):
            row = _report_row(f)
            ws.append([row[c] for c in CSV_COLUMNS])
            r = ws.max_row
            for cell in ws[r]:
                cell.font = body_font
                cell.alignment = top
            sev_cell = ws.cell(row=r, column=CSV_COLUMNS.index("severity") + 1)
            if f.severity in sev_fill:
                sev_cell.fill = sev_fill[f.severity]
                sev_cell.font = sev_font_dark if f.severity == "MEDIUM" else sev_font_white
            conf_label, _ = _confidence(f.sources)
            conf_cell = ws.cell(row=r, column=CSV_COLUMNS.index("confidence") + 1)
            if conf_label in conf_fill:
                conf_cell.fill = conf_fill[conf_label]
                # MEDIUM = amber → dark font for readability; the rest are dark
                # backgrounds → white font.
                conf_cell.font = conf_font_dark if conf_label == "MEDIUM" else conf_font_white
            msg_cell = ws.cell(row=r, column=CSV_COLUMNS.index("message") + 1)
            msg_cell.alignment = wrap
            code_cell = ws.cell(row=r, column=CSV_COLUMNS.index("vulnerable_code") + 1)
            code_cell.font = code_font
            code_cell.alignment = wrap
            reason_cell = ws.cell(row=r, column=CSV_COLUMNS.index("suppress_reason") + 1)
            reason_cell.alignment = wrap
        for i, col in enumerate(CSV_COLUMNS, 1):
            ws.column_dimensions[get_column_letter(i)].width = _XLSX_COL_WIDTHS.get(col, 14)
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = f"A1:{get_column_letter(len(CSV_COLUMNS))}{max(ws.max_row, 1)}"
    wb.save(path)
    return True


_XLSX_HINTED = False


def print_summary(results: List[ScanResult], findings: List[Finding], raw_total: int,
                  suppressed_total: int = 0) -> None:
    def bar(n): return "#" * min(n, 40)
    print("\n" + "=" * 68)
    print(" SCANNER RESULTS")
    print("=" * 68)
    for r in sorted(results, key=lambda x: x.scanner):
        mark = {"ok": "OK ", "error": "ERR", "skipped": "-- "}[r.status]
        print(f"  [{mark}] {r.scanner:<10} {len(r.findings):>4} findings  "
              f"({r.duration_s:4.1f}s)  {r.detail}")
    by_sev = {k: 0 for k in SEV_RANK}
    for f in findings:
        by_sev[f.severity] += 1
    print("\n" + "=" * 68)
    suffix = f" -> {len(findings)} open, {suppressed_total} suppressed" if suppressed_total else ""
    print(f" AGGREGATED FINDINGS  (raw {raw_total} -> deduped "
          f"{len(findings) + suppressed_total}{suffix})")
    print("=" * 68)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        print(f"  {sev:<9} {by_sev[sev]:>4}  {bar(by_sev[sev])}")
    top = sorted(findings, key=lambda f: (-SEV_RANK[f.severity], f.path, f.start_line))[:10]
    if top:
        print("\n  Top findings:")
        for f in top:
            src = ",".join(sorted({s.split(':')[0] for s in f.sources}))
            print(f"   {f.severity:<8} {f.path}:{f.start_line}  {f.rule_id}  [{src}]")
            print(f"            {f.message[:88]}")
            if f.snippet:
                first_line = f.snippet.splitlines()[0].strip()
                print(f"            > {f.start_line}: {first_line[:80]}")
    print()


# --------------------------------------------------------------------------------------
# Config overrides
# --------------------------------------------------------------------------------------

def apply_config(path: Path) -> None:
    """
    JSON like:
    {
      "semgrep": {"enabled": true, "cmd": ["semgrep","scan","--config","p/ci",
                                           "--sarif-output={output}","{target}"]},
      "opengrep": {"cmd": ["opengrep","scan","--config","/rules","--sarif-output={output}","{target}"]},
      "drogonsec": {"languages": ["python","go"]}
    }
    """
    cfg = json.loads(path.read_text(encoding="utf-8"))
    for name, spec in cfg.items():
        a = ADAPTERS_BY_NAME.get(name)
        if not a:
            log.warning("config: unknown scanner '%s' ignored", name)
            continue
        if spec.get("enabled") is False:
            ADAPTERS.remove(a)
            del ADAPTERS_BY_NAME[name]
            continue
        if "cmd" in spec:
            a.cmd_template = list(spec["cmd"])
        if "binary" in spec:
            a.binary = spec["binary"]
        if "languages" in spec:
            a.languages = set(spec["languages"])
        if "out_ext" in spec:
            a.out_ext = spec["out_ext"]




# ======================================================================================
# GitLab integration: runtime inputs, crawler, clone-and-scan orchestration, menu.
# (The scanning engine above is used as-is; this section is the GitLab glue.)
# ======================================================================================

import getpass
import tempfile
from urllib.parse import urlparse

try:
    import requests
except ImportError:
    print("This tool needs the 'requests' package. Install it with:\n"
          "    pip install requests", file=sys.stderr)
    sys.exit(1)

try:
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except Exception:  # pragma: no cover - retries are optional
    HTTPAdapter = None
    Retry = None


SUGGESTED_GITLAB_URL = "https://gitlab.example.com"
PER_PAGE = 100

# A single shared HTTP session, reconfigured in main() from CLI flags. It
# honors the standard HTTPS_PROXY / HTTP_PROXY / NO_PROXY and REQUESTS_CA_BUNDLE
# environment variables automatically.
SESSION = requests.Session()


def make_session(ca_bundle=None, insecure=False, retries=3):
    """Build the shared session: optional custom CA bundle or no-verify, plus
    automatic retry/backoff for transient network errors (resets, 5xx, 429)."""
    s = requests.Session()
    if insecure:
        s.verify = False
        try:
            import urllib3
            urllib3.disable_warnings()
        except Exception:
            pass
    elif ca_bundle:
        s.verify = ca_bundle
    if HTTPAdapter and Retry and retries > 0:
        retry = Retry(
            total=retries, connect=retries, read=retries,
            backoff_factor=1.0,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET"]),
        )
        adapter = HTTPAdapter(max_retries=retry)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
    return s


def _explain_conn_error(base_url: str, exc: Exception) -> None:
    print(f"\nCould not reach the GitLab API at:\n    {base_url}\n", file=sys.stderr)
    print(f"Transport error: {type(exc).__name__}: {str(exc)[:200]}\n", file=sys.stderr)
    print(
        "This failed at the network/TLS layer, so your token was never checked.\n"
        "Common causes and fixes:\n"
        "  * Not on the VPN / corporate network the host lives behind.\n"
        "      -> Connect to the VPN and retry (most common for internal hosts).\n"
        "  * A corporate proxy / TLS inspection (Zscaler, Netskope, ...) resetting\n"
        "    direct connections.\n"
        "      -> Route through it:  export HTTPS_PROXY=http://<proxy-host>:<port>\n"
        "         (HTTPS_PROXY / HTTP_PROXY / NO_PROXY are honored automatically.)\n"
        "  * That proxy presents its own TLS certificate.\n"
        "      -> Trust its CA:  --ca-bundle /path/to/corp-ca.pem\n"
        "         (or set REQUESTS_CA_BUNDLE); last resort: --insecure\n"
        "  * Wrong base URL, or the host is down.\n"
        f"      -> Sanity check:  curl -I {base_url}/api/v4/version\n",
        file=sys.stderr,
    )


def gitlab_get(base_url: str, url: str, **kwargs):
    """GET via the shared session, turning transport failures into a clean,
    actionable message instead of a raw traceback."""
    try:
        return SESSION.get(url, **kwargs)
    except requests.exceptions.RequestException as exc:
        _explain_conn_error(base_url, exc)
        sys.exit(1)

# Crawl CSV columns (also the schema the scan action's --csv mode expects).
CRAWL_FIELDS = [
    "id", "name", "path_with_namespace", "web_url", "visibility",
    "default_branch", "last_activity_at", "archived",
]

# Per-repo scan roll-up summary columns.
SCAN_SUMMARY_FIELDS = [
    "path_with_namespace", "web_url", "status", "languages", "scanners",
    "critical", "high", "medium", "low", "info", "suppressed",
    "total_findings", "output_dir",
]


# --- runtime input helpers -----------------------------------------------------------

def prompt_text(label: str, default: Optional[str] = None, required: bool = False) -> Optional[str]:
    while True:
        if default is not None:
            raw = input(f"{label} [{default}]: ").strip()
            return raw or default
        raw = input(f"{label}: ").strip()
        if raw:
            return raw
        if not required:
            return None
        print("  This value is required.")


def prompt_yes_no(label: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    while True:
        raw = input(f"{label} [{suffix}]: ").strip().lower()
        if not raw:
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print("  Please answer y or n.")


def prompt_int(label: str, default: int, minimum: Optional[int] = None) -> int:
    while True:
        raw = input(f"{label} [{default}]: ").strip()
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            print("  Please enter a whole number.")
            continue
        if minimum is not None and value < minimum:
            print(f"  Please enter a number >= {minimum}.")
            continue
        return value


def prompt_optional_int(label: str, minimum: Optional[int] = None) -> Optional[int]:
    while True:
        raw = input(f"{label}: ").strip()
        if not raw:
            return None
        try:
            value = int(raw)
        except ValueError:
            print("  Please enter a whole number, or leave blank.")
            continue
        if minimum is not None and value < minimum:
            print(f"  Please enter a number >= {minimum}, or leave blank.")
            continue
        return value


def prompt_choice(label: str, choices, default: str) -> str:
    shown = "/".join(choices)
    while True:
        raw = input(f"{label} ({shown}) [{default}]: ").strip()
        if not raw:
            return default
        for c in choices:
            if raw.lower() == c.lower():
                return c
        print(f"  Please choose one of: {shown}")


def get_access_token() -> str:
    token = getpass.getpass("Enter your GitLab Personal Access Token: ").strip()
    if not token:
        print("No token entered. Exiting.", file=sys.stderr)
        sys.exit(1)
    return token


# --- GitLab REST API -----------------------------------------------------------------

def verify_token(base_url: str, token: str) -> dict:
    resp = gitlab_get(
        base_url,
        f"{base_url}/api/v4/user",
        headers={"PRIVATE-TOKEN": token},
        timeout=15,
    )
    if resp.status_code != 200:
        print(f"Token check failed ({resp.status_code}): {resp.text[:200]}", file=sys.stderr)
        sys.exit(1)
    return resp.json()


def crawl_projects(base_url: str, token: str, group: Optional[str], membership_only: bool) -> list:
    headers = {"PRIVATE-TOKEN": token}
    projects: list = []
    page = 1

    if group:
        encoded_group = requests.utils.quote(group, safe="")
        endpoint = f"{base_url}/api/v4/groups/{encoded_group}/projects"
    else:
        endpoint = f"{base_url}/api/v4/projects"

    while True:
        params = {
            "per_page": PER_PAGE,
            "page": page,
            "order_by": "last_activity_at",
            "sort": "desc",
            "include_subgroups": "true" if group else None,
        }
        if not group:
            params["membership"] = "true" if membership_only else "false"
            params["simple"] = "true"

        resp = gitlab_get(base_url, endpoint, headers=headers, params=params, timeout=30)
        if resp.status_code != 200:
            print(f"Request failed ({resp.status_code}): {resp.text[:200]}", file=sys.stderr)
            break

        batch = resp.json()
        if not batch:
            break

        projects.extend(batch)
        print(f"  fetched page {page} ({len(batch)} projects, {len(projects)} total so far)")

        next_page = resp.headers.get("X-Next-Page")
        if not next_page:
            break
        page = int(next_page)

    return projects


def get_single_project(base_url: str, token: str, repo_path: str) -> dict:
    encoded = requests.utils.quote(repo_path.strip("/"), safe="")
    resp = gitlab_get(
        base_url,
        f"{base_url}/api/v4/projects/{encoded}",
        headers={"PRIVATE-TOKEN": token},
        timeout=30,
    )
    if resp.status_code != 200:
        print(f"Could not find project '{repo_path}' ({resp.status_code}): "
              f"{resp.text[:200]}", file=sys.stderr)
        sys.exit(1)
    return resp.json()


# --- CSV helpers ---------------------------------------------------------------------

def write_crawl_csv(projects: list, output_path: str) -> None:
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CRAWL_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for p in projects:
            writer.writerow(p)


# CSV column headers that may hold the repo's git/clone URL, in priority order.
URL_HEADER_PRIORITY = [
    "clone_url", "http_url_to_repo", "git_http_url", "git_url",
    "repo_url", "url", "web_url", "ssh_url_to_repo",
]


def _looks_like_git_url(value: str) -> bool:
    v = (value or "").strip()
    return v.startswith(("http://", "https://", "git@")) or v.endswith(".git")


def derive_repo_key(url: str) -> str:
    """Turn a clone URL into a namespace-style key for output dirs/summary,
    e.g. https://gitlab.example.com/group/sub/proj.git -> group/sub/proj."""
    u = (url or "").strip()
    if u.startswith("git@"):                       # git@host:group/proj.git
        part = u.split(":", 1)[1] if ":" in u else u
    else:
        part = urlparse(u).path
    part = part.strip("/")
    if part.endswith(".git"):
        part = part[:-4]
    return part or u


def _project_from_url(url: str) -> dict:
    """Minimal project dict whose clone target is the CSV's git URL verbatim."""
    return {
        "clone_url": url.strip(),                  # used as-is by build_clone_url
        "path_with_namespace": derive_repo_key(url),
        "web_url": url.strip(),
        "default_branch": None,
    }


def load_projects_csv(csv_path: str, include_archived: bool, limit: Optional[int]) -> list:
    """Load repos to scan from a CSV, cloning from a git URL column read
    directly out of the file (rather than rebuilding it from other fields)."""
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        rows = list(reader)

    # Case 1: a header-less single-column file that is just a list of URLs.
    if len(fieldnames) == 1 and _looks_like_git_url(fieldnames[0]):
        urls = [fieldnames[0]] + [(r.get(fieldnames[0]) or "") for r in rows]
        projects = [_project_from_url(u) for u in urls if u.strip()]
        return projects[:limit] if limit else projects

    # Locate the git-URL column: prefer known header names, else sniff a
    # column whose values look like git URLs.
    lower = {(fn or "").lower(): fn for fn in fieldnames}
    url_field = next((lower[c] for c in URL_HEADER_PRIORITY if c in lower), None)
    if url_field is None and rows:
        for fn in fieldnames:
            if _looks_like_git_url(rows[0].get(fn) or ""):
                url_field = fn
                break
    if url_field is None:
        raise SystemExit(
            f"No git URL column found in {csv_path}. Headers present: "
            f"{', '.join(fieldnames) or '(none)'}. Add a column named one of: "
            f"{', '.join(URL_HEADER_PRIORITY)} (or a column whose values are git URLs)."
        )

    projects = []
    for row in rows:
        url = (row.get(url_field) or "").strip()
        if not url:
            continue
        if not include_archived and str(row.get("archived", "")).lower() == "true":
            continue
        proj = _project_from_url(url)
        # Keep richer metadata when the CSV also happens to have it.
        if row.get("path_with_namespace"):
            proj["path_with_namespace"] = row["path_with_namespace"]
        if row.get("default_branch"):
            proj["default_branch"] = row["default_branch"]
        if row.get("web_url"):
            proj["web_url"] = row["web_url"]
        if row.get("archived") is not None:
            proj["archived"] = row.get("archived", "")
        projects.append(proj)

    if limit:
        projects = projects[:limit]
    return projects


def filter_projects(projects: list, include_archived: bool, limit: Optional[int]) -> list:
    out = []
    for p in projects:
        if not include_archived and str(p.get("archived", "")).lower() == "true":
            continue
        if not (p.get("web_url") or p.get("http_url_to_repo")):
            continue
        out.append(p)
    if limit:
        out = out[:limit]
    return out


# --- checkpoint / summary (resume support) -------------------------------------------

def load_checkpoint(path: Path) -> set:
    if not path.exists():
        return set()
    return {line.strip() for line in path.read_text().splitlines() if line.strip()}


def mark_done(path: Path, repo_key: str) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(repo_key + "\n")


DEFAULT_SUMMARY_NAME = "sast_summary.csv"


def resolve_summary_path(value: str) -> Path:
    """Turn whatever was given for the summary CSV into a writable file path.

    Accepts a file path, a directory (the summary is placed inside it as
    sast_summary.csv), or a path with a trailing separator. Also creates any
    missing parent directories, so --out-summary out/reports/summary.csv works
    on a fresh checkout.
    """
    raw = str(value).strip() or DEFAULT_SUMMARY_NAME
    p = Path(raw).expanduser()
    # A directory (existing, or written with a trailing slash) -> file inside it.
    if p.is_dir() or raw.endswith((os.sep, "/")):
        p = p / DEFAULT_SUMMARY_NAME
    elif p.suffix == "":
        # No extension and not an existing dir: treat as a directory the user
        # wants the summary in, rather than creating an extension-less file.
        p = p / DEFAULT_SUMMARY_NAME
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def append_summary(csv_path: Path, row: dict) -> None:
    csv_path = Path(csv_path)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    is_new = not csv_path.exists()
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=SCAN_SUMMARY_FIELDS, extrasaction="ignore")
        if is_new:
            writer.writeheader()
        writer.writerow(row)


# --------------------------------------------------------------------------------------
# Per-finding roll-up CSV (flat view across all scanned repos)
#
# sast_summary.csv is a per-repo AGGREGATE — one row per scanned target, with
# severity counts. Triagers who want to see WHICH specific vulnerability fired
# at WHICH file:line — with the actual vulnerable snippet in the same row —
# have to open each repo's findings.csv individually. On a large run that
# means dozens of files.
#
# findings_summary.csv is the flat companion: one row per finding across
# every scanned repo, with the repo tag, severity, confidence tier, file
# path, line number, line-numbered vulnerable-code snippet, message and
# fingerprint all in one place. Same append semantics as sast_summary.csv
# so consecutive runs accumulate. Delete the file to reset.
# --------------------------------------------------------------------------------------

FINDINGS_SUMMARY_FIELDS = [
    "repo",             # path_with_namespace for GitLab scans / local path for --path
    "severity",         # CRITICAL / HIGH / MEDIUM / LOW / INFO
    "confidence",       # VERY HIGH / HIGH / MEDIUM / LOW (independence-weighted)
    "rule_id",          # scanner's own rule id (e.g. B608, G404, mhealth.python.…)
    "cwe",              # CWE- number when available
    "category",         # inferred category bucket (secrets / xss / …)
    "scanner",          # primary scanner that reported it
    "sources",          # semicolon-joined list of scanner:rule pairs
    "path",             # repo-relative source file path
    "start_line",       # 1-based start line of the vulnerable code
    "end_line",         # end line (equal to start_line for point findings)
    "message",          # scanner's own single-line description
    "vulnerable_code",  # the offending code lines, prefixed with real line numbers
    "fingerprint",      # deterministic id; matches findings.json / suppression store
    "status",           # open / false_positive / accepted_risk / wont_fix
    "suppress_reason",  # populated when the finding was auto- or manually suppressed
]


def resolve_findings_summary_path(summary_path: Path) -> Path:
    """Derive the per-finding roll-up CSV path from the per-repo summary path
    passed via --out-summary: same directory, fixed name findings_summary.csv."""
    return Path(summary_path).parent / "findings_summary.csv"


def append_findings_summary(csv_path: Path, repo_key: str,
                            findings: List["Finding"]) -> None:
    """Append every finding in `findings` as a row to findings_summary.csv.

    Each row carries the exact file:line location plus the line-numbered
    `vulnerable_code` snippet — the same format the per-repo findings.csv
    uses, so a triager can review real code without hopping between files.
    """
    csv_path = Path(csv_path)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    is_new = not csv_path.exists()
    with open(csv_path, "a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(
            fh, fieldnames=FINDINGS_SUMMARY_FIELDS,
            extrasaction="ignore", quoting=csv.QUOTE_MINIMAL,
        )
        if is_new:
            writer.writeheader()
        for f in _report_sorted(findings):
            conf_label, _ = _confidence(f.sources)
            writer.writerow({
                "repo":            repo_key,
                "severity":        f.severity,
                "confidence":      conf_label,
                "rule_id":         f.rule_id,
                "cwe":             f.cwe or "",
                "category":        f.category or "",
                "scanner":         f.scanner,
                "sources":         ";".join(f.sources),
                "path":            f.path,
                "start_line":      f.start_line,
                "end_line":        f.end_line,
                # Collapse newlines in the message so it stays on one row;
                # the vulnerable_code column carries the real, multi-line
                # snippet in a quoted CSV cell.
                "message":         (f.message or "").replace("\r", " ")
                                                     .replace("\n", " ").strip(),
                "vulnerable_code": format_snippet_with_lines(f.snippet, f.start_line),
                "fingerprint":     f.fingerprint(),
                "status":          f.status,
                "suppress_reason": f.suppress_reason or "",
            })


# --- clone URL (token embedded transiently, never persisted) -------------------------

def build_clone_url(project: dict, token: str) -> str:
    # Prefer a git URL taken directly from the CSV; otherwise fall back to the
    # GitLab API fields (http_url_to_repo, or web_url + .git).
    repo_url = project.get("clone_url") or project.get("http_url_to_repo")
    if not repo_url:
        web = project.get("web_url", "")
        repo_url = web if web.endswith(".git") else (web + ".git" if web else "")
    # Inject the token only for HTTP(S) clones; SSH/other URLs are used as-is.
    if repo_url.startswith(("http://", "https://")):
        parsed = urlparse(repo_url)
        netloc = f"oauth2:{token}@{parsed.netloc}"
        return parsed._replace(netloc=netloc).geturl()
    return repo_url


def safe_dir_name(path_with_namespace: str) -> str:
    return path_with_namespace.replace("/", "__")


# --- scan one repo: clone -> engine -> summarize -> cleanup --------------------------

def _run_rule_profile(root: Path, out_dir: Path, extra_configs: List[str],
                      timeout: int) -> None:
    """Optional --profile-rules pass: run semgrep once with --time --json,
    then emit rule_profile.csv listing every rule sorted by cost with its
    finding count, so operators can spot dead-and-expensive rules to prune.

    This is a dedicated second pass — the primary scan stays on SARIF for
    downstream consumers. It's opt-in because it roughly doubles semgrep
    wall-clock on the target; the payoff is a permanent baseline cut once
    the dead rules are removed."""
    sg = ADAPTERS_BY_NAME.get("semgrep")
    if sg is None or not sg.available():
        _status("   [PROFILE] semgrep not available — rule profile skipped")
        return
    profile_json = out_dir / "rule_profile.json"
    # Reuse semgrep's own template so registry packs + excludes match the real
    # scan; strip the SARIF output flags and swap in JSON + --time.
    base_cmd = sg.build_cmd(root, out_dir / "semgrep.sarif",
                            extra_configs=extra_configs)
    profile_cmd: List[str] = []
    skip_next = False
    for tok in base_cmd:
        if skip_next:
            skip_next = False
            continue
        if tok == "--sarif":
            continue
        if tok.startswith("--sarif-output="):
            continue
        if tok == "--sarif-output":
            skip_next = True
            continue
        profile_cmd.append(tok)
    profile_cmd.extend(["--json", "--time", "--output", str(profile_json)])
    _status("   [PROFILE] running rule-timing pass (semgrep --time --json) ...")
    log.info("[profile] running: %s", " ".join(profile_cmd))
    t0 = time.time()
    try:
        proc = subprocess.run(profile_cmd, capture_output=True, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired:
        _status("   [PROFILE] timed out — no rule_profile.csv written")
        return
    except Exception as e:  # noqa: BLE001
        _status(f"   [PROFILE] failed to launch: {e}")
        return
    dur = time.time() - t0
    if not profile_json.exists() or profile_json.stat().st_size == 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-2:]
        _status(f"   [PROFILE] no output (rc={proc.returncode}) ({dur:.1f}s) "
                + (" | ".join(tail) if tail else ""))
        return
    try:
        data = json.loads(profile_json.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        _status(f"   [PROFILE] could not parse output: {e}")
        return
    # Count findings per rule (semgrep JSON: results[].check_id).
    finding_counts: Dict[str, int] = {}
    for r in data.get("results", []) or []:
        rid = r.get("check_id") or "unknown"
        finding_counts[rid] = finding_counts.get(rid, 0) + 1
    # Timing block schema (semgrep --time --json):
    #   time.rules   : ordered list of rule IDs (strings)
    #   time.targets : list of {path, match_times[], parse_times[], run_time}
    #                  where match_times[i] / parse_times[i] correspond to
    #                  time.rules[i]. Sum across targets to get per-rule cost.
    time_block = data.get("time") or {}
    rule_ids = time_block.get("rules") or []
    n_rules = len(rule_ids)
    match_totals = [0.0] * n_rules
    parse_totals = [0.0] * n_rules
    for tgt in time_block.get("targets") or []:
        mt = tgt.get("match_times") or []
        pt = tgt.get("parse_times") or []
        for i in range(min(n_rules, len(mt))):
            v = mt[i]
            if isinstance(v, (int, float)) and v > 0:
                match_totals[i] += float(v)
        for i in range(min(n_rules, len(pt))):
            v = pt[i]
            if isinstance(v, (int, float)) and v > 0:
                parse_totals[i] += float(v)
    rows: List[tuple] = []
    for i, rid in enumerate(rule_ids):
        parse_t = parse_totals[i]
        match_t = match_totals[i]
        run_t = parse_t + match_t
        fc = finding_counts.get(rid, 0)
        dead = "yes" if fc == 0 and match_t >= 0.05 else ""
        rows.append((rid, parse_t, match_t, run_t, fc, dead))
    rows.sort(key=lambda r: (-r[3], -r[2]))
    csv_path = out_dir / "rule_profile.csv"
    with csv_path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["rule_id", "parse_time_s", "match_time_s",
                    "run_time_s", "findings", "dead_and_costly"])
        for rid, pt, mt, rt, fc, dead in rows:
            w.writerow([rid, f"{pt:.4f}", f"{mt:.4f}", f"{rt:.4f}", fc, dead])
    n_dead = sum(1 for r in rows if r[5] == "yes")
    _status(f"   [PROFILE] wrote {csv_path} — {len(rows)} rules profiled, "
            f"{n_dead} dead-and-costly (≥50ms match_time, 0 findings) "
            f"— {dur:.1f}s")


def run_pipeline(root: Path, out_dir: Path, only: Optional[set], skip: set,
                 scanner_workers: int, timeout: int,
                 suppressions: Optional[SuppressionStore] = None,
                 auto_fp: bool = True,
                 dedup_line_window: int = DEFAULT_DEDUP_LINE_WINDOW,
                 rulepack_filter: bool = True,
                 profile_rules: bool = False):
    """Drive the inlined engine over a local checkout. Stage flow:
      1. detect languages
      2. detect frameworks (informational + used to gate rulepack loading)
      3. resolve external rulepacks -> language-filtered --config paths
      4. select scanners applicable to the language mix
      5. run all scanners in parallel with the resolved per-repo --configs
      6. two-pass dedup + user + built-in false-positive filters
      7. write outputs
    Returns (langs, active, suppressed, results)."""
    lang_counts = detect_languages(root)
    langs = set(lang_counts)
    _status("   Detected languages: " +
            (", ".join(f"{l}({n})" for l, n in lang_counts.items()) or "none"))

    # Framework detection — printed for visibility; also feeds rulepack scoping.
    fw_by_lang = detect_frameworks(root)
    if fw_by_lang:
        summary = ", ".join(
            f"{l}:[{','.join(sorted(fw)) or '-'}]"
            for l, fw in sorted(fw_by_lang.items())
        )
        _status(f"   Detected frameworks: {summary}")

    # Per-repo external rulepack resolution: pass each --config file down to
    # semgrep + opengrep. bandit / bearer / drogonsec / gosec silently ignore
    # extras because their templates carry no --config token.
    extra_configs: List[str] = []

    # 1) Semgrep Registry vendor packs — always-on defaults + language/framework
    #    tags surfaced by the detector, plus infra packs gated on real k8s/
    #    dockerfile manifest detection so a Spring config yaml doesn't drag
    #    in p/kubernetes. Runs even when no --custom-rulepack was supplied,
    #    so the moment the framework detector says "fastapi" the matching
    #    pack starts firing.
    infra_manifests = detect_infra_manifests(root)
    if infra_manifests:
        _status(f"   Detected infra manifests: {', '.join(sorted(infra_manifests))}")
    vendor_packs = resolve_vendor_packs(langs, fw_by_lang, infra_manifests)
    if vendor_packs:
        extra_configs.extend(vendor_packs)
        _status(f"   Vendor packs auto-loaded: {len(vendor_packs)} "
                f"({', '.join(vendor_packs)})")

    # 2) Registered custom rulepack files/directories — filtered per repo's
    #    language set unless --no-rulepack-filter is on.
    if _USER_RULEPACKS:
        user_configs = resolve_rulepack_configs(
            _USER_RULEPACKS, langs, apply_filter=rulepack_filter,
        )
        extra_configs.extend(user_configs)
        total_reg = sum(1 for _ in _USER_RULEPACKS)
        if rulepack_filter and langs:
            _status(f"   External rulepacks: {total_reg} registered, "
                    f"{len(user_configs)} rule file(s) match "
                    f"{sorted(langs)}")
        else:
            _status(f"   External rulepacks: {total_reg} registered, "
                    f"filter disabled -> loading everything")

    chosen = select_adapters(langs, only, skip)
    _status("   Planned scanners : " + (", ".join(a.name for a in chosen) or "none"))
    for a in chosen:
        why = "all-lang" if a.languages == ALL_LANGS else ",".join(sorted(a.languages & langs))
        avail = "" if a.available() else "  (WILL SKIP: binary not found)"
        _status(f"   - {a.name:<10} -> {why}{avail}")

    if not chosen:
        return langs, [], [], []

    out_dir.mkdir(parents=True, exist_ok=True)

    # 3) Global dead-rule exclusions loaded from the file next to argus.py
    #    (EXCLUDE_RULES_PATH). Populated by the team after running
    #    --profile-rules on a representative repo; each ID here saves that
    #    rule's match_time on every subsequent scan across every repo.
    exclude_rules = _load_exclude_rules()
    if exclude_rules:
        _status(f"   Excluded rules   : {len(exclude_rules)} loaded from "
                f"{EXCLUDE_RULES_PATH.name}")

    # 4) Bundle every local rule YAML into a single file so each semgrep-family
    #    scanner opens 1 --config, not 40. Registry packs (p/*) pass through.
    #    Bundle is regenerated per scan into the reports out_dir, so nothing
    #    ever gets written into the target repo.
    out_dir.mkdir(parents=True, exist_ok=True)
    bundled, bundle_path, n_files, n_rules = bundle_local_rulepacks(
        extra_configs, out_dir)
    if bundle_path is not None:
        extra_configs = bundled
        _status(f"   Rulepack bundle  : merged {n_files} file(s) → "
                f"{n_rules} unique rule(s) in {bundle_path.name}")

    # Per-scanner core budget: split CPU cores fairly across the concurrent
    # scanner subprocesses so semgrep + opengrep + bearer don't each try to
    # use every core. Reported once so operators can see the cap in effect.
    jobs = _compute_scanner_jobs(scanner_workers, chosen)
    _status(f"   Per-scanner jobs : {jobs} (cores={os.cpu_count() or '?'}, "
            f"concurrent={min(scanner_workers, len(chosen))})")

    # Live progress: per-scanner completions + periodic heartbeat while scans
    # are still in flight. Total is len(chosen) — even scanners whose binary is
    # missing get counted, because run_adapter emits a [SKIP] and marks the
    # tracker so the % still advances.
    tracker = ProgressTracker(total=len(chosen), repo_label=root.name)
    tracker.start()
    results: List[ScanResult] = []
    try:
        with futures.ThreadPoolExecutor(max_workers=max(1, scanner_workers)) as pool:
            fut = {pool.submit(run_adapter, a, root, out_dir, timeout,
                               extra_configs, tracker,
                               exclude_rules or None, jobs): a
                   for a in chosen}
            for f in futures.as_completed(fut):
                results.append(f.result())
    finally:
        tracker.stop()

    raw = [fd for r in results for fd in r.findings]
    deduped = deduplicate(raw, line_window=dedup_line_window)
    _status(f"   Dedup: {len(raw)} raw -> {len(deduped)} deduplicated "
            f"({len(raw) - len(deduped)} merged, "
            f"{(len(raw) - len(deduped)) / max(len(raw), 1) * 100:.1f}%)")

    # Fix A (2026-09-23): file-rule roll-up. Collapse clusters of the same
    # rule firing on the same file into a single row with an `occurrences`
    # list of the extra line numbers. Raw per-line data remains in
    # raw_findings.json — this only affects the primary review view.
    pre_rollup = len(deduped)
    deduped = collapse_file_rule_clusters(deduped)
    if pre_rollup > len(deduped):
        _status(f"   Roll-up: {pre_rollup} -> {len(deduped)} rows "
                f"(collapsed {pre_rollup - len(deduped)} into (file, rule) groups)")

    n_upgraded, upgrade_reasons = upgrade_severities(deduped)
    if n_upgraded:
        reason_str = ", ".join(f"{k}={v}" for k, v in sorted(
            upgrade_reasons.items(), key=lambda kv: -kv[1]))
        _status(f"   Severity: promoted {n_upgraded} HIGH -> CRITICAL ({reason_str})")

    active, suppressed = write_all_reports(deduped, suppressions, out_dir,
                                           raw=raw, auto_fp=auto_fp)
    if suppressed:
        auto_hits = sum(1 for f in suppressed
                        if (f.suppress_reason or "").startswith("[auto]"))
        _status(f"   Suppressed {len(suppressed)} finding(s) "
                f"({auto_hits} auto, {len(suppressed) - auto_hits} user-triaged) "
                f"-> {out_dir / 'suppressed.csv'}")

    # Opt-in rule-cost profile: run once, prune dead rules from rulepacks,
    # save that cost from every subsequent scan.
    if profile_rules:
        _run_rule_profile(root, out_dir, extra_configs, timeout)

    print_summary(results, active, raw_total=len(raw), suppressed_total=len(suppressed))
    return langs, active, suppressed, results


def severity_counts(deduped) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in deduped:
        counts[f.severity.lower()] = counts.get(f.severity.lower(), 0) + 1
    counts["total_findings"] = len(deduped)
    return counts


def scan_one_repo(project: dict, token: str, base_reports_dir: Path, only, skip,
                  scanner_workers: int, timeout: int, clone_timeout: int,
                  checkpoint_path: Path, summary_path: Path,
                  suppressions: Optional[SuppressionStore] = None,
                  auto_fp: bool = True,
                  dedup_line_window: int = DEFAULT_DEDUP_LINE_WINDOW,
                  rulepack_filter: bool = True,
                  profile_rules: bool = False) -> str:
    repo_key = project["path_with_namespace"]
    branch = project.get("default_branch") or "main"
    repo_out_dir = base_reports_dir / safe_dir_name(repo_key)
    clone_url = build_clone_url(project, token)

    print("\n" + "=" * 78)
    print(f" REPO: {repo_key}   (branch: {branch})")
    print("=" * 78)

    workdir = Path(tempfile.mkdtemp(prefix="gl_sast_"))
    src_dir = workdir / "src"
    try:
        _status("   Cloning (shallow, single branch) ...")
        clone = subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", "--branch", branch,
             clone_url, str(src_dir)],
            capture_output=True, text=True, timeout=clone_timeout,
        )
        if clone.returncode != 0:
            _status("   Branch clone failed; retrying with default branch ...")
            shutil.rmtree(src_dir, ignore_errors=True)
            clone = subprocess.run(
                ["git", "clone", "--depth", "1", clone_url, str(src_dir)],
                capture_output=True, text=True, timeout=clone_timeout,
            )
        if clone.returncode != 0:
            append_summary(summary_path, {
                "path_with_namespace": repo_key, "web_url": project.get("web_url", ""),
                "status": f"clone_failed: {clone.stderr.strip()[:200]}",
                "languages": "", "scanners": "",
                "critical": "", "high": "", "medium": "", "low": "", "info": "",
                "total_findings": "", "output_dir": "",
            })
            mark_done(checkpoint_path, repo_key)
            return f"CLONE FAIL  {repo_key}"

        langs, deduped, suppressed, results = run_pipeline(
            src_dir, repo_out_dir, only, skip, scanner_workers, timeout,
            suppressions, auto_fp=auto_fp, dedup_line_window=dedup_line_window,
            rulepack_filter=rulepack_filter, profile_rules=profile_rules,
        )

        if not langs:
            append_summary(summary_path, {
                "path_with_namespace": repo_key, "web_url": project.get("web_url", ""),
                "status": "no_recognized_languages",
                "languages": "", "scanners": "",
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
                "total_findings": 0, "output_dir": "",
            })
            mark_done(checkpoint_path, repo_key)
            return f"NO LANGS    {repo_key}"

        counts = severity_counts(deduped)
        scanners_ok = sorted({r.scanner for r in results if r.status == "ok"})
        status = "ok"
        if any(r.status == "error" for r in results):
            status = "ok_with_scanner_errors"

        append_summary(summary_path, {
            "path_with_namespace": repo_key, "web_url": project.get("web_url", ""),
            "status": status,
            "languages": ",".join(sorted(langs)),
            "scanners": ",".join(scanners_ok),
            "critical": counts["critical"], "high": counts["high"],
            "medium": counts["medium"], "low": counts["low"], "info": counts["info"],
            "suppressed": len(suppressed),
            "total_findings": counts["total_findings"],
            "output_dir": str(repo_out_dir),
        })
        # Flat per-finding roll-up (findings_summary.csv sibling to sast_summary.csv)
        append_findings_summary(
            resolve_findings_summary_path(summary_path),
            repo_key,
            list(deduped) + list(suppressed),
        )
        mark_done(checkpoint_path, repo_key)
        return (f"OK          {repo_key}  "
                f"(crit={counts['critical']} high={counts['high']} "
                f"med={counts['medium']} total={counts['total_findings']} "
                f"suppressed={len(suppressed)})")

    except subprocess.TimeoutExpired:
        append_summary(summary_path, {
            "path_with_namespace": repo_key, "web_url": project.get("web_url", ""),
            "status": "timeout", "languages": "", "scanners": "",
            "critical": "", "high": "", "medium": "", "low": "", "info": "",
            "total_findings": "", "output_dir": "",
        })
        mark_done(checkpoint_path, repo_key)
        return f"TIMEOUT     {repo_key}"
    except Exception as exc:  # noqa: BLE001
        append_summary(summary_path, {
            "path_with_namespace": repo_key, "web_url": project.get("web_url", ""),
            "status": f"error: {exc}", "languages": "", "scanners": "",
            "critical": "", "high": "", "medium": "", "low": "", "info": "",
            "total_findings": "", "output_dir": "",
        })
        mark_done(checkpoint_path, repo_key)
        return f"ERROR       {repo_key}  ({exc})"
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --- action: CRAWL -------------------------------------------------------------------

def action_crawl(base_url: str, token: str, args) -> int:
    print("\n=== Action: crawl GitLab projects ===\n")

    group = args.group
    if group is None:
        group = prompt_text("Restrict to a group/umbrella (path or ID; Enter to crawl everything)")

    if group:
        membership_only = False
    else:
        membership_only = args.membership_only
        if membership_only is None:
            membership_only = prompt_yes_no("Only list projects you're a member of?", default=False)

    output_path = args.output or prompt_text("Output CSV path", default="gitlab_projects.csv")

    print("\nCrawling projects...")
    projects = crawl_projects(base_url, token, group, membership_only)
    if not projects:
        print("No projects found (or all requests failed).")
        return 0

    write_crawl_csv(projects, output_path)
    print(f"\nDone. {len(projects)} projects written to {output_path}")
    print("\nSample:")
    for p in projects[:10]:
        print(f"  - {p.get('path_with_namespace')}  ({p.get('visibility')})  {p.get('web_url')}")
    if len(projects) > 10:
        print(f"  ... and {len(projects) - 10} more (see {output_path})")
    print(f"\nTip: scan these with:\n"
          f"    python3 {Path(__file__).name} --action scan --csv {output_path}")
    return 0


# --- action: LOCAL SCAN ---------------------------------------------------------------

def action_scan_local(args) -> int:
    """Scan one or more local directories with the same engine as the GitLab
    scan (language detection -> multi-scanner -> dedup -> FP suppression ->
    SARIF/JSON/CSV/xlsx reports). No GitLab URL, token, or network needed."""
    print("\n=== Action: scan local directories (language-aware, multi-scanner) ===\n")

    paths = args.path
    if not paths:
        raw = prompt_text("Directory to scan (space/comma separated for several)",
                          default=".")
        paths = [p for p in raw.replace(",", " ").split() if p]

    targets: List[Path] = []
    for p in paths:
        d = Path(p).expanduser().resolve()
        if not d.is_dir():
            print(f"Not a directory, skipping: {p}", file=sys.stderr)
            continue
        targets.append(d)
    if not targets:
        print("No valid directories to scan.", file=sys.stderr)
        return 1

    only, skip = resolve_scanner_selection(args)

    scanner_workers = args.scanner_workers
    if scanner_workers is None:
        scanner_workers = (prompt_int("Parallel scanners per directory", default=4, minimum=1)
                           if args.action_interactive else 4)
    timeout = args.timeout
    if timeout is None:
        timeout = (prompt_int("Per-scanner timeout (seconds)", default=900, minimum=1)
                   if args.action_interactive else 900)

    reports_dir = args.reports_dir
    if reports_dir is None:
        reports_dir = (prompt_text("Directory for scan reports", default="sast_reports")
                       if args.action_interactive else "sast_reports")
    summary_out = args.out_summary
    if summary_out is None:
        summary_out = (prompt_text("Summary CSV output path", default="sast_summary.csv")
                       if args.action_interactive else "sast_summary.csv")

    base_reports_dir = Path(reports_dir).expanduser()
    base_reports_dir.mkdir(parents=True, exist_ok=True)
    summary_path = resolve_summary_path(summary_out)
    if str(summary_path) != str(Path(summary_out).expanduser()):
        print(f"Summary CSV path resolved to: {summary_path}")

    suppressions = load_suppression_store(args.suppressions)
    if suppressions:
        print(f"Suppression file: {suppressions.path}  "
              f"({len(suppressions.by_fingerprint)} triaged finding(s), "
              f"{len(suppressions.rules)} rule(s))")

    print(f"\nScanning {len(targets)} local dir(s): "
          f"scanners/dir={scanner_workers}, per-scanner-timeout={timeout}s")

    t0 = time.time()
    worst_open: List[Finding] = []
    for i, target in enumerate(targets, 1):
        # A directory scanned in place is never cloned or deleted; reports are
        # keyed by the directory name (with a short path hash to avoid
        # collisions between same-named dirs).
        key = f"{target.name}-{hashlib.sha1(str(target).encode()).hexdigest()[:8]}"
        repo_out_dir = base_reports_dir / safe_dir_name(key)

        print("\n" + "=" * 78)
        print(f" LOCAL DIR [{i}/{len(targets)}]: {target}")
        print("=" * 78)

        langs, active, suppressed, results = run_pipeline(
            target, repo_out_dir, only, skip, scanner_workers, timeout,
            suppressions, auto_fp=args.auto_fp,
            dedup_line_window=args.dedup_line_window,
            rulepack_filter=args.rulepack_filter,
            profile_rules=getattr(args, "profile_rules", False),
        )

        if not langs:
            append_summary(summary_path, {
                "path_with_namespace": str(target), "web_url": "",
                "status": "no_recognized_languages", "languages": "", "scanners": "",
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
                "suppressed": 0, "total_findings": 0, "output_dir": "",
            })
            print(f"NO LANGS    {target}")
            continue

        worst_open.extend(active)
        counts = severity_counts(active)
        scanners_ok = sorted({r.scanner for r in results if r.status == "ok"})
        status = "ok"
        if any(r.status == "error" for r in results):
            status = "ok_with_scanner_errors"
        append_summary(summary_path, {
            "path_with_namespace": str(target), "web_url": "",
            "status": status,
            "languages": ",".join(sorted(langs)),
            "scanners": ",".join(scanners_ok),
            "critical": counts["critical"], "high": counts["high"],
            "medium": counts["medium"], "low": counts["low"], "info": counts["info"],
            "suppressed": len(suppressed),
            "total_findings": counts["total_findings"],
            "output_dir": str(repo_out_dir),
        })
        # Flat per-finding roll-up — one row per finding across every scanned
        # target, with file path + line number + line-numbered vulnerable-code
        # snippet in a single spreadsheet. Includes both open and auto/user-
        # suppressed findings so the suppression audit trail lives with the code.
        append_findings_summary(
            resolve_findings_summary_path(summary_path),
            str(target),
            list(active) + list(suppressed),
        )
        print(f"OK          {target}  "
              f"(crit={counts['critical']} high={counts['high']} "
              f"med={counts['medium']} total={counts['total_findings']} "
              f"suppressed={len(suppressed)})")

    findings_summary_path = resolve_findings_summary_path(summary_path)
    print(f"\nDone in {time.time() - t0:4.1f}s.")
    print(f"Summary CSV      : {summary_path}")
    print(f"Findings summary : {findings_summary_path}  "
          f"(flat per-finding roll-up · path · line · vulnerable_code)")
    print(f"Reports dir      : {base_reports_dir}/   (per dir: findings.xlsx with 3 sheets "
          f"[Raw Findings / Deduplicated / False Positives Removed], merged.sarif, "
          f"findings.json/csv, raw_findings.json/csv, suppressed.json/csv)")

    if args.fail_on:
        threshold = SEV_RANK[args.fail_on.upper()]
        gating = [f for f in worst_open if SEV_RANK.get(f.severity, 0) >= threshold]
        if gating:
            print(f"\nfail-on={args.fail_on}: {len(gating)} open finding(s) at/above "
                  f"threshold -> non-zero exit")
            return 2
    return 0


# --- action: SCAN --------------------------------------------------------------------

def choose_scan_targets(base_url: str, token: str, args) -> list:
    include_archived = args.include_archived
    limit = args.limit

    if args.repo:
        return [get_single_project(base_url, token, args.repo)]
    if args.csv:
        if include_archived is None:
            include_archived = False
        return load_projects_csv(args.csv, include_archived, limit)
    if args.group:
        projects = crawl_projects(base_url, token, args.group, membership_only=False)
        if include_archived is None:
            include_archived = False
        return filter_projects(projects, include_archived, limit)

    src = prompt_choice("What do you want to scan?", ["repo", "group", "csv"], default="repo")

    if src == "repo":
        repo_path = prompt_text("Project path (e.g. group/subgroup/project)", required=True)
        return [get_single_project(base_url, token, repo_path)]

    if include_archived is None:
        include_archived = prompt_yes_no("Include archived repositories?", default=False)
    if limit is None:
        limit = prompt_optional_int("Limit to the first N repos (Enter to scan all)", minimum=1)

    if src == "group":
        group = prompt_text("Group/umbrella path or ID", required=True)
        projects = crawl_projects(base_url, token, group, membership_only=False)
        return filter_projects(projects, include_archived, limit)

    csv_path = prompt_text("Path to a crawl CSV", default="gitlab_projects.csv")
    return load_projects_csv(csv_path, include_archived, limit)


def resolve_scanner_selection(args):
    available = [a.name for a in ADAPTERS]
    only = set(args.scanners) if args.scanners else None
    skip = set(args.skip) if args.skip else set()

    if only is None and not skip and args.action_interactive:
        print("\nRegistered scanners (availability checked against your PATH):")
        for a in ADAPTERS:
            langs = "all languages" if a.languages == ALL_LANGS else ", ".join(sorted(a.languages))
            avail = "available" if a.available() else "NOT on PATH"
            print(f"  {a.name:<10} [{avail:<11}]  langs: {langs}")
        restrict = prompt_text(
            "\nRestrict to specific scanners? (space/comma separated; Enter = all applicable)"
        )
        if restrict:
            only = {s.strip() for s in restrict.replace(",", " ").split() if s.strip()}
        else:
            sk = prompt_text("Skip any scanners? (space/comma separated; Enter = none)")
            if sk:
                skip = {s.strip() for s in sk.replace(",", " ").split() if s.strip()}

    for name in (only or set()) | skip:
        if name not in available:
            print(f"Unknown scanner '{name}'. Known: {', '.join(available)}", file=sys.stderr)
            sys.exit(1)
    return only, skip


def action_scan(base_url: str, token: str, args) -> int:
    print("\n=== Action: scan GitLab repositories (language-aware, multi-scanner) ===\n")

    if shutil.which("git") is None:
        print("git is not on PATH. Install git and retry.", file=sys.stderr)
        return 1

    only, skip = resolve_scanner_selection(args)

    scanner_workers = args.scanner_workers
    if scanner_workers is None:
        scanner_workers = (prompt_int("Parallel scanners per repo", default=4, minimum=1)
                           if args.action_interactive else 4)
    timeout = args.timeout
    if timeout is None:
        timeout = (prompt_int("Per-scanner timeout (seconds)", default=900, minimum=1)
                   if args.action_interactive else 900)
    clone_timeout = args.clone_timeout

    reports_dir = args.reports_dir
    if reports_dir is None:
        reports_dir = (prompt_text("Directory for scan reports", default="sast_reports")
                       if args.action_interactive else "sast_reports")
    summary_out = args.out_summary
    if summary_out is None:
        summary_out = (prompt_text("Summary CSV output path", default="sast_summary.csv")
                       if args.action_interactive else "sast_summary.csv")
    checkpoint = args.checkpoint
    if checkpoint is None:
        checkpoint = (prompt_text("Checkpoint file path", default="sast_checkpoint.txt")
                      if args.action_interactive else "sast_checkpoint.txt")

    suppressions = load_suppression_store(args.suppressions)
    if suppressions:
        print(f"Suppression file: {suppressions.path}  "
              f"({len(suppressions.by_fingerprint)} triaged finding(s), "
              f"{len(suppressions.rules)} rule(s)) — matching findings will be "
              f"filtered out of findings.csv/json and marked suppressed in SARIF.")

    projects = choose_scan_targets(base_url, token, args)
    if not projects:
        print("No projects selected to scan.")
        return 0

    base_reports_dir = Path(reports_dir).expanduser()
    base_reports_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_path = Path(checkpoint).expanduser()
    checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path = resolve_summary_path(summary_out)
    if str(summary_path) != str(Path(summary_out).expanduser()):
        print(f"Summary CSV path resolved to: {summary_path}")

    done = load_checkpoint(checkpoint_path)
    todo = [p for p in projects if p["path_with_namespace"] not in done]

    print(f"\nProjects selected:            {len(projects)}")
    print(f"Already completed (checkpoint): {len(done)}")
    print(f"Remaining to scan this run:     {len(todo)}")
    if not todo:
        print("Nothing to do.")
        return 0

    repo_workers = max(1, args.repo_workers)
    print(f"\nScanning {len(todo)} repo(s): repo-workers={repo_workers}, "
          f"scanners/repo={scanner_workers}, per-scanner-timeout={timeout}s")
    if repo_workers > 1:
        print("Note: repo-workers > 1 interleaves per-scanner logs across repos.")

    t0 = time.time()
    completed = 0

    def _run(p):
        return scan_one_repo(
            p, token, base_reports_dir, only, skip, scanner_workers, timeout,
            clone_timeout, checkpoint_path, summary_path, suppressions,
            auto_fp=args.auto_fp, dedup_line_window=args.dedup_line_window,
            rulepack_filter=args.rulepack_filter,
            profile_rules=getattr(args, "profile_rules", False),
        )

    if repo_workers == 1:
        for p in todo:
            completed += 1
            print(f"\n[{completed}/{len(todo)}] {_run(p)}")
    else:
        with futures.ThreadPoolExecutor(max_workers=repo_workers) as pool:
            fut = {pool.submit(_run, p): p for p in todo}
            for f in futures.as_completed(fut):
                completed += 1
                try:
                    print(f"\n[{completed}/{len(todo)}] {f.result()}")
                except Exception as exc:  # noqa: BLE001
                    repo = fut[f]["path_with_namespace"]
                    print(f"\n[{completed}/{len(todo)}] ERROR  {repo}  ({exc})")

    print(f"\nDone in {time.time() - t0:4.1f}s.")
    print(f"Summary CSV : {summary_path}")
    print(f"Reports dir : {base_reports_dir}/   (per repo: findings.xlsx with 3 sheets "
          f"[Raw Findings / Deduplicated / False Positives Removed], merged.sarif, "
          f"findings.json/csv, raw_findings.json/csv, suppressed.json/csv)")
    print(f"Checkpoint  : {checkpoint_path}  (re-run to resume; scanned repos are skipped)")

    if args.fail_on:
        threshold = SEV_RANK[args.fail_on.upper()]
        order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        gating_levels = [lvl for lvl in order if SEV_RANK[lvl] >= threshold]
        total_gating = 0
        if summary_path.exists():
            with open(summary_path, newline="", encoding="utf-8") as fh:
                for row in csv.DictReader(fh):
                    for lvl in gating_levels:
                        try:
                            total_gating += int(row.get(lvl.lower()) or 0)
                        except ValueError:
                            pass
        if total_gating:
            print(f"\nfail-on={args.fail_on}: {total_gating} finding(s) at/above threshold "
                  f"-> non-zero exit")
            return 2
    return 0


# --- action: TRIAGE ------------------------------------------------------------------

def _finding_from_dict(d: dict) -> Finding:
    fields = {f.name for f in dataclasses.fields(Finding)}
    return Finding(**{k: v for k, v in d.items() if k in fields})


def load_findings_json(path: Path) -> List[Finding]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        raise SystemExit(f"Could not read findings file {path}: {e}")
    if not isinstance(data, list):
        raise SystemExit(f"{path} is not a findings.json produced by this tool.")
    return [_finding_from_dict(d) for d in data if isinstance(d, dict)]


def _print_finding_card(idx: int, total: int, f: Finding) -> None:
    src = ",".join(sorted({s.split(":")[0] for s in f.sources})) or f.scanner
    print("\n" + "-" * 68)
    print(f" [{idx}/{total}]  {f.severity}  {f.rule_id}"
          + (f"  ({f.cwe})" if f.cwe else ""))
    print(f"   file    : {f.path}:{f.start_line}"
          + (f"-{f.end_line}" if f.end_line > f.start_line else ""))
    print(f"   tools   : {src}")
    print(f"   message : {(f.message or '').strip()[:200]}")
    print(f"   fingerprint: {f.fingerprint()}")
    code = format_snippet_with_lines(f.snippet, f.start_line)
    if code:
        print("   vulnerable code:")
        for line in code.splitlines()[:12]:
            print(f"     {line}")


def cmd_triage(args) -> int:
    """Triage deduplicated findings: mark false positives (or accepted risk /
    won't fix), persist decisions to the shared suppression file, and rewrite
    the report files with those findings suppressed."""
    print("\n=== Action: triage findings / suppress false positives ===\n")

    findings_path = args.findings
    if findings_path is None:
        findings_path = prompt_text(
            "Path to a findings.json from a previous scan "
            "(e.g. sast_reports/group__proj/findings.json)", required=True)
    fpath = Path(findings_path)
    # A suppressed.json may exist alongside; include it so earlier decisions
    # can be revisited and so re-writing reports never loses findings.
    findings = load_findings_json(fpath)
    sup_sibling = fpath.parent / "suppressed.json"
    if sup_sibling.exists() and fpath.name != "suppressed.json":
        findings = deduplicate(findings + load_findings_json(sup_sibling))
    # Apply the CRITICAL-upgrade rules on the triage path too so re-loads of
    # older findings.json files pick up the new severity labels.
    upgrade_severities(findings)

    store_path = args.suppressions or DEFAULT_SUPPRESSIONS_FILE
    store = SuppressionStore(store_path)
    print(f"Loaded {len(findings)} deduplicated finding(s) from {fpath}")
    print(f"Suppression file: {store.path}  "
          f"({len(store.by_fingerprint)} entries, {len(store.rules)} rules)")

    # --- non-interactive: suppress explicit fingerprints ---------------------
    if args.suppress_fingerprints:
        by_fp = {f.fingerprint(): f for f in findings}
        reason = args.reason or "triaged as false positive"
        status = args.suppress_status
        for fp in args.suppress_fingerprints:
            f = by_fp.get(fp)
            if f is not None:
                store.add(f, status, reason)
                print(f"  suppressed {fp}  {f.path}:{f.start_line}  {f.rule_id}")
            else:
                store.add_fingerprint(fp, status, reason)
                print(f"  suppressed {fp}  (not present in this findings file; "
                      f"stored for future scans)")
        store.save()
        active, suppressed = write_all_reports(findings, store, fpath.parent,
                                               auto_fp=args.auto_fp)
        print(f"\nSaved {store.path}. Reports rewritten in {fpath.parent}: "
              f"{len(active)} open, {len(suppressed)} suppressed.")
        return 0

    # --- interactive triage --------------------------------------------------
    active, already = apply_suppressions(findings, store, auto_fp=args.auto_fp)
    if already:
        print(f"{len(already)} finding(s) already suppressed by the file above.")
    if not active:
        print("Nothing left to triage — all findings are suppressed.")
        write_all_reports(findings, store, fpath.parent, auto_fp=args.auto_fp)
        return 0

    ordered = sorted(active, key=lambda f: (-SEV_RANK.get(f.severity, 0),
                                            f.path, f.start_line, f.rule_id))
    print(f"\n{len(ordered)} open finding(s) to review.")
    print("For each finding: [f]alse positive  [a]ccepted risk  [w]on't fix  "
          "[s]kip (keep open)  [q]uit & save\n")

    decided = 0
    for i, f in enumerate(ordered, 1):
        _print_finding_card(i, len(ordered), f)
        choice = prompt_choice("Decision", ["f", "a", "w", "s", "q"], default="s")
        if choice == "q":
            break
        if choice == "s":
            continue
        status = {"f": "false_positive", "a": "accepted_risk", "w": "wont_fix"}[choice]
        reason = prompt_text("Reason (stored in the suppression file)",
                             default=status.replace("_", " "))
        store.add(f, status, reason)
        decided += 1

    store.save()
    active, suppressed = write_all_reports(findings, store, fpath.parent,
                                           auto_fp=args.auto_fp)
    print(f"\nTriage session: {decided} new decision(s) recorded.")
    print(f"Suppression file : {store.path}  "
          f"({len(store.by_fingerprint)} entries, {len(store.rules)} rules)")
    print(f"Reports rewritten: {fpath.parent}/  "
          f"({len(active)} open, {len(suppressed)} suppressed)")
    print("Future scans automatically pick this file up "
          f"(or pass --suppressions {store.path}).")
    return 0


def cmd_list_scanners() -> int:
    _print_argus_banner(compact=True)
    print()
    print("Registered scanners:\n")
    for a in ADAPTERS:
        langs = "all languages" if a.languages == ALL_LANGS else ", ".join(sorted(a.languages))
        avail = "available" if a.available() else "NOT on PATH"
        print(f"  {a.name:<10} [{avail:<11}] langs: {langs}")
        print(f"             install: {a.install_hint}")
        print(f"             cmd    : {' '.join(a.cmd_template)}\n")
    if _USER_RULEPACKS:
        print("Registered rulepacks (language-filtered per target repo at scan time):")
        for rp in _USER_RULEPACKS:
            kind = "dir " if rp.is_dir() else "file"
            print(f"  [{kind}] {rp}")
        print()
    return 0


# --- entry point ---------------------------------------------------------------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Unified GitLab tool: crawl projects, or clone+scan repos "
                    "with a language-aware multi-scanner SAST engine.",
    )
    ap.add_argument("--url", default=None, help="GitLab base URL (prompted if omitted)")
    ap.add_argument("--action", choices=["crawl", "scan", "local", "triage"], default=None,
                    help="What to do (prompted if omitted)")
    ap.add_argument("--path", nargs="+", metavar="DIR", default=None,
                    help="local: one or more local directories to scan "
                         "(implies --action local; no GitLab URL/token needed)")
    ap.add_argument("--list-scanners", action="store_true",
                    help="list registered scanners and exit")

    # triage / suppression options
    ap.add_argument("--suppressions", default=None,
                    help=f"suppression file (default: ./{DEFAULT_SUPPRESSIONS_FILE} "
                         f"is auto-loaded when present)")
    ap.add_argument("--no-auto-suppress", dest="auto_fp", action="store_false",
                    default=True,
                    help="disable the built-in false-positive filter that drops "
                         "findings inside sast_reports/, virtualenvs, "
                         "node_modules, build dirs, minified assets and "
                         "bandit-B101-in-tests")
    ap.add_argument("--custom-rulepack", nargs="+", default=None, metavar="PATH",
                    help=f"one or more extra Semgrep-compatible rulepack files "
                         f"or directories for semgrep + opengrep. Additive on "
                         f"top of every *_rulepack.yml / *_semgrep.yml / "
                         f"*.semgrep.yml file bundled next to this script "
                         f"(auto-discovered at startup). For each scanned repo "
                         f"the tool detects languages + frameworks and passes "
                         f"only the rule files whose `languages:` field "
                         f"intersects the repo's language set — a Java rule "
                         f"never loads against a Go repo. Directories are "
                         f"walked recursively; broken rules are skipped with "
                         f"a warning by semgrep at scan time.")
    ap.add_argument("--no-rulepack-filter", dest="rulepack_filter",
                    action="store_false", default=True,
                    help="disable the per-repo language filter and pass every "
                         "registered rulepack file/directory to semgrep + "
                         "opengrep verbatim (slower; useful when the language "
                         "detector guesses wrong or for debugging rule loads)")
    ap.add_argument("--dedup-line-window", type=int, default=DEFAULT_DEDUP_LINE_WINDOW,
                    metavar="N",
                    help="second-pass semantic dedup merges same-file same-category "
                         "findings within ±N lines (default 3; 0 = disable pass 2)")
    ap.add_argument("--profile-rules", action="store_true", default=False,
                    help="run an extra semgrep pass with --time --json and write "
                         "rule_profile.csv (per-rule parse/match cost + finding "
                         "count, dead-and-costly flagged). Opts into ~2x semgrep "
                         "wall-clock for one run so you can prune expensive "
                         "no-match rules from your rulepacks — permanent saving "
                         "on every subsequent scan.")
    ap.add_argument("--findings", default=None,
                    help="triage: findings.json from a previous scan")
    ap.add_argument("--suppress-fingerprints", nargs="+", metavar="FP", default=None,
                    help="triage: non-interactively suppress these fingerprints")
    ap.add_argument("--reason", default=None,
                    help="triage: reason recorded with --suppress-fingerprints")
    ap.add_argument("--suppress-status", choices=list(SUPPRESS_STATUSES),
                    default="false_positive",
                    help="triage: status recorded with --suppress-fingerprints")

    # crawl options
    ap.add_argument("--group", default=None,
                    help="Group/umbrella path or ID (crawl: filter; scan: source)")
    ap.add_argument("--membership-only", action="store_true", default=None,
                    help="crawl: only projects you're a member of (ignored with --group)")
    ap.add_argument("--output", default=None, help="crawl: CSV output path")

    # scan source options
    ap.add_argument("--repo", default=None,
                    help="scan: a single project path, e.g. group/sub/project")
    ap.add_argument("--csv", default=None, help="scan: read repos from a crawl CSV")
    ap.add_argument("--include-archived", action="store_true", default=None,
                    help="scan: include archived repos (group/csv sources)")
    ap.add_argument("--limit", type=int, default=None,
                    help="scan: only the first N repos (group/csv sources)")

    # scan engine options
    ap.add_argument("--scanners", nargs="+", metavar="NAME",
                    help="scan: only run these scanners (default: all applicable)")
    ap.add_argument("--skip", nargs="+", default=None, metavar="NAME",
                    help="scan: skip these scanners")
    ap.add_argument("--scanner-workers", type=int, default=None,
                    help="scan: parallel scanners within a repo (default 4)")
    ap.add_argument("--repo-workers", type=int, default=1,
                    help="scan: repos scanned in parallel (default 1; >1 interleaves logs)")
    ap.add_argument("--timeout", type=int, default=None,
                    help="scan: per-scanner timeout seconds (default 900)")
    ap.add_argument("--clone-timeout", type=int, default=180,
                    help="scan: per-repo git clone timeout seconds (default 180)")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                    help="scan: non-zero exit if any finding at/above this severity")

    # scan output options
    ap.add_argument("--reports-dir", default=None, help="scan: directory for per-repo reports")
    ap.add_argument("--out-summary", default=None, help="scan: summary CSV path")
    ap.add_argument("--checkpoint", default=None, help="scan: checkpoint file path")

    # connection / TLS options
    ap.add_argument("--ca-bundle", default=None,
                    help="path to a CA bundle to trust (e.g. a corporate proxy CA)")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS certificate verification (last resort; not recommended)")
    ap.add_argument("--retries", type=int, default=3,
                    help="HTTP retry attempts for transient network errors (default 3)")

    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S",
    )

    # Register every bundled rulepack that ships next to argus.py, plus
    # any --custom-rulepack paths supplied on the command line. Rulepacks are
    # resolved to language-scoped --config files per repo inside run_pipeline,
    # not here — so `--list-scanners` shows the base scanner templates while
    # the actual --config flags depend on the repo being scanned.
    rulepack_paths: List[Path] = list(discover_bundled_rulepacks())
    if args.custom_rulepack:
        rulepack_paths.extend(Path(p).expanduser() for p in args.custom_rulepack)
    for rp in rulepack_paths:
        register_rulepack(rp)
        if rp.exists():
            log.info("Registered rulepack: %s", rp)

    if args.list_scanners:
        return cmd_list_scanners()

    if args.skip is None:
        args.skip = []

    _print_argus_banner()

    # ---- 1) Decide WHAT to do, before asking for anything else. -------------
    # Only the GitLab actions need a URL/token, so the action is chosen first
    # and credentials are requested afterwards, and only when required.
    action = args.action
    if action is None and args.path:
        action = "local"          # --path implies a local scan
    if action is None and (args.repo or args.csv or args.group):
        action = "scan"           # a GitLab source implies a GitLab scan
    if action is None and args.findings:
        action = "triage"         # a findings file implies triage

    args.action_interactive = args.action is None
    if action is None:
        print("What would you like to do?")
        print("  1) Scan a local directory           -> multi-scanner SAST, no GitLab needed")
        print("  2) Scan GitLab repositories         -> clone + multi-scanner SAST")
        print("  3) Crawl GitLab projects            -> CSV")
        print("  4) Triage previous scan results     -> suppress false positives")
        choice = prompt_choice("Choose", ["1", "2", "3", "4"], default="1")
        action = {"1": "local", "2": "scan", "3": "crawl", "4": "triage"}[choice]

    # ---- 2) Run the actions that need no GitLab connection. ------------------
    if action == "triage":
        return cmd_triage(args)
    if action == "local":
        # Explicit --path means a fully specified, non-interactive run; without
        # it the user is at a terminal and gets prompted for the directory and
        # the remaining options.
        args.action_interactive = not args.path
        return action_scan_local(args)

    # ---- 3) GitLab actions: now collect the connection details. -------------
    global SESSION
    SESSION = make_session(ca_bundle=args.ca_bundle, insecure=args.insecure,
                           retries=max(0, args.retries))
    if args.insecure:
        print("WARNING: TLS verification disabled (--insecure).\n", file=sys.stderr)

    print("\nThis action needs access to GitLab.")
    base_url = (args.url or prompt_text("GitLab base URL", default=SUGGESTED_GITLAB_URL)).rstrip("/")
    token = get_access_token()
    user = verify_token(base_url, token)
    print(f"Authenticated as: {user.get('username')} ({user.get('name')})\n")

    if action == "crawl":
        return action_crawl(base_url, token, args)
    return action_scan(base_url, token, args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
    except EOFError:
        print("\nNo input received (stdin closed). Re-run interactively, or pass "
              "the options on the command line — see --help.", file=sys.stderr)
        sys.exit(1)