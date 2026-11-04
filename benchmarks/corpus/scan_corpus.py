"""Scan the cloned corpus with mcpscan and write anonymized aggregate rates.

Per-repository results (with repository names) stay in the private work directory under
.bench-data and are never committed. The committed output contains only counts and rates.

Usage (from the repository root, after `make build` and fetch_corpus.py):
  uv run --project benchmarks python benchmarks/corpus/scan_corpus.py \
      --corpus ../.bench-data/mcp-security-scanner/corpus --private ../.bench-data/mcp-security-scanner/private
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import resource
import secrets
import subprocess
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stats import wilson  # noqa: E402

CATEGORIES = [
    "command-injection",
    "path-traversal",
    "ssrf",
    "secrets",
    "over-broad-scope",
    "tool-poisoning",
]


def anon_id(salt: str, url: str) -> str:
    """Stable pseudonym for a repository; the salt never leaves the private directory."""
    return "r" + hashlib.sha256((salt + url).encode()).hexdigest()[:10]


def load_salt(private: Path) -> str:
    p = private / "salt"
    if not p.exists():
        private.mkdir(parents=True, exist_ok=True)
        p.write_text(secrets.token_hex(16))
        p.chmod(0o600)
    return p.read_text().strip()


def scan_repo(binary: str, path: Path) -> tuple[dict, float]:
    t0 = time.perf_counter()
    proc = subprocess.run(
        [binary, "scan", str(path), "--format", "json", "--fail-on", "none"],
        capture_output=True,
        text=True,
        env={**os.environ, "GOMEMLIMIT": "1GiB"},
    )
    secs = time.perf_counter() - t0
    if proc.returncode != 0:
        raise RuntimeError(f"{path}: {proc.stderr.strip()}")
    return json.loads(proc.stdout), secs


def aggregate(rows: list[dict]) -> dict:
    """Turn per-repository rows into rates. Rows carry categories, rule counts and stats."""
    n = len(rows)
    out: dict = {"repositories": n}
    with_handlers = [r for r in rows if r["tool_handlers"] > 0]
    out["repositories_with_tool_handlers"] = len(with_handlers)
    out["files"] = sum(r["files"] for r in rows)
    out["lines"] = sum(r.get("lines", 0) for r in rows)
    out["repositories_with_js_ts_or_python"] = sum(1 for r in rows if r["files"] > 0)
    out["tool_handlers"] = sum(r["tool_handlers"] for r in rows)
    out["tool_definitions"] = sum(r["tool_definitions"] for r in rows)
    rates = {}
    for cat in CATEGORIES:
        k = sum(1 for r in rows if r["categories"].get(cat, 0) > 0)
        lo, hi = wilson(k, n)
        k2 = sum(1 for r in with_handlers if r["categories"].get(cat, 0) > 0)
        rates[cat] = {
            "repos_flagged": k,
            "share": k / n if n else 0.0,
            "ci95": [lo, hi],
            "repos_flagged_among_with_handlers": k2,
            "share_among_with_handlers": k2 / len(with_handlers) if with_handlers else 0.0,
            "findings": sum(r["categories"].get(cat, 0) for r in rows),
        }
    out["by_category"] = rates
    rules: Counter = Counter()
    repos_by_rule: Counter = Counter()
    for r in rows:
        rules.update(r["rules"])
        repos_by_rule.update(r["rules"].keys())
    out["by_rule"] = {k: {"findings": rules[k], "repos": repos_by_rule[k]} for k in sorted(rules)}
    any_code = sum(
        1 for r in rows if any(r["categories"].get(c, 0) for c in ("command-injection", "path-traversal", "ssrf"))
    )
    out["repos_with_any_injection_class_finding"] = any_code
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mcpscan", default="bin/mcpscan")
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument("--private", type=Path, required=True, help="directory for per-repository results (never commit)")
    ap.add_argument("--lock", type=Path, default=Path("benchmarks/corpus/corpus.lock.json"))
    ap.add_argument("--out", type=Path, default=Path("benchmarks/results/corpus.json"))
    args = ap.parse_args(argv)

    lock = json.loads(args.lock.read_text())
    salt = load_salt(args.private)
    rows, private_rows = [], []
    total_secs = 0.0
    total_bytes = 0
    errors = 0
    for entry in lock["repos"]:
        d = args.corpus / entry["url"].removeprefix("https://github.com/").replace("/", "__")
        if not d.exists():
            continue
        try:
            rep, secs = scan_repo(args.mcpscan, d)
        except RuntimeError as e:
            errors += 1
            print(e, file=sys.stderr)
            continue
        total_secs += secs
        cats: dict[str, int] = defaultdict(int)
        rules: dict[str, int] = defaultdict(int)
        for f in rep["findings"]:
            cats[f["category"]] += 1
            rules[f["rule_id"]] += 1
        stats = rep.get("stats", {})
        total_bytes += stats.get("bytes", 0)
        row = {
            "repo": anon_id(salt, entry["url"]),
            "files": stats.get("files", 0),
            "lines": stats.get("lines", 0),
            "tool_handlers": stats.get("tool_handlers", 0),
            "tool_definitions": stats.get("tool_definitions", 0),
            "seconds": secs,
            "categories": dict(cats),
            "rules": dict(rules),
        }
        rows.append(row)
        private_rows.append({**row, "url": entry["url"], "sha": entry["sha"], "findings": rep["findings"]})

    args.private.mkdir(parents=True, exist_ok=True)
    with (args.private / "corpus_findings.jsonl").open("w") as fh:
        for r in private_rows:
            fh.write(json.dumps(r) + "\n")

    agg = aggregate(rows)
    peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    agg.update(
        {
            "scan_errors": errors,
            "seconds_total": round(total_secs, 2),
            "source_bytes_scanned": total_bytes,
            "throughput_mb_per_s": round(total_bytes / 1e6 / total_secs, 2) if total_secs else None,
            "peak_rss_mb_largest_repo": round(peak / (1 << 20 if sys.platform == "darwin" else 1 << 10), 1),
            "machine": f"{platform.machine()} {platform.system()} {platform.release()}",
            "corpus_lock": str(args.lock),
            "registry_unique_github_repos": lock.get("registry_unique_github_repos"),
            "note": "Rates are shares of scanned repositories with at least one finding of a category. "
            "Findings are unreviewed scanner output; see precision.json for the hand-labeled precision.",
        }
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(agg, indent=1) + "\n")
    print(json.dumps({k: v for k, v in agg.items() if k != "by_rule"}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
