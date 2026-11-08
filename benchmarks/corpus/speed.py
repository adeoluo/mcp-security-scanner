"""Compare wall time and peak memory of mcpscan and Semgrep on a random subset of the corpus.

Each tool scans each repository in its own process under /usr/bin/time, one at a time.

Usage (from the repository root, after `make build`):
  uv run --project benchmarks python benchmarks/corpus/speed.py \
      --corpus ../.bench-data/mcp-security-scanner/corpus --repos 20
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import random
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from compare_planted import SEMGREP_CONFIGS, SEMGREP_VERSION  # noqa: E402


def peak_rss_mb(stderr: str) -> float | None:
    """Parse peak RSS from BSD (`time -l`, bytes) or GNU (`time -v`, kilobytes) output."""
    m = re.search(r"(\d+)\s+maximum resident set size", stderr)
    if m:
        return int(m.group(1)) / (1 << 20)
    m = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", stderr)
    if m:
        return int(m.group(1)) / 1024
    return None


def timed(cmd: list[str]) -> tuple[float, float | None, int]:
    flag = "-l" if sys.platform == "darwin" else "-v"
    t0 = time.perf_counter()
    proc = subprocess.run(["/usr/bin/time", flag, *cmd], capture_output=True, text=True)
    return time.perf_counter() - t0, peak_rss_mb(proc.stderr), proc.returncode


def pick(corpus: Path, lock: dict, n: int, seed: int, min_files: int = 5) -> list[Path]:
    dirs = []
    for entry in lock["repos"]:
        d = corpus / entry["url"].removeprefix("https://github.com/").replace("/", "__")
        if d.exists() and sum(1 for p in d.rglob("*") if p.suffix in {".ts", ".js", ".py"}) >= min_files:
            dirs.append(d)
    rng = random.Random(seed)
    return sorted(rng.sample(dirs, min(n, len(dirs))))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mcpscan", default="bin/mcpscan")
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument("--lock", type=Path, default=Path("benchmarks/corpus/corpus.lock.json"))
    ap.add_argument("--repos", type=int, default=20)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", type=Path, default=Path("benchmarks/results/speed.json"))
    args = ap.parse_args(argv)

    dirs = pick(args.corpus, json.loads(args.lock.read_text()), args.repos, args.seed)
    semgrep = [
        "uv",
        "tool",
        "run",
        f"semgrep=={SEMGREP_VERSION}",
        "scan",
        "--json",
        "--metrics=off",
        "--quiet",
        "--no-git-ignore",
        "-o",
        "/dev/null",
    ]
    for c in SEMGREP_CONFIGS:
        semgrep += ["--config", c]
    rows = []
    for d in dirs:
        m_secs, m_rss, _ = timed(
            [args.mcpscan, "scan", str(d), "--format", "json", "--fail-on", "none", "-o", "/dev/null"]
        )
        s_secs, s_rss, s_code = timed([*semgrep, str(d)])
        rows.append(
            {
                "mcpscan_seconds": m_secs,
                "mcpscan_peak_mb": m_rss,
                "semgrep_seconds": s_secs,
                "semgrep_peak_mb": s_rss,
                "semgrep_exit": s_code,
            }
        )
        print(f"{len(rows)}/{len(dirs)} mcpscan {m_secs:.2f}s semgrep {s_secs:.1f}s", file=sys.stderr)

    def med(key: str) -> float:
        return statistics.median(r[key] for r in rows if r[key] is not None)

    summary = {
        "repositories": len(rows),
        "seed": args.seed,
        "semgrep_version": SEMGREP_VERSION,
        "semgrep_configs": SEMGREP_CONFIGS,
        "mcpscan_seconds_total": round(sum(r["mcpscan_seconds"] for r in rows), 2),
        "semgrep_seconds_total": round(sum(r["semgrep_seconds"] for r in rows), 2),
        "mcpscan_seconds_median": round(med("mcpscan_seconds"), 3),
        "semgrep_seconds_median": round(med("semgrep_seconds"), 3),
        "mcpscan_peak_mb_median": round(med("mcpscan_peak_mb"), 1),
        "semgrep_peak_mb_median": round(med("semgrep_peak_mb"), 1),
        "mcpscan_peak_mb_max": round(max(r["mcpscan_peak_mb"] or 0 for r in rows), 1),
        "semgrep_peak_mb_max": round(max(r["semgrep_peak_mb"] or 0 for r in rows), 1),
        "machine": f"{platform.machine()} {platform.system()} {platform.release()}",
        "load_average_1m_end": round(os.getloadavg()[0], 2),
        "note": "Semgrep fetches registry rule packs on each run; its time includes that download. "
        "Semgrep peak memory is measured for the uv wrapper process tree as reported by time(1).",
        "per_repository": rows,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "per_repository"}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
