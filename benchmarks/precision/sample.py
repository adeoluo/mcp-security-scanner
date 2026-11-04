"""Draw a stratified random sample of corpus findings for hand labeling.

Reads the private per-repository findings written by corpus/scan_corpus.py and writes a private
worksheet with code context. Nothing written here is committed; only the labels exported by
export_labels.py (anonymized repository id, rule, label, reason code) are.

Usage:
  python benchmarks/precision/sample.py --private ../.bench-data/mcp-security-scanner/private \
      --corpus ../.bench-data/mcp-security-scanner/corpus
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

# Rule groups and how many findings to draw from each (all of them when fewer exist).
STRATA = {
    "command-injection": (["MCP101", "MCP102"], 30),
    "path-traversal": (["MCP111"], 30),
    "ssrf": (["MCP121"], 30),
    "secrets": (["MCP131", "MCP132"], 30),
    "cors": (["MCP143"], 15),
    "bind-all": (["MCP142"], 15),
    "tls": (["MCP144"], 15),
    "oauth-scope": (["MCP141"], 15),
    "tool-poisoning": (["MCP201", "MCP202", "MCP203", "MCP204", "MCP205", "MCP206", "MCP208", "MCP209"], 40),
}

# Strata with fewer findings than this after excluding the development worksheet are labeled in full.
MIN_HELD_OUT = 10


def key(repo: str, f: dict) -> tuple:
    return (repo, f.get("file", ""), f.get("line", 0), f["rule_id"])


def mask_secrets(line: str, snippet_rule: str) -> str:
    """Hide most of any long token so the worksheet does not carry full credentials."""
    if snippet_rule not in {"MCP131", "MCP132"}:
        return line
    out = []
    for word in line.split(" "):
        core = word.strip("\"'`;,()")
        if len(core) >= 16:
            word = word.replace(core, core[:6] + "*" * 6 + f"[{len(core)}]")
        out.append(word)
    return " ".join(out)


def context(corpus: Path, repo_dir: str, rel: str, line: int, rule: str, radius: int = 5) -> list[str]:
    p = corpus / repo_dir / rel
    try:
        lines = p.read_text(errors="replace").splitlines()
    except OSError:
        return []
    lo, hi = max(0, line - 1 - radius), min(len(lines), line + radius)
    return [f"{i + 1:5d}{'>' if i + 1 == line else ' '} {mask_secrets(lines[i][:220], rule)}" for i in range(lo, hi)]


def draw(rows: list[dict], seed: int, exclude: set[tuple] | None = None) -> list[dict]:
    """Stratified sample. Findings in `exclude` (the development worksheet) are skipped unless a
    stratum would be left with fewer than MIN_HELD_OUT findings; then the whole stratum is used
    and each item is marked seen_in_development."""
    rng = random.Random(seed)
    exclude = exclude or set()
    sample = []
    for stratum, (rules, k) in STRATA.items():
        pool = []
        for r in rows:
            for f in r["findings"]:
                if f["rule_id"] in rules:
                    pool.append((r, f))
        pool.sort(key=lambda x: key(x[0]["repo"], x[1]))
        fresh = [x for x in pool if key(x[0]["repo"], x[1]) not in exclude]
        if len(fresh) >= MIN_HELD_OUT:
            pool = fresh
        picked = pool if len(pool) <= k else rng.sample(pool, k)
        for r, f in picked:
            seen = key(r["repo"], f) in exclude
            sample.append(
                {"stratum": stratum, "repo": r["repo"], "url": r["url"], "finding": f, "seen_in_development": seen}
            )
    for i, s in enumerate(sample, 1):
        s["id"] = f"s{i:03d}"
    return sample


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--private", type=Path, required=True)
    ap.add_argument("--corpus", type=Path, required=True)
    ap.add_argument("--seed", type=int, default=20261104)
    ap.add_argument("--exclude", type=Path, help="earlier worksheet whose findings were used during development")
    ap.add_argument("--name", default="worksheet.jsonl")
    args = ap.parse_args(argv)
    rows = [json.loads(line) for line in (args.private / "corpus_findings.jsonl").open()]
    exclude = set()
    if args.exclude:
        for line in args.exclude.open():
            s = json.loads(line)
            exclude.add(key(s["repo"], s["finding"]))
    sample = draw(rows, args.seed, exclude)
    with (args.private / args.name).open("w") as fh:
        for s in sample:
            f = s["finding"]
            repo_dir = s["url"].removeprefix("https://github.com/").replace("/", "__")
            s["context"] = (
                context(args.corpus, repo_dir, f.get("file", ""), f.get("line", 0), f["rule_id"])
                if f.get("file")
                else []
            )
            fh.write(json.dumps(s) + "\n")
    counts: dict[str, int] = {}
    for s in sample:
        counts[s["stratum"]] = counts.get(s["stratum"], 0) + 1
    print(json.dumps(counts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
