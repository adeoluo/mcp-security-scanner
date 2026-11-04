"""Compute precision from the hand labels and export the anonymized labels.

Inputs (private, never committed): the worksheet drawn by sample.py and the labels file written
during review. Outputs (committed): labels.jsonl with sample id, stratum, rule, pseudonymous
repository id, label and a generic reason; results/precision.json and results/precision.md.

Labels:
  flow        tp when the finding is factually right (for taint rules: a value derived from tool
              input reaches the sink without an effective check), fp otherwise
  actionable  for taint and secret rules only: a reviewer would ask for a fix (not a by-design
              operation on a model-chosen workspace directory, for example); null for
              configuration rules, whose impact depends on deployment
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stats import fmt, wilson  # noqa: E402

ORDER = [
    "command-injection",
    "path-traversal",
    "ssrf",
    "secrets",
    "cors",
    "bind-all",
    "tls",
    "oauth-scope",
    "tool-poisoning",
]


def summarize(rows: list[dict]) -> dict:
    by: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by[r["stratum"]].append(r)
    out = {}
    for stratum in ORDER:
        rs = by.get(stratum, [])
        if not rs:
            continue
        n = len(rs)
        tp = sum(r["flow"] == "tp" for r in rs)
        act = [r for r in rs if r["actionable"] is not None]
        entry = {
            "labeled": n,
            "repositories": len({r["repo"] for r in rs}),
            "seen_in_development": sum(bool(r["seen_in_development"]) for r in rs),
            "correct": tp,
            "precision": tp / n,
            "precision_ci95": list(wilson(tp, n)),
        }
        if act:
            a = sum(bool(r["actionable"]) for r in act)
            entry["actionable"] = a
            entry["actionable_share"] = a / len(act)
            entry["actionable_ci95"] = list(wilson(a, len(act)))
        out[stratum] = entry
    return out


def markdown(summary: dict) -> str:
    lines = [
        "| Finding type | Labeled | Repos | Correct | Precision (95% CI) | Actionable (95% CI) |",
        "|---|---:|---:|---:|---|---|",
    ]
    for stratum, e in summary.items():
        p = f"{fmt(e['precision'], 2)} ({fmt(e['precision_ci95'][0], 2)} to {fmt(e['precision_ci95'][1], 2)})"
        if "actionable" in e:
            lo, hi = e["actionable_ci95"]
            a = f"{e['actionable']} = {fmt(e['actionable_share'], 2)} ({fmt(lo, 2)} to {fmt(hi, 2)})"
        else:
            a = "n/a"
        lines.append(f"| {stratum} | {e['labeled']} | {e['repositories']} | {e['correct']} | {p} | {a} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--private", type=Path, required=True)
    ap.add_argument("--worksheet", default="final.jsonl")
    ap.add_argument("--labels", default="labels_private.jsonl")
    ap.add_argument("--export", type=Path, default=Path("benchmarks/precision/labels.jsonl"))
    ap.add_argument("--out", type=Path, default=Path("benchmarks/results/precision.json"))
    ap.add_argument(
        "--current",
        help="corpus findings file of the current scanner; labeled items it no longer reports are set aside. "
        "A later change that only removes findings keeps the survivors a random sample of the new findings.",
    )
    args = ap.parse_args(argv)

    sheet = {s["id"]: s for s in map(json.loads, (args.private / args.worksheet).open())}
    labels = {x["id"]: x for x in map(json.loads, (args.private / args.labels).open())}
    dropped = 0
    if args.current:
        live = set()
        for line in (args.private / args.current).open():
            r = json.loads(line)
            for f in r["findings"]:
                live.add((r["repo"], f.get("file", ""), f.get("line", 0), f["rule_id"]))
        keep = {}
        for sid, s in sheet.items():
            f = s["finding"]
            if (s["repo"], f.get("file", ""), f.get("line", 0), f["rule_id"]) in live:
                keep[sid] = s
        dropped = len(sheet) - len(keep)
        sheet = keep
    missing = sorted(set(sheet) - set(labels))
    if missing:
        raise SystemExit(f"unlabeled items: {missing[:10]}")
    rows = []
    for sid in sorted(sheet):
        s, lab = sheet[sid], labels[sid]
        rows.append(
            {
                "id": sid,
                "stratum": s["stratum"],
                "rule": s["finding"]["rule_id"],
                "repo": s["repo"],
                "seen_in_development": bool(s.get("seen_in_development")),
                "flow": lab["flow"],
                "actionable": lab["actionable"],
                "reason": lab["reason"],
            }
        )
    args.export.parent.mkdir(parents=True, exist_ok=True)
    with args.export.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    summary = summarize(rows)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps({"labeled": len(rows), "set_aside_no_longer_reported": dropped, "by_type": summary}, indent=1) + "\n"
    )
    args.out.with_suffix(".md").write_text(markdown(summary))
    print(markdown(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
