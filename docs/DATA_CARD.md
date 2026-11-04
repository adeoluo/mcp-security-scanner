# Data card

The evaluation uses three datasets. Two are produced by this repository; one is a corpus of
public source code that is cloned locally and never redistributed.

## 1. Public MCP server corpus

| Field | Value |
|---|---|
| Source | Official MCP registry API (`registry.modelcontextprotocol.io/v0/servers`), every server entry that names a GitHub repository (4,869 unique repositories on 2026-11-03), plus `modelcontextprotocol/servers` and `modelcontextprotocol/servers-archived` |
| Sample | Uniform random sample of 1,500 registry repositories (seed 20261103) plus the two official repositories |
| Cloned | 1,013 of 1,502 (the rest were deleted, private, or had no JavaScript, TypeScript, Python or JSON files) |
| Size | 63,668 source files scanned, 12.16 million lines, 522 MB; 1.0 GB on disk after pruning |
| Languages | 722 repositories with JavaScript, TypeScript or Python; the rest are other languages or remote-only entries |
| Pinning | `benchmarks/corpus/corpus.lock.json` records URL and commit SHA for every cloned repository |
| Rebuild | `python benchmarks/corpus/fetch_corpus.py --out <dir>` (the registry changes over time; the lock records what was scanned) |
| Handling | Shallow, read-only clones under `.bench-data/` outside the repository. Code is never executed. Per-repository results stay in a private directory. |
| License | Each repository keeps its own license; no third-party code is committed here |

Known biases: the registry over-represents recent, small, TypeScript servers published by their
authors; servers published only to npm or PyPI without a GitHub link are absent; deleted or
private repositories (about a third of the sample) are missing.

## 2. Planted-vulnerability benchmark

Written by `mcpscan bench --out DIR` from seed 20261103: 432 small servers, each with one
labeled case.

| Group | Cases |
|---|---|
| Vulnerable, standard tier (command injection, path traversal, SSRF; 9 flow patterns by 4 TypeScript and 3 Python registration styles) | 189 |
| Planted secrets (provider formats with random values, never issued) | 20 |
| Safe look-alikes, standard tier | 140 |
| Safe secret look-alikes (placeholders, documented examples, digests, environment lookups) | 16 |
| Hard tier: vulnerable patterns the analyzer does not model | 10 |
| Hard tier: safe patterns the analyzer does not model or models only partly (schema regex, lookup tables, ternaries) | 57 |

Every payload is inert: commands are `ls`, paths sit under a fictional `/srv/data`, hosts are
reserved example domains. The benchmark was written by the author of the scanner and covers
patterns the scanner was designed for; treat the standard tier as a regression test and the
hard tier as a statement of known gaps.

## 3. Tool-poisoning benchmark

Generated from the same seed: 400 tool descriptions.

| Group | Count |
|---|---|
| Benign descriptions (30 actions by 4 phrasings) | 120 |
| Benign descriptions with trigger words ("IMPORTANT", ".env", "instead of", "send an email") | 20 |
| Poisoned, 10 standard techniques by 20 | 200 |
| Poisoned, 3 hard techniques (paraphrase, polite override, recipient swap) by 20 | 60 |

The techniques follow public write-ups of tool poisoning and tool shadowing (Invariant Labs,
"MCP Security Notification: Tool Poisoning Attacks", April 2025) and of hidden Unicode tag text
(Johann Rehberger, "ASCII Smuggler", 2024). The canary files and addresses are fictional.

## 4. Hand labels

183 corpus findings drawn by stratified random sampling after the last analyzer change, labeled
by the author with a written rubric (see `docs/EVALUATION_REPORT.md`). Exported in
`benchmarks/precision/labels.jsonl` with salted repository pseudonyms and generic reasons only.
