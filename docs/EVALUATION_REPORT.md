# Evaluation report

Every number here comes from a script in this repository; raw outputs are in
[`benchmarks/results/`](../benchmarks/results). Hardware: Apple M1 (4 performance and 4
efficiency cores), 8 GB RAM, macOS 27.0.1, Go 1.27.3, shared with other jobs during the runs
(load average up to 11), so timings are indicative and were taken one tool at a time.

Three questions:

1. **Recall and false positives on known patterns.** Does the analyzer find planted
   vulnerabilities, and leave safe look-alikes alone, compared with general-purpose scanners?
2. **What do public MCP servers look like?** Finding rates over 1,013 public server
   repositories.
3. **How many corpus findings are right?** Precision on a stratified, hand-labeled sample.

## 1. Planted-vulnerability benchmark

`mcpscan bench --out DIR` generates 432 small MCP servers (seed 20261103), each with exactly one
labeled case; [`benchmarks/compare_planted.py`](../benchmarks/compare_planted.py) runs mcpscan,
Semgrep 1.183.0 (registry packs `p/default`, `p/security-audit`, `p/owasp-top-ten`, `p/secrets`,
`p/gitleaks`, `p/javascript`, `p/typescript`, `p/python`, `p/nodejs`, `p/command-injection`) and
Bandit 1.9.4 (Python cases only), and scores every tool with the same rule: a vulnerable case is
detected when the tool reports a finding of that category anywhere in the case directory; a safe
look-alike is a false positive when it does. The mapping from Semgrep and Bandit rule IDs to
categories is in the script and in `planted.json`.

**Standard tier** (patterns mcpscan was built for: 9 flow patterns from direct use to two-hop
helpers in other files, times 4 TypeScript and 3 Python registration styles). Recall / false
positive rate on safe look-alikes (vulnerable + safe cases):

| Category | mcpscan | Semgrep 1.183.0 | Bandit 1.9.4 (Python only) |
|---|---|---|---|
| Command and code injection | **1.00 / 0.02** (63+42) | 0.59 / 0.40 (63+42) | 1.00 / 0.83 (27+18) |
| Path traversal | **1.00 / 0.02** (63+49) | 0.00 / 0.00 (63+49) | 0.00 / 0.00 (27+21) |
| SSRF | **1.00 / 0.02** (63+49) | 0.11 / 0.10 (63+49) | 0.26 / 0.29 (27+21) |
| Secrets | **1.00 / 0.00** (20+16) | 1.00 / 0.25 (20+16) | 0.90 / 0.62 (10+8) |

**Hard tier** (written to be missed: dynamic dispatch through computed keys, state stored on an
object between calls, computed member access, dependency injection, `getattr`, a common method
name across files; and safe cases whose safety lives in a schema regex, a lookup table or a
ternary):

| Category | mcpscan | Semgrep 1.183.0 | Bandit 1.9.4 (Python only) |
|---|---|---|---|
| Command and code injection | 0.00 / 0.26 (4+19) | 0.50 / 0.26 (4+19) | 0.50 / 1.00 (2+8) |
| Path traversal | 0.25 / 0.26 (4+19) | 0.00 / 0.00 (4+19) | 0.00 / 0.00 (2+8) |
| SSRF | 1.00 / 0.26 (2+19) | 0.00 / 0.05 (2+19) | 0.00 / 0.25 (1+8) |

Overall over all 432 cases: mcpscan recall 0.968 and false positive rate 0.085; Semgrep 0.301
and 0.150; Bandit (Python cases) 0.458 and 0.391. Whole-tree wall time: mcpscan 0.05 s,
Bandit 0.64 s, Semgrep 11.35 s (registry packs fetched on each run).

How to read this:

- The benchmark was written by the author of mcpscan, and the analyzer was developed against
  it. The standard tier is a regression gate (`TestBench` fails if any standard case is missed),
  not evidence of real-world recall. The hard tier lists the known gaps.
- Semgrep and Bandit are general scanners. Their community rules flag dangerous calls without
  knowing which values come from an MCP tool, so they flag safe `execFile` and fixed commands
  (false positives) and miss flows through helpers and template strings (false negatives).
  Semgrep's commercial cross-file taint rules were not available and were not run.
- The 2 percent false positive rate in the standard tier is one TypeScript style
  (`setRequestHandler` with a numeric argument and no schema in the call): without a schema
  the analyzer cannot know the argument is a number.

### Tool-poisoning benchmark

400 descriptions from the same seed (120 benign, 20 benign with trigger words, 200 poisoned with
10 standard techniques, 60 poisoned with 3 hard techniques):

| Technique | Detected |
|---|---:|
| `<IMPORTANT>` hidden-instruction tag | 20 / 20 |
| "Ignore all previous instructions" | 20 / 20 |
| Instruction hidden in Unicode tag characters | 20 / 20 |
| Instruction split with zero-width spaces | 20 / 20 |
| Read a credential file and pass it in an argument | 20 / 20 |
| Shadowing another server's tool | 20 / 20 |
| Pass the conversation history in a parameter | 20 / 20 |
| Base64-encoded instruction | 20 / 20 |
| Instruction after 40 blank lines | 20 / 20 |
| Instruction in a parameter description | 20 / 20 |
| Paraphrase without trigger phrases (hard) | 0 / 20 |
| Polite override, "earlier guidance no longer applies" (hard) | 0 / 20 |
| Payment recipient swap (hard) | 0 / 20 |
| False positives on benign descriptions | 0 / 120 |
| False positives on benign descriptions with trigger words | 1 / 20 |

The checks are patterns. They catch the published techniques and fail on paraphrases; a
model-based classifier would be needed for those.

## 2. Corpus finding rates

[`benchmarks/corpus/fetch_corpus.py`](../benchmarks/corpus/fetch_corpus.py) sampled 1,500 of
the 4,869 GitHub repositories listed in the official MCP registry, plus the two official server
repositories, and cloned 1,013 (see [DATA_CARD.md](DATA_CARD.md)).
[`benchmarks/corpus/scan_corpus.py`](../benchmarks/corpus/scan_corpus.py) scanned each one with
default settings (tests and bundles skipped).

| Measure | Value |
|---|---:|
| Repositories scanned | 1,013 |
| With JavaScript, TypeScript or Python source | 722 |
| With at least one detected tool handler | 455 |
| Source files / lines / bytes | 63,668 / 12.16 M / 522 MB |
| Tool handlers / tool definitions found | 15,852 / 15,953 |

Share of the 1,013 repositories with at least one finding (95% Wilson interval) and the share
among the 455 with detected handlers:

| Category | Repos flagged | Share of all | Share with handlers | Findings |
|---|---:|---|---:|---:|
| Command or code injection | 2 | 0.2% (0.1 to 0.7) | 0.4% | 7 |
| Path traversal | 30 | 3.0% (2.1 to 4.2) | 6.6% | 366 |
| SSRF | 15 | 1.5% (0.9 to 2.4) | 3.3% | 23 |
| Secrets | 12 | 1.2% (0.7 to 2.1) | 2.0% | 22 |
| Over-broad scope (CORS, bind-all, TLS, OAuth) | 194 | 19.2% (16.8 to 21.7) | 35.8% | 787 |
| Tool poisoning (descriptions in source) | 24 | 2.4% (1.6 to 3.5) | 5.1% | 34 |

These are scanner outputs, not confirmed vulnerabilities; section 3 measures how many are
right. Per-repository results are kept private ([ADR 0006](adr/0006-corpus-research-without-disclosure.md)).

## 3. Precision on hand-labeled corpus findings

**Protocol.** The analyzer was tuned on corpus output in two rounds; the 291 distinct findings inspected
during that work form a development set. After the last change to the analyzer that adds or
changes findings, [`benchmarks/precision/sample.py`](../benchmarks/precision/sample.py) drew a
stratified random sample (seed 20261106) that excludes the development set, except where a
stratum had fewer than 10 unseen findings, in which case the whole stratum was used and marked.
183 findings were labeled by hand. One later change only restricted sources in inferred handlers
([ADR 0004](adr/0004-where-tool-input-comes-from.md)); it removes findings and adds none, so the
labeled findings it still reports (158) remain a random sample of the current output, and the 25
it no longer reports (6 path traversal, 19 SSRF, all labeled false positives) are set aside.

**Rubric.** *Correct*: for taint rules, a value derived from tool input reaches the sink without
an effective check (second-order flows through files at a model-chosen path count, and are
noted); for other rules, the code does what the finding says. *Actionable*: a reviewer would ask
for a fix: arbitrary file read or overwrite, a fetch of any URL without private-address
filtering, a committed credential; reading fixed-name files under a workspace directory that the
tool is meant to receive does not count. Actionability is not judged for configuration rules,
whose impact depends on deployment.

| Finding type | Labeled | Repos | Correct | Precision (95% CI) | Actionable (95% CI) |
|---|---:|---:|---:|---|---|
| Command injection (all corpus findings) | 7 | 2 | 2 | 0.29 (0.08 to 0.64) | 0.29 (0.08 to 0.64) |
| Path traversal | 24 | 15 | 22 | 0.92 (0.74 to 0.98) | 0.08 (0.02 to 0.26) |
| SSRF | 11 | 8 | 2 | 0.18 (0.05 to 0.48) | 0.18 (0.05 to 0.48) |
| Secrets (all corpus findings) | 22 | 12 | 11 | 0.50 (0.31 to 0.69) | 0.50 (0.31 to 0.69) |
| Wildcard CORS | 15 | 12 | 14 | 0.93 (0.70 to 0.99) | n/a |
| Bind to all interfaces | 15 | 8 | 13 | 0.87 (0.62 to 0.96) | n/a |
| TLS verification disabled | 15 | 12 | 15 | 1.00 (0.80 to 1.00) | n/a |
| Broad OAuth scope | 15 | 4 | 12 | 0.80 (0.55 to 0.93) | n/a |
| Tool poisoning (all corpus findings) | 34 | 24 | 0 | 0.00 (0.00 to 0.10) | 0.00 (0.00 to 0.10) |

Confidence intervals treat findings as independent; several come from the same repository, so
the true uncertainty is wider. Labels: [`benchmarks/precision/labels.jsonl`](../benchmarks/precision/labels.jsonl).

### Error analysis

- **Command injection (5 false positives, 2 repositories).** All five come from objects passed
  whole into helpers: the helper receives `info` and sees `info.packageManager` as tainted
  because `info.path` is. The two correct findings are a shell command built from a
  model-supplied list of table names inside quotes the input can close, and a second-order flow
  from package names in a manifest at a model-chosen path.
- **Path traversal.** The flows are almost always real (22 of 24), but most are by design:
  developer tools receive a workspace or project directory and read or write their own files
  under it. Two are actionable: a tool that writes to any path the model names, and a tool that
  uploads any local file to a remote service.
- **SSRF (9 false positives).** Hosts that come from server configuration objects passed to
  registered handlers (`env`, `link`, `apiConfig`), clients with a fixed base URL, and URLs
  returned by an API. The two correct findings are a file-reading tool that also fetches any URL
  without private-address filtering.
- **Secrets (11 false positives).** PEM headers in code that formats keys or in form
  placeholders (5), public analytics keys and contract addresses (4), a documented example token
  and a test fixture (2). The provider-format rule should require a key body after the PEM
  header.
- **Configuration rules.** Mostly right. Errors are string comparisons rather than settings
  (`allowedOrigins === '*'`, `host in ("0.0.0.0", "::")`), the word "repo" in prose under a key
  named `scope`, and test scripts.
- **Tool poisoning (34 false positives).** No corpus description was malicious. The flags are
  benign guidance aimed at the model ("never silently send another post", "use this instead of
  calling lookup_lei", "before calling it you MUST show the user the block"), and tools whose
  purpose involves `.env` files, SSH keys or client configuration. 34 flags over 15,953 tool
  definitions is a rate of 0.21 percent; on benign text the benchmark gives 0 of 120 and 1 of 20.

## 4. Speed and memory

[`benchmarks/corpus/speed.py`](../benchmarks/corpus/speed.py) ran each tool on the same 20 corpus
repositories (random, seed 7, at least five source files each), one process per repository,
under `/usr/bin/time`:

| Measure | mcpscan | Semgrep 1.183.0 (10 registry packs) |
|---|---:|---:|
| Total wall time, 20 repositories | 2.2 s | 502 s |
| Median per repository | 0.041 s | 9.3 s |
| Median peak memory | 20 MB | 304 MB |
| Largest peak memory | 180 MB | 852 MB |

Semgrep fetches and compiles its rule packs on every run, which accounts for several seconds of
each run (its fastest repository took 5.9 s); its peak memory is that of the whole process tree
as reported by `time`. The two tools also do different work: Semgrep applies about 1,300
general rules, mcpscan about 30 MCP-specific ones. The comparison shows what each costs to run in
CI on an MCP server, not the speed of equivalent analyses.

The full corpus scan (1,013 repositories, 522 MB, one process per repository) took 79 s, about
6.6 MB/s including process start-up, while other jobs kept the load average between 7 and 10 on
8 cores, so the time is an upper bound for this machine. Peak resident memory was 755 MB, for
the largest repository (139 MB on disk, 61 MB of JavaScript, TypeScript and Python left after
skipping dependencies, tests and bundles, 6.8 million tokens). Every file's tokens are kept for
the cross-file pass, so memory grows with source size at roughly 12 bytes per source byte.

## Reproduce

```sh
make build
make bench                      # planted and poisoning benchmarks (mcpscan only, under a second)
make compare                    # adds Semgrep and Bandit (needs uv; downloads the rule packs)
python benchmarks/corpus/fetch_corpus.py --out ../.bench-data/mcp-security-scanner/corpus
make corpus                     # finding rates
make speed                      # mcpscan and Semgrep on 20 corpus repositories
python benchmarks/precision/sample.py --private PRIVATE --corpus CORPUS   # worksheet for labeling
python benchmarks/precision/score.py --private PRIVATE --current corpus_findings.jsonl
```
