# ADR 0007: Audit confidence on every finding

## Status

Accepted.

## Context

The rubric-audited sample of corpus findings ([evaluation report](../EVALUATION_REPORT.md),
section 3) shows that rules differ widely in how often they are right on public servers: 22 of
24 for path traversal, 2 of 11 for SSRF, 0 of 34 for tool-poisoning text found in source. A
report that prints all of them the same way hides that, and a CI gate that fails on a rule that
is usually wrong gets switched off.

## Decision

- Every rule has an audit record derived from the committed labels
  (`benchmarks/precision/labels.jsonl`): correct and labeled counts, precision rounded to two
  places, and the scanner release the audited findings came from (`v0.1.1`). The table lives in
  `internal/findings/confidence.go`; `TestAuditMatchesLabels` recomputes it from the labels file
  and fails when the two differ.
- The record maps to a label: `high` from 0.80, `medium` from 0.50, `low` below 0.50, and
  `unaudited` when no finding of the rule was in the sample. The thresholds are compared on the
  counts, not on rounded values.
- The label is attached to every finding (`confidence` in JSON, `properties.confidence` on each
  SARIF result and rule, a `confidence:` line in text output) and counted in
  `summary.by_confidence`.
- `--min-confidence LEVEL` drops findings of rules below a level. The order is
  `low < unaudited < medium < high`: a rule measured as mostly wrong ranks below a rule that was
  never measured. The default is `low`, which keeps everything, so findings, exit codes and
  benchmark numbers are the same as before unless the flag is given.

## Alternatives considered

- **Lower the severity of low-precision rules.** Severity states the impact if the finding is
  true; precision states how often it is. Mixing them would change the default exit code.
- **Use the lower bound of the Wilson interval.** More careful with small samples, but harder to
  explain than the point estimate, and the counts are printed next to the label anyway.
- **Put `unaudited` at the bottom.** Then `--min-confidence low` would keep rules measured at 0
  of 34 and drop rug-pull and schema checks that nobody has measured, which is backwards for a
  CI gate.
- **Per-finding confidence from flow features.** There is no labeled data to calibrate it.

## Consequences

- The label is a property of the rule on one audited corpus, not a probability for a single
  finding. A planted command injection in a test fixture is reported with `low` because the rule
  was right on 2 of 7 corpus findings.
- Samples are small (4 to 24 findings per rule), come from one rubric audit by the evaluation
  agent with no second annotator, and intervals are wide. Thirteen of the 34 rules have a
  record; rug-pull, schema and transport rules have none.
- Tool-poisoning rules were audited on descriptions extracted from the source of public servers,
  where no description was malicious. The same label is shown for live `probe` findings.
- `--min-confidence medium` or `high` hides every unaudited rule, including rug-pull findings
  from `verify`. Use `unaudited` to drop only the rules measured as imprecise.
- When a rule changes after the audit, its record still describes the audited release until
  the sample is scored again (`make corpus && make precision`); the `measured_on` field says
  which release that was.
- SARIF rule metadata still carries the fixed `precision: medium` it had before; mapping it to
  the audit label would change existing output and is left for a later change.
