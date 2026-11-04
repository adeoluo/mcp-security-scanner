# ADR 0003: Token-level taint tracking with per-function summaries

## Status

Accepted.

## Context

Pattern rules ("any call to exec is bad") flag every child process in a code base, including the
many that run fixed commands. The interesting question for an MCP server is narrower: can a
value chosen by the model (a tool argument) reach a shell, an evaluator, a file path or the host
of an outbound request?

## Decision

Treat tool handler parameters as the only sources and follow them with a flow-sensitive walk over
each function body:

- assignments, destructuring, `for ... of/in`, comprehensions and `with ... as` propagate taint;
- reassignment to an untainted value clears it;
- three taint bits (command, path, URL host) are cleared independently by sanitizers
  (`shlex.quote`, `path.basename`, `encodeURIComponent`, validators by name) and by guards
  (`startsWith` containment checks, allowlist membership, regex tests);
- the condition of a ternary and the key of an index expression do not flow into the result;
- URL host taint is dropped when the expression fixes the scheme and host before any tainted
  part, so `https://api.example.com/items/${id}` is not SSRF;
- calls into repository functions use per-parameter summaries (sinks reached, taint returned,
  and per-key taint when every return is an object literal); unknown library calls propagate
  taint from receiver and arguments.

## Consequences

- On the planted benchmark the standard tier is detected in full with 1.5 to 2.4 percent false
  positives on safe look-alikes, against 0.30 recall for Semgrep's registry packs.
- Objects passed whole into helpers are field-insensitive: a helper that receives `info` sees
  every field as tainted. This caused five of the seven command-injection false positives in
  the hand-labeled corpus sample.
- No alias analysis, no flow through object state between calls, no dynamic dispatch through
  computed keys. The hard tier of the planted benchmark measures exactly these misses.
