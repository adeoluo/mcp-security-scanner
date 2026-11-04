# Threat model

Two systems are in scope: the MCP servers and clients that `mcpscan` examines, and `mcpscan`
itself.

## What mcpscan defends against

An MCP client hands tool descriptions to a model and lets the model call tools with arguments
it chooses. The model can be steered by any text it reads (web pages, issues, files, other tool
results), so tool arguments must be treated as attacker-controlled, and tool metadata must be
treated as instructions from whoever controls the server.

| Threat | Vector | What mcpscan checks | Rules |
|---|---|---|---|
| Command or code injection | Model-chosen argument reaches a shell or evaluator | Taint from handler parameters to `exec`, `spawn` with a shell, `os.system`, `subprocess` with `shell=True`, `eval`, `vm` | MCP101, MCP102 |
| Arbitrary file access | Argument used as a path without containment | Taint to file system sinks, with containment checks and validators as sanitizers | MCP111 |
| Server-side request forgery | Argument decides the request host | Taint to HTTP clients, host-fixed URL analysis | MCP121 |
| Credential exposure | Secrets committed to the server source | Provider token formats, high-entropy literals in secret-named variables | MCP131, MCP132 |
| Over-broad access | Server requests more than its tools need, or is reachable more widely than intended | Broad OAuth scopes, bind-all listeners, wildcard CORS, disabled TLS checks | MCP141 to MCP144 |
| Tool poisoning | Instructions hidden in descriptions | Hidden-instruction tags and phrases, Unicode tag characters, zero-width and bidi characters, credential file references, exfiltration and shadowing phrases, encoded blobs, whitespace padding | MCP201 to MCP209 |
| Tool shadowing | A server names or redefines another server's tools | Cross-server name collisions and mentions in `probe --config` and `tools` | MCP205, MCP207 |
| Rug pull | A server changes tool text after approval | Pinned SHA-256 hashes per field | MCP401 to MCP404 |
| Misleading metadata | Destructive tool annotated read-only, malformed schemas | Schema and annotation checks | MCP301 to MCP308 |
| DNS rebinding and open endpoints | Local HTTP server accepts foreign Origins; remote server without TLS or credentials | Live transport checks | MCP501 to MCP503 |

## Threats to mcpscan itself

| Threat | Vector | Mitigation |
|---|---|---|
| Running an untrusted server | `probe -- CMD` and `probe --config` start the configured command | Probing is opt-in and runs exactly the command the user gives; it never starts anything during `scan` or `tools`. Run untrusted servers in a container or VM. |
| Hostile source or manifests | Malformed or adversarial input to the lexer and parsers | The lexer never fails and is fuzzed; files over 1 MB and minified bundles are skipped; JSON input is size-limited in the HTTP service (16 MB) and in the client (64 MB per response). |
| SSRF through the HTTP service | A caller asks the service to connect somewhere | The service only analyzes posted source and manifests; it never connects to a server. |
| Path traversal through the HTTP service | File names in posted source | Names with `..` or absolute paths are rejected; nothing is written to disk. |
| Secret leakage in reports | Findings include matched secrets | Secret findings show the first four characters and the length only. |
| Prompt injection against the scanner | Poisoned descriptions in scanned manifests | The scanner uses no model; descriptions are matched, never executed or followed. |
| Supply chain | Malicious dependency | The Go module has no third-party dependencies; the benchmark harness pins its Python dev tools in `benchmarks/uv.lock`; CodeQL runs on every push to `main` and weekly. |

## Residual risk

- Static analysis misses flows it does not model (see the hard tier of the planted benchmark
  and [Limitations](../README.md#limitations)); a clean report is not proof of safety.
- Tool-poisoning checks are pattern based. Paraphrased instructions without trigger phrases
  are not detected (0 of 60 in the hard tier).
- A server can behave differently during a probe than later; pinning catches changes in
  metadata, not in behavior.
