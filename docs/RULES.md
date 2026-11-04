# Rules

Written by `mcpscan rules --format markdown`. SARIF results link to the entries below.

| ID | Name | Category | Severity | CWE |
|---|---|---|---|---|
| [MCP101](#mcp101) | shell-command-injection | command-injection | critical | CWE-78 |
| [MCP102](#mcp102) | code-injection | command-injection | critical | CWE-94 |
| [MCP111](#mcp111) | path-traversal | path-traversal | high | CWE-22 |
| [MCP121](#mcp121) | server-side-request-forgery | ssrf | high | CWE-918 |
| [MCP131](#mcp131) | hardcoded-provider-secret | secrets | high | CWE-798 |
| [MCP132](#mcp132) | hardcoded-generic-secret | secrets | medium | CWE-798 |
| [MCP141](#mcp141) | over-broad-oauth-scope | over-broad-scope | medium | CWE-250 |
| [MCP142](#mcp142) | listen-all-interfaces | over-broad-scope | low | CWE-1327 |
| [MCP143](#mcp143) | cors-wildcard | over-broad-scope | medium | CWE-942 |
| [MCP144](#mcp144) | tls-verification-disabled | over-broad-scope | medium | CWE-295 |
| [MCP201](#mcp201) | hidden-instructions | tool-poisoning | high | CWE-74 |
| [MCP202](#mcp202) | unicode-tag-characters | tool-poisoning | critical | CWE-116 |
| [MCP203](#mcp203) | invisible-characters | tool-poisoning | medium | CWE-116 |
| [MCP204](#mcp204) | sensitive-file-reference | tool-poisoning | high | CWE-200 |
| [MCP205](#mcp205) | tool-shadowing | tool-poisoning | high | CWE-74 |
| [MCP206](#mcp206) | exfiltration-channel | tool-poisoning | high | CWE-200 |
| [MCP207](#mcp207) | duplicate-tool-name | tool-poisoning | medium | CWE-694 |
| [MCP208](#mcp208) | encoded-payload | tool-poisoning | medium | CWE-116 |
| [MCP209](#mcp209) | padding-hides-text | tool-poisoning | medium | CWE-451 |
| [MCP301](#mcp301) | invalid-input-schema | schema | medium | CWE-20 |
| [MCP302](#mcp302) | untyped-parameter | schema | low | CWE-20 |
| [MCP303](#mcp303) | required-not-defined | schema | low | CWE-20 |
| [MCP304](#mcp304) | missing-description | schema | low |  |
| [MCP305](#mcp305) | invalid-tool-name | schema | medium | CWE-1007 |
| [MCP306](#mcp306) | duplicate-tool-in-server | schema | medium |  |
| [MCP307](#mcp307) | unconstrained-dangerous-parameter | schema | low | CWE-20 |
| [MCP308](#mcp308) | annotation-mismatch | schema | medium | CWE-451 |
| [MCP401](#mcp401) | tool-definition-changed | rug-pull | high | CWE-494 |
| [MCP402](#mcp402) | tool-added | rug-pull | medium | CWE-494 |
| [MCP403](#mcp403) | tool-removed | rug-pull | low |  |
| [MCP404](#mcp404) | server-identity-changed | rug-pull | medium |  |
| [MCP501](#mcp501) | origin-not-validated | transport | medium | CWE-346 |
| [MCP502](#mcp502) | unauthenticated-remote | transport | low | CWE-306 |
| [MCP503](#mcp503) | plaintext-remote | transport | medium | CWE-319 |

<a id="mcp101"></a>

## MCP101 shell-command-injection

**Tool input reaches a shell command.** A value supplied by the model through a tool call flows into a function that runs a shell command (exec, execSync, spawn with shell, os.system, subprocess with shell=True). A prompt-injected model can run arbitrary commands. Pass arguments as an array without a shell, or validate against an allowlist.

Category: command-injection. Default severity: critical. CWE-78.

<a id="mcp102"></a>

## MCP102 code-injection

**Tool input reaches code evaluation.** A tool argument flows into eval, exec, new Function or the vm module, which evaluates it as code. Parse the input instead of evaluating it.

Category: command-injection. Default severity: critical. CWE-94.

<a id="mcp111"></a>

## MCP111 path-traversal

**Tool input reaches a file system path without containment.** A tool argument is used as or joined into a file path that is read, written or deleted, with no check that the resolved path stays inside an allowed root. Resolve the real path and verify it is inside the allowed directories before use.

Category: path-traversal. Default severity: high. CWE-22.

<a id="mcp121"></a>

## MCP121 server-side-request-forgery

**Tool input controls the host of an outbound request.** A tool argument decides where the server sends an HTTP request (the whole URL, or the scheme and host part). The server can be steered to internal services or cloud metadata endpoints. Fix the host, or check the parsed host against an allowlist and block private address ranges.

Category: ssrf. Default severity: high. CWE-918.

<a id="mcp131"></a>

## MCP131 hardcoded-provider-secret

**Credential with a known provider format in source.** A string matches the format of a real credential (cloud keys, API tokens, private keys). Revoke it, load it from the environment or a secret manager, and remove it from history.

Category: secrets. Default severity: high. CWE-798.

<a id="mcp132"></a>

## MCP132 hardcoded-generic-secret

**High-entropy literal assigned to a secret-named variable.** A long, high-entropy string literal is assigned to a variable or key whose name suggests a secret (token, api_key, password). Load secrets from the environment.

Category: secrets. Default severity: medium. CWE-798.

<a id="mcp141"></a>

## MCP141 over-broad-oauth-scope

**OAuth scope wider than a tool server usually needs.** The server requests a scope that grants full account, repository, mailbox, drive or directory access. Request the narrowest scopes the tools need.

Category: over-broad-scope. Default severity: medium. CWE-250.

<a id="mcp142"></a>

## MCP142 listen-all-interfaces

**Network transport bound to all interfaces.** The server listens on 0.0.0.0 or ::. A local MCP server bound to every interface is reachable from the network. Bind to 127.0.0.1 unless remote access is intended and authenticated.

Category: over-broad-scope. Default severity: low. CWE-1327.

<a id="mcp143"></a>

## MCP143 cors-wildcard

**CORS allows any origin.** The HTTP transport sends Access-Control-Allow-Origin: * (or an equivalent framework setting), so any web page can call it from a browser. Restrict origins.

Category: over-broad-scope. Default severity: medium. CWE-942.

<a id="mcp144"></a>

## MCP144 tls-verification-disabled

**TLS certificate verification disabled.** Outbound requests skip certificate verification (rejectUnauthorized: false, NODE_TLS_REJECT_UNAUTHORIZED=0, verify=False), so a network attacker can read and change tool traffic.

Category: over-broad-scope. Default severity: medium. CWE-295.

<a id="mcp201"></a>

## MCP201 hidden-instructions

**Tool description contains instructions aimed at the model.** The description contains text that tries to steer the model rather than describe the tool: hidden-instruction tags, requests to ignore earlier instructions, or requests to keep actions from the user. Descriptions are read by the model as trusted context.

Category: tool-poisoning. Default severity: high. CWE-74.

<a id="mcp202"></a>

## MCP202 unicode-tag-characters

**Invisible Unicode tag characters in tool metadata.** The text contains characters from the Unicode tag block (U+E0000 to U+E007F). They render as nothing but many models read them as ASCII, so they can carry hidden instructions. The decoded hidden text is shown as evidence.

Category: tool-poisoning. Default severity: critical. CWE-116.

<a id="mcp203"></a>

## MCP203 invisible-characters

**Zero-width or bidirectional control characters in tool metadata.** The text contains zero-width, invisible or bidirectional override characters that hide or reorder content when displayed to a person but not when read by the model.

Category: tool-poisoning. Default severity: medium. CWE-116.

<a id="mcp204"></a>

## MCP204 sensitive-file-reference

**Tool description refers to credential or configuration files.** The description mentions files such as SSH keys, cloud credentials, .env files or MCP client configuration. Combined with an instruction to read or send them this is the classic tool-poisoning exfiltration pattern.

Category: tool-poisoning. Default severity: high. CWE-200.

<a id="mcp205"></a>

## MCP205 tool-shadowing

**Tool description tries to change how other tools behave.** The description gives rules for other tools (when another tool is called, instead of using another tool, all messages must be sent to an address). A server can use this to hijack tools from other, trusted servers.

Category: tool-poisoning. Default severity: high. CWE-74.

<a id="mcp206"></a>

## MCP206 exfiltration-channel

**Tool description asks the model to pass data through a parameter or URL.** The description instructs the model to put file contents, conversation history or credentials into a parameter or to send them to an address.

Category: tool-poisoning. Default severity: high. CWE-200.

<a id="mcp207"></a>

## MCP207 duplicate-tool-name

**Tool name is defined by more than one server.** Two configured servers expose a tool with the same name, so the client or model may call the wrong one. A malicious server can register the name of a trusted tool.

Category: tool-poisoning. Default severity: medium. CWE-694.

<a id="mcp208"></a>

## MCP208 encoded-payload

**Encoded text blob in tool metadata.** The description contains a long base64 or hex blob that decodes to readable text. Hidden instructions are sometimes encoded to evade review.

Category: tool-poisoning. Default severity: medium. CWE-116.

<a id="mcp209"></a>

## MCP209 padding-hides-text

**Large whitespace gap inside tool metadata.** The description contains a long run of blank lines or spaces followed by more text, which pushes content out of view in client UIs while the model still reads it.

Category: tool-poisoning. Default severity: medium. CWE-451.

<a id="mcp301"></a>

## MCP301 invalid-input-schema

**Tool inputSchema is missing or not an object schema.** The MCP specification requires inputSchema to be a JSON Schema object with type "object". Clients may refuse the tool or pass unvalidated input.

Category: schema. Default severity: medium. CWE-20.

<a id="mcp302"></a>

## MCP302 untyped-parameter

**Tool parameter without a type.** A property in inputSchema has no type, enum, const or composition keyword, so any JSON value is accepted.

Category: schema. Default severity: low. CWE-20.

<a id="mcp303"></a>

## MCP303 required-not-defined

**Required parameter not defined in properties.** inputSchema.required names a property that is not declared in properties.

Category: schema. Default severity: low. CWE-20.

<a id="mcp304"></a>

## MCP304 missing-description

**Tool without a description.** Without a description the model has to guess what the tool does, which raises the chance of unintended calls.

Category: schema. Default severity: low.

<a id="mcp305"></a>

## MCP305 invalid-tool-name

**Tool name outside the allowed character set.** Tool names should be 1 to 128 characters from A to Z, a to z, 0 to 9, underscore, hyphen and dot. Other characters, including look-alike Unicode letters, can be used to impersonate other tools.

Category: schema. Default severity: medium. CWE-1007.

<a id="mcp306"></a>

## MCP306 duplicate-tool-in-server

**Server lists the same tool name twice.** tools/list returned two tools with the same name.

Category: schema. Default severity: medium.

<a id="mcp307"></a>

## MCP307 unconstrained-dangerous-parameter

**Command, code, path or URL parameter without constraints.** A string parameter whose name suggests a command, script, path or URL has no enum, pattern or format. This is not a vulnerability by itself, but it is the input that the server must validate.

Category: schema. Default severity: low. CWE-20.

<a id="mcp308"></a>

## MCP308 annotation-mismatch

**Tool annotations claim read-only for a destructive-looking tool.** The tool is annotated readOnlyHint: true (or destructiveHint: false) but its name says it deletes, writes or executes. Clients use these hints to decide whether to ask the user.

Category: schema. Default severity: medium. CWE-451.

<a id="mcp401"></a>

## MCP401 tool-definition-changed

**Tool definition differs from the pinned hash.** The description, schema or annotations of a pinned tool changed since it was approved. A server can present a harmless definition for review and change it later.

Category: rug-pull. Default severity: high. CWE-494.

<a id="mcp402"></a>

## MCP402 tool-added

**Server exposes a tool that was not pinned.** A new tool appeared since the manifest was pinned.

Category: rug-pull. Default severity: medium. CWE-494.

<a id="mcp403"></a>

## MCP403 tool-removed

**Pinned tool no longer exposed.** A pinned tool disappeared from the server.

Category: rug-pull. Default severity: low.

<a id="mcp404"></a>

## MCP404 server-identity-changed

**Server name or version differs from the pin.** serverInfo reported during initialize differs from the pinned value.

Category: rug-pull. Default severity: medium.

<a id="mcp501"></a>

## MCP501 origin-not-validated

**HTTP transport accepts requests from a foreign Origin.** The Streamable HTTP transport answered a request carrying an Origin header from another site. The MCP specification requires servers to validate Origin to prevent DNS rebinding attacks against local servers.

Category: transport. Default severity: medium. CWE-346.

<a id="mcp502"></a>

## MCP502 unauthenticated-remote

**Remote HTTP transport answers without authentication.** A server on a non-loopback address completed initialize and tools/list without any credentials.

Category: transport. Default severity: low. CWE-306.

<a id="mcp503"></a>

## MCP503 plaintext-remote

**Remote HTTP transport without TLS.** The server URL uses http:// on a non-loopback host.

Category: transport. Default severity: medium. CWE-319.
