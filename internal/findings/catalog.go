package findings

// Catalog lists every rule. IDs are stable; SARIF output and baselines refer to them.
var Catalog = map[string]Rule{}

func add(r Rule) { Catalog[r.ID] = r }

func init() {
	// Static analysis of server source: tool input reaching dangerous sinks.
	add(Rule{"MCP101", "shell-command-injection", CommandInjection, Critical,
		"Tool input reaches a shell command",
		"A value supplied by the model through a tool call flows into a function that runs a shell command (exec, execSync, spawn with shell, os.system, subprocess with shell=True). A prompt-injected model can run arbitrary commands. Pass arguments as an array without a shell, or validate against an allowlist.",
		"CWE-78"})
	add(Rule{"MCP102", "code-injection", CommandInjection, Critical,
		"Tool input reaches code evaluation",
		"A tool argument flows into eval, exec, new Function or the vm module, which evaluates it as code. Parse the input instead of evaluating it.",
		"CWE-94"})
	add(Rule{"MCP111", "path-traversal", PathTraversal, High,
		"Tool input reaches a file system path without containment",
		"A tool argument is used as or joined into a file path that is read, written or deleted, with no check that the resolved path stays inside an allowed root. Resolve the real path and verify it is inside the allowed directories before use.",
		"CWE-22"})
	add(Rule{"MCP121", "server-side-request-forgery", SSRF, High,
		"Tool input controls the host of an outbound request",
		"A tool argument decides where the server sends an HTTP request (the whole URL, or the scheme and host part). The server can be steered to internal services or cloud metadata endpoints. Fix the host, or check the parsed host against an allowlist and block private address ranges.",
		"CWE-918"})
	add(Rule{"MCP131", "hardcoded-provider-secret", Secrets, High,
		"Credential with a known provider format in source",
		"A string matches the format of a real credential (cloud keys, API tokens, private keys). Revoke it, load it from the environment or a secret manager, and remove it from history.",
		"CWE-798"})
	add(Rule{"MCP132", "hardcoded-generic-secret", Secrets, Medium,
		"High-entropy literal assigned to a secret-named variable",
		"A long, high-entropy string literal is assigned to a variable or key whose name suggests a secret (token, api_key, password). Load secrets from the environment.",
		"CWE-798"})
	add(Rule{"MCP141", "over-broad-oauth-scope", BroadScope, Medium,
		"OAuth scope wider than a tool server usually needs",
		"The server requests a scope that grants full account, repository, mailbox, drive or directory access. Request the narrowest scopes the tools need.",
		"CWE-250"})
	add(Rule{"MCP142", "listen-all-interfaces", BroadScope, Low,
		"Network transport bound to all interfaces",
		"The server listens on 0.0.0.0 or ::. A local MCP server bound to every interface is reachable from the network. Bind to 127.0.0.1 unless remote access is intended and authenticated.",
		"CWE-1327"})
	add(Rule{"MCP143", "cors-wildcard", BroadScope, Medium,
		"CORS allows any origin",
		"The HTTP transport sends Access-Control-Allow-Origin: * (or an equivalent framework setting), so any web page can call it from a browser. Restrict origins.",
		"CWE-942"})
	add(Rule{"MCP144", "tls-verification-disabled", BroadScope, Medium,
		"TLS certificate verification disabled",
		"Outbound requests skip certificate verification (rejectUnauthorized: false, NODE_TLS_REJECT_UNAUTHORIZED=0, verify=False), so a network attacker can read and change tool traffic.",
		"CWE-295"})

	// Tool description and manifest analysis.
	add(Rule{"MCP201", "hidden-instructions", ToolPoisoning, High,
		"Tool description contains instructions aimed at the model",
		"The description contains text that tries to steer the model rather than describe the tool: hidden-instruction tags, requests to ignore earlier instructions, or requests to keep actions from the user. Descriptions are read by the model as trusted context.",
		"CWE-74"})
	add(Rule{"MCP202", "unicode-tag-characters", ToolPoisoning, Critical,
		"Invisible Unicode tag characters in tool metadata",
		"The text contains characters from the Unicode tag block (U+E0000 to U+E007F). They render as nothing but many models read them as ASCII, so they can carry hidden instructions. The decoded hidden text is shown as evidence.",
		"CWE-116"})
	add(Rule{"MCP203", "invisible-characters", ToolPoisoning, Medium,
		"Zero-width or bidirectional control characters in tool metadata",
		"The text contains zero-width, invisible or bidirectional override characters that hide or reorder content when displayed to a person but not when read by the model.",
		"CWE-116"})
	add(Rule{"MCP204", "sensitive-file-reference", ToolPoisoning, High,
		"Tool description refers to credential or configuration files",
		"The description mentions files such as SSH keys, cloud credentials, .env files or MCP client configuration. Combined with an instruction to read or send them this is the classic tool-poisoning exfiltration pattern.",
		"CWE-200"})
	add(Rule{"MCP205", "tool-shadowing", ToolPoisoning, High,
		"Tool description tries to change how other tools behave",
		"The description gives rules for other tools (when another tool is called, instead of using another tool, all messages must be sent to an address). A server can use this to hijack tools from other, trusted servers.",
		"CWE-74"})
	add(Rule{"MCP206", "exfiltration-channel", ToolPoisoning, High,
		"Tool description asks the model to pass data through a parameter or URL",
		"The description instructs the model to put file contents, conversation history or credentials into a parameter or to send them to an address.",
		"CWE-200"})
	add(Rule{"MCP207", "duplicate-tool-name", ToolPoisoning, Medium,
		"Tool name is defined by more than one server",
		"Two configured servers expose a tool with the same name, so the client or model may call the wrong one. A malicious server can register the name of a trusted tool.",
		"CWE-694"})
	add(Rule{"MCP208", "encoded-payload", ToolPoisoning, Medium,
		"Encoded text blob in tool metadata",
		"The description contains a long base64 or hex blob that decodes to readable text. Hidden instructions are sometimes encoded to evade review.",
		"CWE-116"})
	add(Rule{"MCP209", "padding-hides-text", ToolPoisoning, Medium,
		"Large whitespace gap inside tool metadata",
		"The description contains a long run of blank lines or spaces followed by more text, which pushes content out of view in client UIs while the model still reads it.",
		"CWE-451"})

	// Schema checks on live or extracted manifests.
	add(Rule{"MCP301", "invalid-input-schema", Schema, Medium,
		"Tool inputSchema is missing or not an object schema",
		"The MCP specification requires inputSchema to be a JSON Schema object with type \"object\". Clients may refuse the tool or pass unvalidated input.",
		"CWE-20"})
	add(Rule{"MCP302", "untyped-parameter", Schema, Low,
		"Tool parameter without a type",
		"A property in inputSchema has no type, enum, const or composition keyword, so any JSON value is accepted.",
		"CWE-20"})
	add(Rule{"MCP303", "required-not-defined", Schema, Low,
		"Required parameter not defined in properties",
		"inputSchema.required names a property that is not declared in properties.",
		"CWE-20"})
	add(Rule{"MCP304", "missing-description", Schema, Low,
		"Tool without a description",
		"Without a description the model has to guess what the tool does, which raises the chance of unintended calls.",
		""})
	add(Rule{"MCP305", "invalid-tool-name", Schema, Medium,
		"Tool name outside the allowed character set",
		"Tool names should be 1 to 128 characters from A to Z, a to z, 0 to 9, underscore, hyphen and dot. Other characters, including look-alike Unicode letters, can be used to impersonate other tools.",
		"CWE-1007"})
	add(Rule{"MCP306", "duplicate-tool-in-server", Schema, Medium,
		"Server lists the same tool name twice",
		"tools/list returned two tools with the same name.",
		""})
	add(Rule{"MCP307", "unconstrained-dangerous-parameter", Schema, Low,
		"Command, code, path or URL parameter without constraints",
		"A string parameter whose name suggests a command, script, path or URL has no enum, pattern or format. This is not a vulnerability by itself, but it is the input that the server must validate.",
		"CWE-20"})
	add(Rule{"MCP308", "annotation-mismatch", Schema, Medium,
		"Tool annotations claim read-only for a destructive-looking tool",
		"The tool is annotated readOnlyHint: true (or destructiveHint: false) but its name says it deletes, writes or executes. Clients use these hints to decide whether to ask the user.",
		"CWE-451"})

	// Rug-pull detection against a pinned manifest.
	add(Rule{"MCP401", "tool-definition-changed", RugPull, High,
		"Tool definition differs from the pinned hash",
		"The description, schema or annotations of a pinned tool changed since it was approved. A server can present a harmless definition for review and change it later.",
		"CWE-494"})
	add(Rule{"MCP402", "tool-added", RugPull, Medium,
		"Server exposes a tool that was not pinned",
		"A new tool appeared since the manifest was pinned.",
		"CWE-494"})
	add(Rule{"MCP403", "tool-removed", RugPull, Low,
		"Pinned tool no longer exposed",
		"A pinned tool disappeared from the server.",
		""})
	add(Rule{"MCP404", "server-identity-changed", RugPull, Medium,
		"Server name or version differs from the pin",
		"serverInfo reported during initialize differs from the pinned value.",
		""})

	// Live transport checks.
	add(Rule{"MCP501", "origin-not-validated", Transport, Medium,
		"HTTP transport accepts requests from a foreign Origin",
		"The Streamable HTTP transport answered a request carrying an Origin header from another site. The MCP specification requires servers to validate Origin to prevent DNS rebinding attacks against local servers.",
		"CWE-346"})
	add(Rule{"MCP502", "unauthenticated-remote", Transport, Medium,
		"Remote HTTP transport answers without authentication",
		"A server on a non-loopback address completed initialize and tools/list without any credentials.",
		"CWE-306"})
	add(Rule{"MCP503", "plaintext-remote", Transport, Medium,
		"Remote HTTP transport without TLS",
		"The server URL uses http:// on a non-loopback host.",
		"CWE-319"})
}
