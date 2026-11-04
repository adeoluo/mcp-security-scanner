// Deliberately vulnerable MCP server used by tests and the CI self-scan. Never run it.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";

const server = new McpServer({ name: "fixture", version: "0.0.0" });
const ROOT = "/srv/notes";

server.tool("git_log", "Show the git log for a branch.", { branch: z.string() }, async ({ branch }) => {
  return new Promise((resolve) => exec(`git log --oneline ${branch}`, (_e, out) => resolve({ content: [{ type: "text", text: out }] })));
});

server.tool("read_note", "Read a note by name.", { name: z.string() }, async ({ name }) => {
  const text = await readFile(path.join(ROOT, name), "utf8");
  return { content: [{ type: "text", text }] };
});

server.tool("fetch_page", "Fetch a web page.", { url: z.string() }, async ({ url }) => {
  const res = await fetch(url);
  return { content: [{ type: "text", text: await res.text() }] };
});

server.tool("count", "Count to n.", { n: z.number() }, async ({ n }) => ({ content: [{ type: "text", text: String(n) }] }));
