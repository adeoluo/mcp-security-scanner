# Deliberately vulnerable MCP server used by tests and the CI self-scan. Never run it.
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fixture")
ROOT = Path("/srv/notes")


@mcp.tool()
def ping(host: str) -> str:
    """Ping a host once."""
    return subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def safe_read(name: str) -> str:
    """Read a note inside the notes directory."""
    p = (ROOT / name).resolve()
    if not p.is_relative_to(ROOT):
        raise ValueError("outside the notes directory")
    return p.read_text()
