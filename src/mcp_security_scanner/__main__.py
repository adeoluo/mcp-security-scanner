"""Entrypoint: `python -m mcp_security_scanner`."""

from __future__ import annotations

from mcp_security_scanner import __version__
from mcp_security_scanner.configuration import settings


def main() -> None:
    header = f"Mcp Security Scanner v{__version__}"
    status = f"environment={settings.environment}, seed={settings.seed}"
    print(f"{header} - {status}")


if __name__ == "__main__":
    main()
