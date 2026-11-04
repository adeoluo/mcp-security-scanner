"""Build the scan corpus: list public MCP server repositories and shallow clone them read-only.

Sources:
  1. The official MCP registry API (registry.modelcontextprotocol.io/v0/servers): every server whose
     latest version declares a GitHub source repository.
  2. The official reference servers (modelcontextprotocol/servers) and the archived reference servers
     (modelcontextprotocol/servers-archived); each server subdirectory is treated as its own target.

Each repository is cloned with --depth 1, its commit SHA is recorded, every file that the scanner
does not read is deleted, and the .git directory is removed. Nothing is ever pushed or reported
upstream. The list of URLs and SHAs is written to benchmarks/corpus/corpus.lock.json so the corpus
can be rebuilt exactly; per-repository findings are never committed (see docs/DATA_CARD.md).

Usage:
  python benchmarks/corpus/fetch_corpus.py --out ../.bench-data/mcp-security-scanner/corpus --max 1500
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import random
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
OFFICIAL = [
    "https://github.com/modelcontextprotocol/servers",
    "https://github.com/modelcontextprotocol/servers-archived",
]
KEEP_SUFFIXES = {".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs", ".jsx", ".py", ".json"}
SKIP_DIRS = {"node_modules", "dist", "build", ".git", "vendor", "__pycache__", ".venv", "venv", "coverage"}
MAX_FILE_BYTES = 1_000_000
LOCK = Path(__file__).with_name("corpus.lock.json")


def registry_repos(limit_pages: int = 400) -> list[str]:
    """Page through the official registry and return unique GitHub repository URLs."""
    urls: set[str] = set()
    cursor = ""
    for _ in range(limit_pages):
        q = {"limit": "100"}
        if cursor:
            q["cursor"] = cursor
        with urllib.request.urlopen(f"{REGISTRY}?{urllib.parse.urlencode(q)}", timeout=60) as r:
            page = json.load(r)
        for item in page.get("servers", []):
            repo = (item.get("server") or {}).get("repository") or {}
            url = (repo.get("url") or "").strip().rstrip("/")
            if url.endswith(".git"):
                url = url[:-4]
            parts = urllib.parse.urlparse(url)
            if parts.netloc.lower() != "github.com":
                continue
            segs = [s for s in parts.path.split("/") if s]
            if len(segs) < 2:
                continue
            urls.add(f"https://github.com/{segs[0].lower()}/{segs[1].lower()}")
        cursor = (page.get("metadata") or {}).get("nextCursor") or ""
        if not cursor:
            break
    return sorted(urls)


def prune(root: Path) -> tuple[int, int]:
    """Delete everything the scanner does not read. Returns (files kept, bytes kept)."""
    kept = size = 0
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        for d in list(dirnames):
            if d in SKIP_DIRS:
                shutil.rmtree(os.path.join(dirpath, d), ignore_errors=True)
                dirnames.remove(d)
        for f in filenames:
            p = Path(dirpath) / f
            try:
                st = p.lstat()
            except OSError:
                continue
            if p.is_symlink() or p.suffix.lower() not in KEEP_SUFFIXES or st.st_size > MAX_FILE_BYTES:
                p.unlink(missing_ok=True)
                continue
            if p.suffix == ".json" and f not in {"package.json", "server.json", "manifest.json"}:
                p.unlink(missing_ok=True)
                continue
            kept += 1
            size += st.st_size
    return kept, size


def clone(url: str, out: Path) -> dict | None:
    name = url.removeprefix("https://github.com/").replace("/", "__")
    dest = out / name
    if (dest / ".sha").exists():
        sha = (dest / ".sha").read_text().strip()
        return {"url": url, "sha": sha, "dir": name}
    shutil.rmtree(dest, ignore_errors=True)
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}
    try:
        subprocess.run(
            ["git", "clone", "--quiet", "--depth", "1", "--single-branch", "--no-tags", url, str(dest)],
            check=True,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=180,
        )
        sha = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
        ).stdout.strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        shutil.rmtree(dest, ignore_errors=True)
        return None
    kept, _ = prune(dest)
    if kept == 0:
        shutil.rmtree(dest, ignore_errors=True)
        return None
    (dest / ".sha").write_text(sha + "\n")
    return {"url": url, "sha": sha, "dir": name}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--max", type=int, default=1500, help="maximum registry repositories to clone")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--seed", type=int, default=20261103, help="seed for the uniform sample of registry repositories")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    urls = registry_repos()
    print(f"registry: {len(urls)} unique GitHub repositories", file=sys.stderr)
    pool = [u for u in urls if u not in OFFICIAL]
    random.Random(args.seed).shuffle(pool)
    targets = OFFICIAL + sorted(pool[: args.max])
    t0 = time.time()
    done: list[dict] = []
    with cf.ThreadPoolExecutor(args.workers) as ex:
        for i, res in enumerate(ex.map(lambda u: clone(u, args.out), targets), 1):
            if res:
                done.append(res)
            if i % 50 == 0:
                print(f"{i}/{len(targets)} attempted, {len(done)} cloned, {time.time() - t0:.0f}s", file=sys.stderr)
    done.sort(key=lambda r: r["url"])
    LOCK.write_text(
        json.dumps(
            {
                "sources": ["registry.modelcontextprotocol.io/v0/servers", *OFFICIAL],
                "registry_unique_github_repos": len(urls),
                "seed": args.seed,
                "attempted": len(targets),
                "cloned": len(done),
                "repos": [{"url": r["url"], "sha": r["sha"]} for r in done],
            },
            indent=1,
        )
        + "\n"
    )
    print(f"cloned {len(done)}/{len(targets)} into {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
