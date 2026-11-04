import json
from pathlib import Path

from corpus import fetch_corpus, scan_corpus


def row(repo, handlers, cats, rules):
    return {
        "repo": repo,
        "files": 3,
        "lines": 30,
        "tool_handlers": handlers,
        "tool_definitions": handlers,
        "seconds": 0.1,
        "categories": cats,
        "rules": rules,
    }


def test_aggregate():
    rows = [
        row("a", 2, {"ssrf": 1, "secrets": 2}, {"MCP121": 1, "MCP131": 2}),
        row("b", 0, {"secrets": 1}, {"MCP131": 1}),
        row("c", 1, {}, {}),
    ]
    agg = scan_corpus.aggregate(rows)
    assert agg["repositories"] == 3 and agg["repositories_with_tool_handlers"] == 2
    assert agg["by_category"]["secrets"]["repos_flagged"] == 2
    assert agg["by_category"]["secrets"]["share_among_with_handlers"] == 0.5
    assert agg["by_rule"]["MCP131"] == {"findings": 3, "repos": 2}
    assert agg["repos_with_any_injection_class_finding"] == 1
    lo, hi = agg["by_category"]["ssrf"]["ci95"]
    assert lo < 1 / 3 < hi


def test_anon_id_and_salt(tmp_path: Path):
    salt = scan_corpus.load_salt(tmp_path / "p")
    assert len(salt) == 32 and scan_corpus.load_salt(tmp_path / "p") == salt
    a = scan_corpus.anon_id(salt, "https://github.com/x/y")
    assert a.startswith("r") and len(a) == 11 and a != scan_corpus.anon_id("other", "https://github.com/x/y")


def test_main_with_fake_scanner(tmp_path: Path, monkeypatch):
    corpus = tmp_path / "corpus"
    (corpus / "x__y").mkdir(parents=True)
    lock = tmp_path / "lock.json"
    lock.write_text(
        json.dumps(
            {
                "repos": [
                    {"url": "https://github.com/x/y", "sha": "abc"},
                    {"url": "https://github.com/x/gone", "sha": "d"},
                ]
            }
        )
    )

    def fake_scan(binary, path):
        rep = {
            "findings": [{"rule_id": "MCP111", "category": "path-traversal"}],
            "stats": {"files": 2, "tool_handlers": 1, "tool_definitions": 1, "bytes": 100, "lines": 9},
        }
        return rep, 0.5

    monkeypatch.setattr(scan_corpus, "scan_repo", fake_scan)
    out = tmp_path / "corpus.json"
    assert (
        scan_corpus.main(
            ["--corpus", str(corpus), "--private", str(tmp_path / "priv"), "--lock", str(lock), "--out", str(out)]
        )
        == 0
    )
    res = json.loads(out.read_text())
    assert res["repositories"] == 1 and res["source_bytes_scanned"] == 100
    assert "x/y" not in out.read_text()
    private = (tmp_path / "priv" / "corpus_findings.jsonl").read_text()
    assert "https://github.com/x/y" in private


def test_prune(tmp_path: Path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "node_modules" / "x").mkdir(parents=True)
    (root / "src" / "a.ts").write_text("x")
    (root / "src" / "logo.png").write_bytes(b"\x89PNG")
    (root / "src" / "data.json").write_text("{}")
    (root / "package.json").write_text("{}")
    (root / "node_modules" / "x" / "i.js").write_text("y")
    kept, size = fetch_corpus.prune(root)
    assert kept == 2 and size == 3
    assert not (root / "node_modules").exists() and not (root / "src" / "logo.png").exists()


class FakeResp:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return json.dumps(self.payload).encode()


def test_registry_repos(monkeypatch):
    pages = [
        {
            "servers": [
                {"server": {"repository": {"url": "https://github.com/A/B.git"}}},
                {"server": {"repository": {"url": "https://gitlab.com/x/y"}}},
                {"server": {}},
            ],
            "metadata": {"nextCursor": "c1"},
        },
        {
            "servers": [
                {"server": {"repository": {"url": "https://github.com/a/b/"}}},
                {"server": {"repository": {"url": "https://github.com/solo"}}},
            ],
            "metadata": {},
        },
    ]
    calls = []

    def fake_urlopen(url, timeout):
        calls.append(url)
        return FakeResp(pages[len(calls) - 1])

    monkeypatch.setattr(fetch_corpus.urllib.request, "urlopen", fake_urlopen)
    assert fetch_corpus.registry_repos() == ["https://github.com/a/b"]
    assert "cursor=c1" in calls[1]


def test_clone_local_repo(tmp_path: Path):
    import subprocess

    src = tmp_path / "upstream"
    src.mkdir()
    (src / "index.ts").write_text("export {}\n")
    (src / "README.md").write_text("# x\n")
    env = {
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.com",
        "PATH": "/usr/bin:/bin:/opt/homebrew/bin",
    }
    for cmd in (["git", "init", "-q"], ["git", "add", "."], ["git", "commit", "-qm", "init"]):
        subprocess.run(cmd, cwd=src, check=True, env=env)
    out = tmp_path / "out"
    out.mkdir()
    res = fetch_corpus.clone(f"file://{src}", out)
    assert res and len(res["sha"]) == 40
    d = out / res["dir"]
    assert (d / "index.ts").exists() and not (d / "README.md").exists() and not (d / ".git").exists()
    again = fetch_corpus.clone(f"file://{src}", out)
    assert again["sha"] == res["sha"]
    assert fetch_corpus.clone("file:///nonexistent/repo", out) is None
