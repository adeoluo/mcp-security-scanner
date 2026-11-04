import json
from pathlib import Path

import compare_planted as cp


def test_semgrep_category_mapping():
    assert (
        cp.semgrep_category("javascript.lang.security.detect-child-process.detect-child-process") == "command-injection"
    )
    assert cp.semgrep_category("python.lang.security.audit.eval-detected.eval-detected") == "command-injection"
    assert cp.semgrep_category("generic.secrets.gitleaks.github-pat.github-pat") == "secrets"
    assert cp.semgrep_category("python.lang.security.audit.dynamic-urllib-use-detected.x") == "ssrf"
    assert (
        cp.semgrep_category("javascript.lang.security.audit.path-traversal.path-join-resolve-traversal")
        == "path-traversal"
    )
    assert cp.semgrep_category("python.lang.security.audit.insecure-transport.requests.request-with-http") is None
    assert cp.semgrep_category("javascript.express.security.cors-misconfiguration") is None


def test_case_of(tmp_path: Path):
    root = tmp_path / "source"
    (root / "c0001").mkdir(parents=True)
    f = root / "c0001" / "server.ts"
    f.write_text("x")
    assert cp.case_of(str(f), root) == "c0001"
    assert cp.case_of(str(root / "truth.json"), root) is None
    assert cp.case_of("/elsewhere/x.ts", root) is None


def test_score_and_markdown():
    cases = [
        {"id": "a", "lang": "py", "category": "ssrf", "tier": "standard", "vulnerable": True},
        {"id": "b", "lang": "py", "category": "ssrf", "tier": "standard", "vulnerable": False},
        {"id": "c", "lang": "ts", "category": "ssrf", "tier": "standard", "vulnerable": True},
    ]
    groups = cp.score(cases, {"a": {"ssrf"}, "b": {"ssrf"}})
    assert groups["overall"].tp == 1 and groups["overall"].fp == 1 and groups["overall"].fn == 1
    only_py = cp.score(cases, {}, {"py"})
    assert only_py["overall"].fn == 1 and "ssrf|ts|standard" not in only_py
    results = {"tools": {"x": {"groups": {k: v.as_dict() for k, v in groups.items()}}}}
    md = cp.markdown(results)
    assert "| ssrf | py | standard | x | 1.000 | 1.000 | 1 / 0 / 1 / 0 |" in md
    json.dumps(results)


class FakeProc:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


def test_runners_with_fake_tools(tmp_path: Path, monkeypatch):
    src = tmp_path / "source"
    for cid in ("c0001", "c0002"):
        (src / cid).mkdir(parents=True)
        (src / cid / "server.py").write_text("x = 1\n")
    cases = [
        {"id": "c0001", "lang": "py", "category": "command-injection", "tier": "standard", "vulnerable": True},
        {"id": "c0002", "lang": "py", "category": "secrets", "tier": "standard", "vulnerable": False},
    ]
    (src / "truth.json").write_text(json.dumps({"seed": 1, "cases": cases}))

    def fake_run(cmd):
        if cmd[0] == "mcpscan" and cmd[1] == "scan":
            rule = "MCP101" if cmd[2].endswith("c0001") else "MCP201"
            return 0.01, FakeProc(json.dumps({"findings": [{"rule_id": rule}]}))
        if "semgrep" in " ".join(cmd):
            out = Path(cmd[cmd.index("-o") + 1])
            out.write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "check_id": "python.lang.security.audit.subprocess-shell-true",
                                "path": str(src / "c0001" / "server.py"),
                            },
                            {
                                "check_id": "generic.secrets.gitleaks.generic-api-key",
                                "path": str(src / "c0002" / "server.py"),
                            },
                            {"check_id": "x.cors", "path": str(src / "c0002" / "server.py")},
                        ]
                    }
                )
            )
            return 1.0, FakeProc()
        if "bandit" in " ".join(cmd):
            out = Path(cmd[cmd.index("-o") + 1])
            out.write_text(
                json.dumps(
                    {
                        "results": [
                            {"test_id": "B602", "filename": str(src / "c0001" / "server.py")},
                            {"test_id": "B404", "filename": str(src / "c0002" / "server.py")},
                        ]
                    }
                )
            )
            return 0.5, FakeProc()
        raise AssertionError(cmd)

    monkeypatch.setattr(cp, "run_timed", fake_run)
    det, secs = cp.mcpscan_detections("mcpscan", src, cases)
    assert det == {"c0001": {"command-injection"}, "c0002": set()} and secs > 0
    det, secs, rules = cp.semgrep_detections(src, tmp_path)
    assert det == {"c0001": {"command-injection"}, "c0002": {"secrets"}} and len(rules) == 2
    det, secs = cp.bandit_detections(src, tmp_path)
    assert det == {"c0001": {"command-injection"}}

    def fake_subprocess_run(cmd, capture_output, text, check):
        (tmp_path / "work" / "source").mkdir(parents=True, exist_ok=True)
        (tmp_path / "work" / "source" / "truth.json").write_text(json.dumps({"seed": 1, "cases": cases}))
        return FakeProc(json.dumps({"seed": 1}))

    def fake_run2(cmd):
        if cmd[1] == "scan":
            return 0.01, FakeProc(json.dumps({"findings": []}))
        return fake_run(cmd)

    monkeypatch.setattr(cp.subprocess, "run", fake_subprocess_run)
    monkeypatch.setattr(cp, "run_timed", fake_run2)
    out = tmp_path / "res" / "planted.json"
    assert (
        cp.main(["--mcpscan", "mcpscan", "--work", str(tmp_path / "work"), "--out", str(out), "--skip-external"]) == 0
    )
    res = json.loads(out.read_text())
    assert res["cases"] == 2 and res["tools"]["mcpscan"]["groups"]["overall"]["fn"] == 1
    assert out.with_suffix(".md").exists()


def test_semgrep_failure_raises(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(cp, "run_timed", lambda cmd: (0.0, FakeProc(stderr="boom", returncode=2)))
    import pytest

    with pytest.raises(RuntimeError):
        cp.semgrep_detections(tmp_path, tmp_path)
    with pytest.raises(RuntimeError):
        cp.bandit_detections(tmp_path, tmp_path)
    with pytest.raises(RuntimeError):
        cp.mcpscan_detections("x", tmp_path, [{"id": "a"}])


def test_merge_rule_packs():
    a = "rules:\n- id: one\n  pattern: a\n- id: two\n  pattern: b\n"
    b = "rules:\n- id: two\n  pattern: b2\n- id: three\n  pattern: c\n"
    merged, n = cp.merge_rule_packs([a, b])
    assert n == 3
    assert merged.count("- id: two") == 1 and "pattern: b2" not in merged and merged.startswith("rules:\n- id: one")
