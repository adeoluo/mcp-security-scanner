import json
from pathlib import Path

from precision import sample, score


def finding(rule, line, file="a.ts"):
    return {"rule_id": rule, "file": file, "line": line, "message": "m"}


def rows():
    return [
        {"repo": "r1", "url": "https://github.com/x/one", "findings": [finding("MCP111", i) for i in range(1, 30)]},
        {
            "repo": "r2",
            "url": "https://github.com/x/two",
            "findings": [finding("MCP131", 3, "s.py"), finding("MCP201", 0, "")],
        },
    ]


def test_draw_is_stratified_and_deterministic():
    a = sample.draw(rows(), 1)
    b = sample.draw(rows(), 1)
    assert [x["finding"]["line"] for x in a] == [x["finding"]["line"] for x in b]
    strata = {x["stratum"] for x in a}
    assert strata == {"path-traversal", "secrets", "tool-poisoning"}
    assert sum(x["stratum"] == "path-traversal" for x in a) == 29  # fewer than the cap: all drawn
    assert [x["id"] for x in a][:2] == ["s001", "s002"]


def test_exclusion_and_fallback():
    excl = {("r1", "a.ts", i, "MCP111") for i in range(1, 15)}
    drawn = sample.draw(rows(), 2, excl)
    path = [x for x in drawn if x["stratum"] == "path-traversal"]
    assert all(not x["seen_in_development"] for x in path) and len(path) == 15
    excl_all = {("r2", "s.py", 3, "MCP131")}
    secrets = [x for x in sample.draw(rows(), 2, excl_all) if x["stratum"] == "secrets"]
    assert len(secrets) == 1 and secrets[0]["seen_in_development"]


def test_mask_secrets():
    line = 'TOKEN = "abcdefghijklmnopqrstuvwxyz0123"'
    masked = sample.mask_secrets(line, "MCP132")
    assert "abcdef******[30]" in masked and "ghijkl" not in masked
    assert sample.mask_secrets(line, "MCP111") == line


def test_context(tmp_path: Path):
    repo = tmp_path / "x__one"
    repo.mkdir()
    (repo / "a.ts").write_text("\n".join(f"line {i}" for i in range(1, 20)))
    ctx = sample.context(tmp_path, "x__one", "a.ts", 10, "MCP111", radius=2)
    assert len(ctx) == 5 and ctx[2].startswith("   10>")
    assert sample.context(tmp_path, "x__one", "missing.ts", 1, "MCP111") == []


def test_score_end_to_end(tmp_path: Path):
    private = tmp_path / "private"
    private.mkdir()
    (private / "corpus_findings.jsonl").write_text("\n".join(json.dumps(r) for r in rows()) + "\n")
    corpus = tmp_path / "corpus"
    (corpus / "x__one").mkdir(parents=True)
    (corpus / "x__one" / "a.ts").write_text("x\n" * 40)
    assert sample.main(["--private", str(private), "--corpus", str(corpus), "--name", "final.jsonl"]) == 0
    sheet = [json.loads(line) for line in (private / "final.jsonl").open()]
    with (private / "labels_private.jsonl").open("w") as fh:
        for i, s in enumerate(sheet):
            act = None if s["stratum"] == "tool-poisoning" else i % 2 == 0
            fh.write(
                json.dumps({"id": s["id"], "flow": "tp" if i % 3 else "fp", "actionable": act, "reason": "r"}) + "\n"
            )
    out = tmp_path / "res" / "precision.json"
    export = tmp_path / "labels.jsonl"
    assert score.main(["--private", str(private), "--export", str(export), "--out", str(out)]) == 0
    res = json.loads(out.read_text())
    assert res["labeled"] == len(sheet)
    pt = res["by_type"]["path-traversal"]
    assert 0 < pt["precision"] < 1 and pt["precision_ci95"][0] <= pt["precision"] <= pt["precision_ci95"][1]
    assert "actionable" not in res["by_type"]["tool-poisoning"]
    exported = [json.loads(line) for line in export.open()]
    assert all("url" not in e and "file" not in e for e in exported)
    assert out.with_suffix(".md").read_text().startswith("| Finding type")
    (private / "labels_private.jsonl").write_text("")
    try:
        score.main(["--private", str(private), "--export", str(export), "--out", str(out)])
    except SystemExit as e:
        assert "unlabeled" in str(e)


def test_score_current_filter(tmp_path: Path):
    private = tmp_path / "private"
    private.mkdir()
    sheet = [
        {"id": "s001", "stratum": "ssrf", "repo": "r1", "finding": finding("MCP121", 3), "seen_in_development": False},
        {"id": "s002", "stratum": "ssrf", "repo": "r1", "finding": finding("MCP121", 9), "seen_in_development": False},
    ]
    (private / "final.jsonl").write_text("\n".join(json.dumps(s) for s in sheet) + "\n")
    (private / "labels_private.jsonl").write_text(
        "\n".join(json.dumps({"id": s["id"], "flow": "fp", "actionable": False, "reason": "r"}) for s in sheet) + "\n"
    )
    (private / "now.jsonl").write_text(json.dumps({"repo": "r1", "findings": [finding("MCP121", 3)]}) + "\n")
    out = tmp_path / "p.json"
    args = [
        "--private",
        str(private),
        "--export",
        str(tmp_path / "l.jsonl"),
        "--out",
        str(out),
        "--current",
        "now.jsonl",
    ]
    assert score.main(args) == 0
    res = json.loads(out.read_text())
    assert res["labeled"] == 1 and res["set_aside_no_longer_reported"] == 1
