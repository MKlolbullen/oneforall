"""Smoke tests: package imports, CLI parses, workspace round-trips, auth gate refuses."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import oneforall
from oneforall import STAGES, GATED_STAGES
from oneforall.cli import build_parser, main as cli_main
from oneforall.runner import normalize_stage_selector
from oneforall.schema import empty_findings
from oneforall.workspace import Workspace


def test_package_imports():
    assert oneforall.__version__
    assert len(STAGES) == 10
    assert "s07_api" in GATED_STAGES and "s09_vuln" in GATED_STAGES


def test_all_stage_modules_importable():
    import importlib
    for sid in STAGES:
        mod = importlib.import_module(f"oneforall.stages.{sid}")
        assert callable(getattr(mod, "run"))


def test_cli_parser_help_does_not_crash(capsys):
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--help"])
    out = capsys.readouterr().out
    assert "oneforall" in out


def test_normalize_stage_selector():
    assert normalize_stage_selector(None) == list(STAGES)
    assert normalize_stage_selector("1,2,3") == ["s01_passive", "s02_active", "s03_techscan"]
    assert normalize_stage_selector("s10_report") == ["s10_report"]
    with pytest.raises(ValueError):
        normalize_stage_selector("99")
    with pytest.raises(ValueError):
        normalize_stage_selector("nope")


def test_workspace_layout_and_findings_roundtrip(tmp_path: Path):
    ws = Workspace.for_target("example.com", base=tmp_path)
    assert ws.findings_path.exists()
    assert (ws.root / "raw" / "s01").is_dir()
    assert (ws.root / "logs").is_dir()

    data = ws.read_findings()
    assert data == empty_findings("example.com")

    ws.merge_subdomain("api.example.com", source="test", live=True, status_code=200)
    ws.merge_subdomain("api.example.com", source="other")  # merges sources, doesn't dup
    ws.merge_url("https://api.example.com/v1/users?id=1", source="test", params=["id"])
    ws.merge_port("api.example.com", 443, service="https", tech=["nginx"])
    ws.append_secret("https://x/y.js", "aws_access_key", "AKIAFAKE", confidence="high")
    ws.append_vuln("test-vuln", "https://api.example.com/", "high", evidence="x", tool="t")
    ws.mark_stage_done("s01_passive")

    data = ws.read_findings()
    sub = next(s for s in data["subdomains"] if s["name"] == "api.example.com")
    assert set(sub["sources"]) == {"test", "other"}
    assert sub["live"] is True and sub["status_code"] == 200
    assert data["urls"][0]["params"] == ["id"]
    assert data["ports"][0]["tech"] == ["nginx"]
    assert data["secrets"][0]["confidence"] == "high"
    assert data["vulns"][0]["severity"] == "high"
    assert "s01_passive" in data["stages_completed"]


def test_auth_gate_refuses_without_scope(tmp_path: Path):
    with pytest.raises(SystemExit) as exc_info:
        cli_main([
            "s09_vuln", "-d", "example.com",
            "--workspace", str(tmp_path),
            "--i-have-authorization",
        ])
    assert exc_info.value.code == 2


def test_auth_gate_refuses_without_flag(tmp_path: Path):
    # init scope first so we're testing the flag, not scope absence
    cli_main(["init-scope", "-d", "example.com", "--workspace", str(tmp_path)])
    with pytest.raises(SystemExit) as exc_info:
        cli_main([
            "s09_vuln", "-d", "example.com",
            "--workspace", str(tmp_path),
        ])
    assert exc_info.value.code == 2


def test_init_scope_creates_yaml(tmp_path: Path):
    rc = cli_main(["init-scope", "-d", "example.com", "--workspace", str(tmp_path)])
    assert rc == 0
    scope_path = tmp_path / "example.com" / "scope.yaml"
    assert scope_path.exists()
    assert "example.com" in scope_path.read_text()


def test_s10_report_renders_from_empty_findings(tmp_path: Path):
    """Stage 10 should produce report.md and report.html even from an empty findings.json."""
    ws = Workspace.for_target("example.com", base=tmp_path)
    from oneforall.stages import s10_report
    s10_report.run(ws)
    assert (ws.root / "report" / "report.md").exists()
    assert (ws.root / "report" / "report.html").exists()
    md = (ws.root / "report" / "report.md").read_text()
    assert "example.com" in md
