"""CLI end-to-end tests on the fixtures."""
import json
import os

from agentscope.cli import main
from conftest import SAFE_DIR, SAFE_FILE, VULNERABLE_DIR, VULNERABLE_FILE


def test_cli_scan_vulnerable_file(tmp_path):
    out = tmp_path / "out"
    code = main(["scan", VULNERABLE_FILE, "--out", str(out)])
    assert code == 1  # default --fail-on high, vulnerable has high+ findings
    assert (out / "report.md").is_file()
    assert (out / "report.json").is_file()
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert data["summary"]["servers"] == 4
    assert data["summary"]["findings"] > 0
    assert data["overall_score"] > 0
    md = (out / "report.md").read_text(encoding="utf-8")
    assert "AgentScope Report" in md


def test_cli_scan_safe_file_exits_zero(tmp_path):
    out = tmp_path / "out"
    code = main(["scan", SAFE_FILE, "--out", str(out)])
    assert code == 0
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert data["summary"]["findings"] == 0
    assert data["overall_score"] == 0
    assert data["risk_level"] == "clean"


def test_cli_scan_directory(tmp_path):
    out = tmp_path / "out"
    code = main(["scan", VULNERABLE_DIR, "--out", str(out)])
    assert code == 1
    data = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert len(data["scanned_files"]) == 2


def test_cli_fail_on_threshold_is_configurable(tmp_path):
    # Safe file stays 0 at any threshold.
    assert main(["scan", SAFE_FILE, "--out", str(tmp_path / "a"),
                 "--fail-on", "low"]) == 0
    # Vulnerable file has a critical finding, so even --fail-on critical trips.
    assert main(["scan", VULNERABLE_FILE, "--out", str(tmp_path / "b"),
                 "--fail-on", "critical"]) == 1


def test_cli_fail_on_medium_on_safe_dir(tmp_path):
    assert main(["scan", SAFE_DIR, "--out", str(tmp_path / "out"),
                 "--fail-on", "medium"]) == 0


def test_cli_missing_path_exits_2(tmp_path):
    assert main(["scan", "/nonexistent/agentscope-nope",
                 "--out", str(tmp_path)]) == 2


def test_cli_stdout_summary(tmp_path, capsys):
    main(["scan", SAFE_FILE, "--out", str(tmp_path / "out")])
    out = capsys.readouterr().out
    assert "overall risk score: 0/100 (clean)" in out
    assert "report.md" in out and "report.json" in out
