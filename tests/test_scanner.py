"""Scanner behaviour on fixtures: vulnerable vs safe, discovery,
classification, and config-shape handling."""
import json
import os

from agentscope.scanner import discover_configs, scan_path
from conftest import SAFE_DIR, SAFE_FILE, VULNERABLE_DIR, VULNERABLE_FILE


def _rules(result):
    return {f.rule_id for f in result.all_findings}


def test_vulnerable_fixture_has_findings():
    result = scan_path(VULNERABLE_FILE)
    assert result.errors == []
    assert len(result.servers) == 4
    assert result.all_findings, "vulnerable config must produce findings"
    assert result.overall_score > 0


def test_vulnerable_fixture_covers_all_required_rules():
    result = scan_path(VULNERABLE_FILE)
    rules = _rules(result)
    # wildcard, unpinned, hardcoded secret, dangerous flag, destructive
    assert {"R001", "R002", "R003", "R004", "R005"} <= rules


def test_safe_fixture_has_no_findings():
    result = scan_path(SAFE_FILE)
    assert result.errors == []
    assert len(result.servers) == 2
    assert result.all_findings == []
    assert result.overall_score == 0
    assert result.risk_level == "clean"


def test_directory_auto_discovery():
    files = discover_configs(VULNERABLE_DIR)
    names = sorted(os.path.basename(f) for f in files)
    assert names == ["claude_desktop_config.json", "settings.json"]


def test_directory_scan_includes_settings_permissions():
    result = scan_path(VULNERABLE_DIR)
    names = {s.name for s in result.servers}
    assert "global-permissions" in names
    assert "R001" in _rules(result)


def test_single_file_scan_any_filename(tmp_path):
    cfg = tmp_path / "my-custom-name.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "x": {"command": "bash", "args": [], "env": {}}}}), encoding="utf-8")
    result = scan_path(str(cfg))
    assert len(result.servers) == 1
    assert result.servers[0].name == "x"


def test_vscode_servers_key_shape(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"servers": {
        "y": {"command": "npx", "args": ["pkg"], "env": {}}}}), encoding="utf-8")
    result = scan_path(str(cfg))
    assert [s.name for s in result.servers] == ["y"]
    assert "R002" in _rules(result)


def test_missing_path_reports_error():
    result = scan_path("/nonexistent/agentscope-nope")
    assert result.errors
    assert result.servers == []


def test_empty_directory_reports_error(tmp_path):
    result = scan_path(str(tmp_path))
    assert result.errors
    assert result.servers == []


def test_invalid_json_reports_error(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text("{not json", encoding="utf-8")
    result = scan_path(str(cfg))
    assert result.errors
    assert result.servers == []


# --- capability classification ----------------------------------------------

def test_classification_shell_filesystem_network_database():
    result = scan_path(VULNERABLE_FILE)
    by_name = {s.name: s for s in result.servers}
    assert by_name["shell-runner"].capabilities.shell_execution is True
    fs = by_name["filesystem-broad"].capabilities
    assert fs.filesystem_access is True
    assert "/" in fs.filesystem_paths
    assert by_name["dangerous-db"].capabilities.database_access is True


def test_classification_safe_fixture():
    result = scan_path(SAFE_FILE)
    by_name = {s.name: s for s in result.servers}
    scoped = by_name["filesystem-scoped"].capabilities
    assert scoped.filesystem_paths == ["/home/user/projects/demo"]
    assert scoped.shell_execution is False
    reader = by_name["sqlite-reader"].capabilities
    assert reader.database_access is True
    assert reader.env_secret_names == ["API_KEY"]


def test_env_secret_names_only_names_present():
    result = scan_path(VULNERABLE_FILE)
    by_name = {s.name: s for s in result.servers}
    names = by_name["everything"].capabilities.env_secret_names
    assert "API_KEY" in names and "OPENAI_API_KEY" in names
