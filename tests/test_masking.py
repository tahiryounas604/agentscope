"""Masking: a secret value must NEVER appear in any output.

The vulnerable fixture plants FAKE_SECRET as an env value. Every
output surface — report.md, report.json, the result dict, finding
details, and CLI stdout — is asserted clean. Other planted secret
values from the fixture are checked the same way.
"""
import json

from agentscope.cli import main
from agentscope.report import render_markdown, result_to_dict, write_reports
from agentscope.scanner import scan_path
from conftest import FAKE_SECRET, VULNERABLE_FILE

OTHER_PLANTED_SECRETS = [
    "sk-fake1234567890abcdefghijklmnop",
    "FAKESECRETDB9999",
]


def _assert_clean(text: str):
    assert FAKE_SECRET not in text
    for secret in OTHER_PLANTED_SECRETS:
        assert secret not in text


def test_secret_names_reported_but_not_values():
    result = scan_path(VULNERABLE_FILE)
    by_name = {s.name: s for s in result.servers}
    assert "API_KEY" in by_name["everything"].capabilities.env_secret_names
    # the stored env representation is masked
    assert by_name["everything"].to_dict()["env"]["API_KEY"] == "***"


def test_result_dict_is_clean():
    result = scan_path(VULNERABLE_FILE)
    _assert_clean(json.dumps(result_to_dict(result)))


def test_markdown_report_is_clean():
    result = scan_path(VULNERABLE_FILE)
    _assert_clean(render_markdown(result))


def test_written_report_files_are_clean(tmp_path):
    result = scan_path(VULNERABLE_FILE)
    md_path, json_path = write_reports(result, str(tmp_path))
    _assert_clean(open(md_path, encoding="utf-8").read())
    _assert_clean(open(json_path, encoding="utf-8").read())


def test_finding_details_are_clean():
    result = scan_path(VULNERABLE_FILE)
    for f in result.all_findings:
        _assert_clean(f.detail)
        _assert_clean(f.title)


def test_cli_stdout_is_clean(tmp_path, capsys):
    out_dir = tmp_path / "out"
    code = main(["scan", VULNERABLE_FILE, "--out", str(out_dir)])
    captured = capsys.readouterr()
    _assert_clean(captured.out)
    _assert_clean(captured.err)
    assert code == 1  # vulnerable fixture is above the default high threshold
    _assert_clean((out_dir / "report.md").read_text(encoding="utf-8"))
    _assert_clean((out_dir / "report.json").read_text(encoding="utf-8"))
