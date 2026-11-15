"""Report writers: report.md + report.json. No secret values, ever."""
from __future__ import annotations

import json
import os
from collections import Counter

from .models import ScanResult
from .scoring import SEVERITY_ORDER


def result_to_dict(result: ScanResult) -> dict:
    findings = result.all_findings
    counts = Counter(f.severity for f in findings)
    return {
        "tool": "agentscope",
        "version": "0.1.0",
        "scanned_files": list(result.scanned_files),
        "errors": list(result.errors),
        "overall_score": result.overall_score,
        "risk_level": result.risk_level,
        "summary": {
            "servers": len(result.servers),
            "findings": len(findings),
            "by_severity": {sev: counts.get(sev, 0)
                            for sev in ("critical", "high", "medium", "low", "info")},
        },
        "servers": [s.to_dict() for s in result.servers],
        "findings": [f.to_dict() for f in
                     sorted(findings,
                            key=lambda f: (-SEVERITY_ORDER[f.severity], f.server_name))],
    }


def render_markdown(result: ScanResult) -> str:
    data = result_to_dict(result)
    lines = []
    lines.append("# AgentScope Report")
    lines.append("")
    lines.append(f"**Overall risk score:** {data['overall_score']}/100 "
                 f"({data['risk_level']})")
    lines.append(f"**Servers scanned:** {data['summary']['servers']}  |  "
                 f"**Findings:** {data['summary']['findings']}")
    sev = data["summary"]["by_severity"]
    lines.append(f"**By severity:** critical {sev['critical']}, "
                 f"high {sev['high']}, medium {sev['medium']}, "
                 f"low {sev['low']}, info {sev['info']}")
    lines.append("")
    lines.append("## Scanned files")
    lines.append("")
    if data["scanned_files"]:
        for f in data["scanned_files"]:
            lines.append(f"- `{f}`")
    else:
        lines.append("- (none)")
    lines.append("")
    if data["errors"]:
        lines.append("## Errors")
        lines.append("")
        for e in data["errors"]:
            lines.append(f"- {e}")
        lines.append("")
    lines.append("## Servers")
    lines.append("")
    if not result.servers:
        lines.append("No MCP servers found.")
        lines.append("")
    for s in result.servers:
        caps = s.capabilities
        lines.append(f"### {s.name} — score {s.score}/100 ({s.risk_level})")
        lines.append("")
        lines.append(f"- Source: `{s.source_file}`")
        if s.command:
            lines.append(f"- Command: `{s.command}`")
        if s.args_masked:
            lines.append(f"- Args: `{' '.join(s.args_masked)}`")
        if s.url:
            lines.append(f"- URL: `{s.url}`")
        lines.append(f"- Shell execution: {'yes' if caps.shell_execution else 'no'}")
        lines.append(f"- Filesystem access: "
                     f"{', '.join(caps.filesystem_paths) if caps.filesystem_paths else 'no'}")
        lines.append(f"- Network access: {'yes' if caps.network_access else 'no'}")
        lines.append(f"- Database access: {'yes' if caps.database_access else 'no'}")
        if caps.env_secret_names:
            lines.append(f"- Env secrets (names only, values masked): "
                         f"{', '.join(caps.env_secret_names)} = ***")
        elif s.env_names:
            lines.append(f"- Env vars: {', '.join(s.env_names)}")
        lines.append("")
        if s.findings:
            lines.append("| Severity | Points | Rule | Finding | Detail |")
            lines.append("|---|---:|---|---|---|")
            for f in s.findings:
                detail = f.detail.replace("|", "\\|")
                lines.append(f"| {f.severity} | {f.points} | {f.rule_id} | "
                             f"{f.title} | {detail} |")
            lines.append("")
        else:
            lines.append("No findings for this server.")
            lines.append("")
    lines.append("## Scoring")
    lines.append("")
    lines.append("Severity points: critical 40, high 25, medium 10, low 5, "
                 "info 0. Per-server score = sum of its finding points, "
                 "capped at 100. Overall score = highest per-server score. "
                 "See README.md for the full formula.")
    lines.append("")
    return "\n".join(lines)


def write_reports(result: ScanResult, out_dir: str) -> tuple[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    md_path = os.path.join(out_dir, "report.md")
    json_path = os.path.join(out_dir, "report.json")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(result))
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(result_to_dict(result), fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return md_path, json_path
