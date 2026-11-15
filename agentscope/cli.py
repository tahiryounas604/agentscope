"""Command-line interface.

  agentscope scan <path> [--out DIR] [--fail-on LEVEL]

``<path>`` may be a single config file (any filename) or a directory,
in which case known MCP config filenames are auto-discovered.
Exit code: 0 = no finding at/above the --fail-on threshold,
1 = threshold met, 2 = usage / IO error.
"""
from __future__ import annotations

import argparse
import sys

from .report import write_reports
from .scanner import scan_path
from .scoring import SEVERITIES, meets_threshold


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentscope",
        description="AI agent / MCP permission auditor (self-hosted, offline)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser(
        "scan", help="Scan an MCP config file or a directory of configs")
    p_scan.add_argument("path", help="Config file or directory to scan")
    p_scan.add_argument("--out", default="agentscope-report",
                        help="Output directory for report.md/report.json "
                             "(default: agentscope-report)")
    p_scan.add_argument("--fail-on", default="high", choices=list(SEVERITIES),
                        help="Exit 1 when any finding is at or above this "
                             "severity (default: high)")
    return parser


def cmd_scan(args) -> int:
    result = scan_path(args.path)
    if result.errors and not result.scanned_files:
        for e in result.errors:
            print(f"error: {e}", file=sys.stderr)
        return 2
    md_path, json_path = write_reports(result, args.out)
    findings = result.all_findings
    print(f"scanned {len(result.scanned_files)} file(s), "
          f"{len(result.servers)} server(s)")
    print(f"overall risk score: {result.overall_score}/100 ({result.risk_level})")
    print(f"findings: {len(findings)}")
    for s in result.servers:
        print(f"  {s.score:>3}  {s.risk_level:<8}  {s.name} "
              f"({len(s.findings)} finding(s))")
        for f in s.findings:
            print(f"       [{f.severity}] {f.rule_id} {f.title} — {f.detail}")
    for e in result.errors:
        print(f"warning: {e}", file=sys.stderr)
    print(f"wrote {md_path}")
    print(f"wrote {json_path}")
    if meets_threshold(findings, args.fail_on):
        print(f"FAIL: findings at or above '{args.fail_on}' severity")
        return 1
    print(f"OK: no findings at or above '{args.fail_on}' severity")
    return 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
