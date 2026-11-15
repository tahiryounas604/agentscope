"""Documented risk scoring for AgentScope.

Formula (also documented in README.md):

Severity points:
    critical = 40
    high     = 25
    medium   = 10
    low      = 5
    info     = 0

Per-server score:
    server_score = min(100, sum(points of that server's findings))

Overall score:
    overall_score = max(server_score for each server), or 0 when there
    are no servers / no findings. The riskiest server drives the
    overall score — averaging would hide a single dangerous server
    behind several safe ones.

Risk level from a score (per-server and overall use the same bands):
    0       -> clean
    1-9     -> low
    10-24   -> medium
    25-49   -> high
    50-100  -> critical
"""
from __future__ import annotations

SEVERITY_POINTS: dict[str, int] = {
    "critical": 40,
    "high": 25,
    "medium": 10,
    "low": 5,
    "info": 0,
}

# Ordered low -> high, used for --fail-on threshold comparisons.
SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SEVERITIES = tuple(SEVERITY_ORDER.keys())


def points_for(severity: str) -> int:
    return SEVERITY_POINTS[severity.lower()]


def level_for_score(score: int) -> str:
    if score <= 0:
        return "clean"
    if score < 10:
        return "low"
    if score < 25:
        return "medium"
    if score < 50:
        return "high"
    return "critical"


def server_score(findings) -> int:
    """Sum of finding points for one server, capped at 100."""
    return min(100, sum(f.points for f in findings))


def overall_score(server_scores) -> int:
    """Max per-server score, or 0 for an empty scan."""
    scores = list(server_scores)
    return max(scores) if scores else 0


def meets_threshold(findings, fail_on: str) -> bool:
    """True when any finding's severity is at or above ``fail_on``."""
    if fail_on is None:
        return False
    threshold = SEVERITY_ORDER[fail_on.lower()]
    return any(SEVERITY_ORDER[f.severity.lower()] >= threshold for f in findings)
