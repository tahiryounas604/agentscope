"""Scoring math unit tests — every number here is from scoring.py's
documented formula (README.md / SCORING section)."""
from agentscope.models import Finding
from agentscope.scoring import (
    SEVERITY_POINTS,
    level_for_score,
    meets_threshold,
    overall_score,
    points_for,
    server_score,
)


def _f(severity):
    return Finding(rule_id="RX", title="t", severity=severity,
                   points=points_for(severity), server_name="s", detail="d")


def test_severity_points_documented_values():
    assert SEVERITY_POINTS == {
        "critical": 40, "high": 25, "medium": 10, "low": 5, "info": 0,
    }


def test_points_for():
    assert points_for("critical") == 40
    assert points_for("HIGH") == 25
    assert points_for("medium") == 10
    assert points_for("low") == 5
    assert points_for("info") == 0


def test_server_score_sums_points():
    assert server_score([_f("high"), _f("medium")]) == 35
    assert server_score([_f("critical"), _f("high")]) == 65
    assert server_score([]) == 0


def test_server_score_capped_at_100():
    assert server_score([_f("critical")] * 5) == 100


def test_overall_score_is_max_server_score():
    assert overall_score([10, 65, 25]) == 65
    assert overall_score([0, 0]) == 0
    assert overall_score([]) == 0


def test_level_bands():
    assert level_for_score(0) == "clean"
    assert level_for_score(1) == "low"
    assert level_for_score(9) == "low"
    assert level_for_score(10) == "medium"
    assert level_for_score(24) == "medium"
    assert level_for_score(25) == "high"
    assert level_for_score(49) == "high"
    assert level_for_score(50) == "critical"
    assert level_for_score(100) == "critical"


def test_meets_threshold():
    findings = [_f("medium"), _f("high")]
    assert meets_threshold(findings, "high") is True
    assert meets_threshold(findings, "critical") is False
    assert meets_threshold(findings, "medium") is True
    assert meets_threshold(findings, "low") is True
    assert meets_threshold([], "low") is False
    assert meets_threshold([_f("critical")], "critical") is True
