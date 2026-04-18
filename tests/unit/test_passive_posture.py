"""Tests for the posture score introduced in PassiveAnalysisOrchestrator."""
from unittest.mock import MagicMock

from modules.passive_analysis import PassiveAnalysisOrchestrator, SecurityIssue


def _issue(severity, category="headers", title="t"):
    return SecurityIssue(
        severity=severity,
        category=category,
        title=title,
        description="",
        evidence={},
        remediation="",
    )


class TestPostureScore:
    def test_score_10_when_no_issues(self):
        o = PassiveAnalysisOrchestrator({"log": {"entries": []}})
        o.results = {"headers": []}
        summary = o.generate_summary()
        assert summary["posture"]["score"] == 10.0
        assert summary["posture"]["grade"] == "A"

    def test_one_critical_drops_score(self):
        o = PassiveAnalysisOrchestrator({"log": {"entries": []}})
        o.results = {"headers": [_issue("CRITICAL")]}
        summary = o.generate_summary()
        assert summary["posture"]["score"] == 8.0
        assert summary["posture"]["grade"] == "B"

    def test_many_highs_capped(self):
        o = PassiveAnalysisOrchestrator({"log": {"entries": []}})
        o.results = {"headers": [_issue("HIGH") for _ in range(10)]}
        summary = o.generate_summary()
        # High penalty capped at -4
        assert summary["posture"]["score"] == 6.0

    def test_critical_penalty_capped(self):
        o = PassiveAnalysisOrchestrator({"log": {"entries": []}})
        o.results = {"headers": [_issue("CRITICAL") for _ in range(10)]}
        summary = o.generate_summary()
        # Critical penalty capped at -6
        assert summary["posture"]["score"] == 4.0

    def test_combined_penalties(self):
        o = PassiveAnalysisOrchestrator({"log": {"entries": []}})
        o.results = {
            "headers": [_issue("HIGH"), _issue("MEDIUM")],
            "data_leaks": [_issue("LOW"), _issue("LOW")],
        }
        summary = o.generate_summary()
        # 10 - 1 (HIGH) - 0.5 (MEDIUM) - 0.2 (2 x LOW) = 8.3
        assert summary["posture"]["score"] == 8.3
        assert summary["posture"]["grade"] == "B"

    def test_grade_f(self):
        o = PassiveAnalysisOrchestrator({"log": {"entries": []}})
        o.results = {"headers": [_issue("CRITICAL") for _ in range(5)]}
        summary = o.generate_summary()
        assert summary["posture"]["grade"] in ("D", "F")
        assert summary["posture"]["score"] <= 6.0

    def test_grouped_returns_by_category(self):
        o = PassiveAnalysisOrchestrator({"log": {"entries": []}})
        o.results = {
            "headers": [
                _issue("HIGH", category="csp", title="CSP missing"),
                _issue("HIGH", category="csp", title="CSP missing"),
                _issue("MEDIUM", category="cookies", title="No HttpOnly"),
            ]
        }
        summary = o.generate_summary()
        grouped = summary["grouped"]
        assert grouped["csp"]["count"] == 2
        assert grouped["cookies"]["count"] == 1

    def test_rationale_contains_counts(self):
        o = PassiveAnalysisOrchestrator({"log": {"entries": []}})
        o.results = {"headers": [_issue("HIGH"), _issue("LOW")]}
        summary = o.generate_summary()
        assert "1 high" in summary["posture"]["rationale"].lower()
