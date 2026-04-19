"""Tests for ui_llm_plan — structural only (no real Streamlit render)."""
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def sample_plan():
    return {
        "har_hash": "abc123",
        "domain_analysis": {
            "inferred_domain": "e-commerce",
            "confidence": 0.9,
            "rationale": "Cart, checkout, and payment endpoints detected",
        },
        "strategies": [
            {
                "attack_type": "mass_assignment",
                "priority": "high",
                "targets": [{"url": "/api/users/profile", "method": "PUT"}],
                "payloads": ["admin=true", "role=admin"],
                "rationale": "Profile update endpoint accepts all body fields",
                "test_plan": ["send PUT with admin=true", "verify role change"],
            },
            {
                "attack_type": "idor",
                "priority": "critical",
                "targets": [],
                "payloads": [],
                "rationale": "Sequential IDs observed",
                "test_plan": [],
            },
        ],
        "prioritized_endpoints": [
            {"url": "/api/users/42", "method": "GET", "risk": "high"},
        ],
        "custom_regex_patterns": [
            {"label": "user id", "pattern": r"user_\d+", "purpose": "IDOR fuzzing"},
        ],
        "business_logic_flows": [
            {"name": "checkout", "steps": ["add to cart", "apply coupon"], "risks": ["race on coupon"]},
        ],
        "metadata": {"model": "claude-sonnet-4", "latency_ms": 1234, "cached": False},
    }


class TestSummarize:
    def test_summarize_counts(self, sample_plan):
        from modules.ui_llm_plan import summarize
        s = summarize(sample_plan)
        assert s["strategies"] == 2
        assert s["prioritized_endpoints"] == 1
        assert s["regex_patterns"] == 1
        assert s["business_flows"] == 1

    def test_summarize_empty_plan(self):
        from modules.ui_llm_plan import summarize
        assert summarize({}) == {
            "strategies": 0,
            "prioritized_endpoints": 0,
            "regex_patterns": 0,
            "business_flows": 0,
        }

    def test_summarize_dataclass_like(self):
        from modules.ui_llm_plan import summarize

        class FakePlan:
            def to_dict(self):
                return {"strategies": [1, 2, 3], "prioritized_endpoints": [], "custom_regex_patterns": [], "business_logic_flows": []}

        assert summarize(FakePlan())["strategies"] == 3


class TestRenderPlan:
    def test_render_does_not_raise(self, sample_plan):
        from modules.ui_llm_plan import render_plan
        with patch("modules.ui_llm_plan.st") as mock_st:
            mock_st.columns.return_value = [MagicMock(), MagicMock()]
            mock_st.expander.return_value.__enter__ = MagicMock(return_value=mock_st)
            mock_st.expander.return_value.__exit__ = MagicMock(return_value=None)
            render_plan(sample_plan)
            assert mock_st.markdown.called or mock_st.caption.called

    def test_render_empty_plan_shows_info(self):
        from modules.ui_llm_plan import render_plan
        with patch("modules.ui_llm_plan.st") as mock_st:
            render_plan({})
            mock_st.info.assert_called_once()

    def test_sorted_strategies_critical_first(self):
        from modules.ui_llm_plan import _sorted_strategies
        strategies = [
            {"attack_type": "x", "priority": "low"},
            {"attack_type": "y", "priority": "critical"},
            {"attack_type": "z", "priority": "medium"},
        ]
        sorted_list = _sorted_strategies(strategies)
        assert sorted_list[0]["priority"] == "critical"
        assert sorted_list[-1]["priority"] == "low"
