"""
UI rendering for the LLM security plan — kept decoupled from app.py so the
plan can be displayed from any Streamlit tab or from a standalone view.

The LLM analyzer (modules/llm/analyzer.py) produces a SecurityPlan dataclass.
This module renders any `SecurityPlan | dict` into a readable Streamlit panel
without making assumptions about which tab is calling it.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

import streamlit as st

SecurityPlanLike = Union[Dict[str, Any], Any]   # Any = SecurityPlan to avoid hard import at module load


PRIORITY_ORDER = ("critical", "high", "medium", "low", "info")
PRIORITY_ICON = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


def _as_dict(plan: SecurityPlanLike) -> Dict[str, Any]:
    """Accept either a SecurityPlan dataclass or a dict."""
    if isinstance(plan, dict):
        return plan
    if hasattr(plan, "to_dict"):
        return plan.to_dict()
    return {}


def _sorted_strategies(strategies: List[Dict]) -> List[Dict]:
    def rank(s: Dict) -> int:
        try:
            return PRIORITY_ORDER.index((s.get("priority") or "medium").lower())
        except ValueError:
            return len(PRIORITY_ORDER)
    return sorted(strategies, key=rank)


def render_plan(plan: SecurityPlanLike, *, key_prefix: str = "llm_plan") -> None:
    """Render a SecurityPlan into the current Streamlit container."""
    data = _as_dict(plan)
    if not data:
        st.info("No LLM plan available.")
        return

    metadata = data.get("metadata") or {}
    model = metadata.get("model", "unknown")
    cached = bool(metadata.get("cached"))
    latency = metadata.get("latency_ms")

    header_bits = [f"Model: `{model}`"]
    if cached:
        header_bits.append("_(cached)_")
    if latency:
        header_bits.append(f"latency: {latency:.0f} ms")
    st.caption(" · ".join(header_bits))

    _render_domain(data.get("domain_analysis") or {})
    _render_strategies(data.get("strategies") or [], key_prefix=key_prefix)
    _render_prioritized_endpoints(data.get("prioritized_endpoints") or [])
    _render_regex_patterns(data.get("custom_regex_patterns") or [])
    _render_business_flows(data.get("business_logic_flows") or [])

    if "error" in metadata:
        st.error(f"LLM plan partial: {metadata['error']}")


def _render_domain(domain: Dict[str, Any]) -> None:
    if not domain:
        return
    inferred = domain.get("inferred_domain", "unknown")
    confidence = domain.get("confidence")
    rationale = domain.get("rationale") or domain.get("description") or ""
    cols = st.columns([2, 1])
    with cols[0]:
        st.markdown(f"**Inferred domain:** `{inferred}`")
        if rationale:
            st.caption(rationale)
    with cols[1]:
        if confidence is not None:
            st.metric("Confidence", f"{float(confidence):.0%}")


def _render_strategies(strategies: List[Dict], *, key_prefix: str) -> None:
    if not strategies:
        return
    st.markdown("### Attack strategies")
    ordered = _sorted_strategies(strategies)
    for i, s in enumerate(ordered):
        prio = (s.get("priority") or "medium").lower()
        icon = PRIORITY_ICON.get(prio, "⚪")
        title = f"{icon} **{s.get('attack_type', 'unknown')}** · priority `{prio}`"
        with st.expander(title, expanded=(prio in {"critical", "high"})):
            if s.get("rationale"):
                st.markdown(f"**Why:** {s['rationale']}")
            targets = s.get("targets") or []
            if targets:
                st.markdown(f"**Targets ({len(targets)}):**")
                st.dataframe(targets[:20], use_container_width=True)
            payloads = s.get("payloads") or []
            if payloads:
                st.markdown(f"**Payloads ({len(payloads)}):**")
                st.code("\n".join(_payload_lines(payloads)[:30]), language=None)
            plan = s.get("test_plan") or []
            if plan:
                st.markdown("**Test plan:**")
                for step in plan:
                    st.markdown(f"- {step}")


def _payload_lines(payloads: List[Any]) -> List[str]:
    lines = []
    for p in payloads:
        if isinstance(p, str):
            lines.append(p)
        elif isinstance(p, dict):
            lines.append(p.get("value") or p.get("payload") or str(p))
        else:
            lines.append(str(p))
    return lines


def _render_prioritized_endpoints(endpoints: List[Dict]) -> None:
    if not endpoints:
        return
    st.markdown("### Prioritized endpoints")
    st.caption("Endpoints the LLM flagged as high-value attack surface")
    st.dataframe(endpoints[:30], use_container_width=True)


def _render_regex_patterns(patterns: List[Dict]) -> None:
    if not patterns:
        return
    with st.expander(f"Custom regex patterns ({len(patterns)})"):
        for p in patterns:
            label = p.get("label") or p.get("name") or "pattern"
            regex = p.get("pattern") or p.get("regex") or ""
            purpose = p.get("purpose") or p.get("description") or ""
            st.markdown(f"**{label}** — {purpose}")
            st.code(regex, language="regex")


def _render_business_flows(flows: List[Dict]) -> None:
    if not flows:
        return
    with st.expander(f"Business logic flows ({len(flows)})"):
        for f in flows:
            name = f.get("name") or f.get("flow") or "flow"
            steps = f.get("steps") or f.get("sequence") or []
            risks = f.get("risks") or f.get("vulnerabilities") or []
            st.markdown(f"**{name}**")
            if steps:
                st.markdown("_Steps:_")
                for step in steps:
                    st.markdown(f"1. {step}")
            if risks:
                st.markdown("_Potential risks:_")
                for r in risks:
                    st.markdown(f"- {r}")


def summarize(plan: SecurityPlanLike) -> Dict[str, int]:
    """Counts for the sidebar/header — no Streamlit dependency."""
    data = _as_dict(plan)
    return {
        "strategies": len(data.get("strategies") or []),
        "prioritized_endpoints": len(data.get("prioritized_endpoints") or []),
        "regex_patterns": len(data.get("custom_regex_patterns") or []),
        "business_flows": len(data.get("business_logic_flows") or []),
    }
