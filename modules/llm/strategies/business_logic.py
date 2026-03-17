"""
Business Logic Strategy - Multi-step flow vulnerability detection.
"""
from typing import Dict, List

from .base import BaseAttackStrategy


class BusinessLogicStrategy(BaseAttackStrategy):
    """Business logic strategy for multi-step flow vulnerabilities."""

    ATTACK_TYPE = "business_logic"

    def get_enriched_payloads(self) -> List[Dict]:
        """Get business logic vulnerabilities to test."""
        if not self.strategy:
            return self._get_from_plan_flows()

        vulns = []
        for p in self.strategy.payloads:
            if isinstance(p, dict):
                vulns.append({
                    'type': p.get('type', 'unknown'),
                    'flow': p.get('flow', []),
                    'attack': p.get('attack', ''),
                    'test_payload': p.get('test_payload', {}),
                    'severity': p.get('severity', 'medium')
                })
        return vulns

    def _get_from_plan_flows(self) -> List[Dict]:
        """Fallback to plan-level business_logic_flows."""
        return self.plan.business_logic_flows if self.plan else []

    def get_targets(self) -> List[Dict]:
        """Get flows as targets."""
        if not self.strategy:
            return []
        return self.strategy.targets

    def get_state_skip_attacks(self) -> List[Dict]:
        """Get state skipping attacks."""
        return [
            v for v in self.get_enriched_payloads()
            if v.get('type') == 'state_skip'
        ]

    def get_manipulation_attacks(self) -> List[Dict]:
        """Get value manipulation attacks (negative, overflow)."""
        return [
            v for v in self.get_enriched_payloads()
            if v.get('type') in ('negative_amount', 'overflow', 'manipulation')
        ]

    def get_bypass_attacks(self) -> List[Dict]:
        """Get workflow bypass attacks."""
        return [
            v for v in self.get_enriched_payloads()
            if v.get('type') == 'bypass'
        ]

    def get_critical_flows(self) -> List[Dict]:
        """Get only critical severity flows."""
        return [
            v for v in self.get_enriched_payloads()
            if v.get('severity') == 'critical'
        ]
