"""
Mass Assignment Strategy - LLM-enriched privilege escalation payloads.
"""
from typing import Dict, List, Any

from .base import BaseAttackStrategy


class MassAssignmentStrategy(BaseAttackStrategy):
    """Mass Assignment strategy using LLM-generated domain-specific payloads."""

    ATTACK_TYPE = "mass_assignment"

    def get_enriched_payloads(self) -> List[Dict]:
        """Get domain-specific privilege escalation payloads."""
        if not self.strategy:
            return []

        payloads = []
        for p in self.strategy.payloads:
            if isinstance(p, dict) and 'field' in p:
                payloads.append({
                    'field': p['field'],
                    'value': p.get('value'),
                    'reason': p.get('reason', '')
                })
        return payloads

    def get_targets(self) -> List[Dict]:
        """Get mutation endpoints to test."""
        if not self.strategy:
            return []
        return self.strategy.targets

    def get_payload_dict(self) -> Dict[str, Any]:
        """Get payloads as field->value dict for direct injection."""
        return {p['field']: p['value'] for p in self.get_enriched_payloads()}

    def merge_with_defaults(self, default_payloads: List[Dict]) -> List[Dict]:
        """Merge LLM payloads with default payloads (LLM first)."""
        llm = self.get_enriched_payloads()
        llm_fields = {p['field'] for p in llm}

        # Add defaults that don't conflict
        for dp in default_payloads:
            field = dp.get('field') or list(dp.keys())[0]
            if field not in llm_fields:
                llm.append(dp)

        return llm
