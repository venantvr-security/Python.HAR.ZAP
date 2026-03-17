"""
Passive Analysis Strategy - Domain-specific regex for sensitive data detection.
"""
import re
from typing import Dict, List, Optional

from .base import BaseAttackStrategy


class PassiveRegexStrategy(BaseAttackStrategy):
    """Passive analysis strategy with LLM-generated custom regex patterns."""

    ATTACK_TYPE = "passive_analysis"

    def get_enriched_payloads(self) -> List[Dict]:
        """Get custom regex patterns for sensitive data detection."""
        if not self.strategy:
            return self._get_from_plan_patterns()

        patterns = []
        for p in self.strategy.payloads:
            if isinstance(p, dict) and 'regex' in p:
                # Validate regex
                if self._is_valid_regex(p['regex']):
                    patterns.append({
                        'name': p.get('name', 'custom_pattern'),
                        'regex': p['regex'],
                        'severity': p.get('severity', 'medium'),
                        'compliance': p.get('compliance'),
                        'description': p.get('description', '')
                    })
        return patterns

    def _get_from_plan_patterns(self) -> List[Dict]:
        """Fallback to plan-level custom_regex_patterns."""
        return self.plan.custom_regex_patterns if self.plan else []

    def get_targets(self) -> List[Dict]:
        """Get patterns as targets."""
        return [{'pattern': p['name']} for p in self.get_enriched_payloads()]

    def _is_valid_regex(self, pattern: str) -> bool:
        """Validate regex pattern."""
        try:
            re.compile(pattern)
            return True
        except re.error:
            return False

    def get_compiled_patterns(self) -> Dict[str, re.Pattern]:
        """Get compiled regex patterns."""
        compiled = {}
        for p in self.get_enriched_payloads():
            try:
                compiled[p['name']] = re.compile(p['regex'])
            except re.error:
                continue
        return compiled

    def get_patterns_by_severity(self, severity: str) -> List[Dict]:
        """Get patterns filtered by severity."""
        return [
            p for p in self.get_enriched_payloads()
            if p.get('severity') == severity
        ]

    def get_compliance_patterns(self, compliance: str) -> List[Dict]:
        """Get patterns for specific compliance (HIPAA, PCI, GDPR)."""
        return [
            p for p in self.get_enriched_payloads()
            if p.get('compliance') == compliance
        ]
