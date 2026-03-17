"""
IDOR Strategy - LLM-determined enumeration strategies per ID type.
"""
from typing import Dict, List, Any, Optional

from .base import BaseAttackStrategy


class IDORStrategy(BaseAttackStrategy):
    """IDOR strategy with LLM-determined enumeration per ID pattern."""

    ATTACK_TYPE = "idor"

    def get_enriched_payloads(self) -> List[Dict]:
        """Get ID enumeration strategies by pattern type."""
        if not self.strategy:
            return []

        strategies = []
        for p in self.strategy.payloads:
            if isinstance(p, dict):
                strategies.append({
                    'pattern': p.get('pattern', ''),
                    'id_type': p.get('id_type', 'unknown'),
                    'strategy': p.get('strategy', 'enumerate'),
                    'mutations': p.get('mutations', []),
                    'risk': p.get('risk', 'medium')
                })
        return strategies

    def get_targets(self) -> List[Dict]:
        """Get endpoints with IDOR potential."""
        if not self.strategy:
            return []
        return self.strategy.targets

    def get_strategy_for_endpoint(self, endpoint: str) -> Optional[Dict]:
        """Get specific strategy for an endpoint."""
        for s in self.get_enriched_payloads():
            if endpoint in s.get('pattern', ''):
                return s
        return None

    def get_mutations_for_id_type(self, id_type: str) -> List[str]:
        """Get mutations for a specific ID type."""
        for s in self.get_enriched_payloads():
            if s.get('id_type') == id_type:
                return s.get('mutations', [])
        return []

    def should_skip(self, endpoint: str) -> bool:
        """Check if endpoint should be skipped (e.g., UUID v4)."""
        strategy = self.get_strategy_for_endpoint(endpoint)
        return strategy and strategy.get('strategy') == 'skip'
