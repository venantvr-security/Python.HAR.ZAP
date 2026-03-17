"""
Race Condition Strategy - TOCTOU window detection in request flows.
"""
from typing import Dict, List

from .base import BaseAttackStrategy


class RaceConditionStrategy(BaseAttackStrategy):
    """Race condition strategy for TOCTOU vulnerability detection."""

    ATTACK_TYPE = "race_condition"

    def get_enriched_payloads(self) -> List[Dict]:
        """Get race condition windows to test."""
        if not self.strategy:
            return []

        windows = []
        for p in self.strategy.payloads:
            if isinstance(p, dict):
                windows.append({
                    'name': p.get('name', ''),
                    'steps': p.get('steps_involved', p.get('endpoints', [])),
                    'attack': p.get('attack', ''),
                    'method': p.get('method', 'burst_parallel'),
                    'concurrent': p.get('concurrent_requests', 10),
                    'severity': p.get('severity', 'medium')
                })
        return windows

    def get_targets(self) -> List[Dict]:
        """Get endpoints involved in race windows."""
        if not self.strategy:
            return []
        return self.strategy.targets

    def get_burst_config(self, window_name: str) -> Dict:
        """Get burst configuration for a specific window."""
        for w in self.get_enriched_payloads():
            if w.get('name') == window_name:
                return {
                    'concurrent': w.get('concurrent', 10),
                    'method': w.get('method', 'burst_parallel'),
                    'steps': w.get('steps', [])
                }
        return {'concurrent': 10, 'method': 'burst_parallel', 'steps': []}

    def get_critical_windows(self) -> List[Dict]:
        """Get only critical/high severity race windows."""
        return [
            w for w in self.get_enriched_payloads()
            if w.get('severity') in ('critical', 'high')
        ]
