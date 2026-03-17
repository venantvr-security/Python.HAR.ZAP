"""
LLM Cache - File-based cache for LLM responses.
"""
import json
import time
from pathlib import Path
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .analyzer import SecurityPlan


class LLMCache:
    """
    File-based cache for LLM responses.
    Key: HAR hash, Value: SecurityPlan JSON
    """

    def __init__(self, cache_dir: str = './.llm_cache', ttl_hours: int = 24):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = ttl_hours * 3600

    def _get_path(self, har_hash: str) -> Path:
        return self.cache_dir / f"{har_hash}.json"

    def get(self, har_hash: str) -> Optional['SecurityPlan']:
        """Get cached plan if exists and not expired."""
        from .analyzer import SecurityPlan, AttackStrategy

        path = self._get_path(har_hash)
        if not path.exists():
            return None

        try:
            with open(path) as f:
                data = json.load(f)

            # Check TTL
            cached_at = data.get('_cached_at', 0)
            if time.time() - cached_at > self.ttl_seconds:
                path.unlink()
                return None

            # Reconstruct SecurityPlan
            strategies = [
                AttackStrategy(**s) for s in data.get('strategies', [])
            ]
            return SecurityPlan(
                har_hash=data['har_hash'],
                domain_analysis=data['domain_analysis'],
                strategies=strategies,
                prioritized_endpoints=data['prioritized_endpoints'],
                custom_regex_patterns=data['custom_regex_patterns'],
                business_logic_flows=data['business_logic_flows'],
                metadata=data['metadata']
            )
        except Exception:
            return None

    def set(self, har_hash: str, plan: 'SecurityPlan'):
        """Cache security plan."""
        path = self._get_path(har_hash)
        data = plan.to_dict()
        data['_cached_at'] = time.time()

        with open(path, 'w') as f:
            json.dump(data, f, indent=2)

    def invalidate(self, har_hash: str):
        """Remove cached entry."""
        path = self._get_path(har_hash)
        if path.exists():
            path.unlink()

    def clear(self):
        """Clear all cache."""
        for f in self.cache_dir.glob('*.json'):
            f.unlink()
