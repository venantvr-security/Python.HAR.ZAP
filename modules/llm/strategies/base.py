"""
Base Attack Strategy - ABC for all LLM-enriched attack strategies.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..analyzer import AttackStrategy, SecurityPlan


class BaseAttackStrategy(ABC):
    """
    Base class for attack strategies that consume LLM-generated plans.
    Each strategy integrates with existing attack modules.
    """

    ATTACK_TYPE: str = ""

    def __init__(self, plan: 'SecurityPlan', config: Optional[Dict] = None):
        self.plan = plan
        self.config = config or {}
        self.strategy = plan.get_strategy(self.ATTACK_TYPE)

    @abstractmethod
    def get_enriched_payloads(self) -> List[Any]:
        """Get LLM-enriched payloads for this attack type."""
        pass

    @abstractmethod
    def get_targets(self) -> List[Dict]:
        """Get prioritized targets for this attack."""
        pass

    def is_applicable(self) -> bool:
        """Check if strategy applies based on LLM analysis."""
        return self.strategy is not None and len(self.get_targets()) > 0

    def get_priority(self) -> str:
        """Get attack priority."""
        if self.strategy:
            return self.strategy.priority
        return "low"

    def get_rationale(self) -> str:
        """Get attack rationale from LLM."""
        if self.strategy:
            return self.strategy.rationale
        return ""

    def get_test_plan(self) -> List[str]:
        """Get step-by-step test plan."""
        if self.strategy:
            return self.strategy.test_plan
        return []
