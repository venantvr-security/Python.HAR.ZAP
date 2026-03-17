"""
LLM Attack Strategies - Strategy pattern for enriching attack modules.
"""
from .base import BaseAttackStrategy
from .mass_assignment import MassAssignmentStrategy
from .idor_strategy import IDORStrategy
from .race_condition import RaceConditionStrategy
from .passive_analysis import PassiveRegexStrategy
from .business_logic import BusinessLogicStrategy
from .fuzzer_strategy import FuzzerVocabularyStrategy

__all__ = [
    'BaseAttackStrategy',
    'MassAssignmentStrategy',
    'IDORStrategy',
    'RaceConditionStrategy',
    'PassiveRegexStrategy',
    'BusinessLogicStrategy',
    'FuzzerVocabularyStrategy',
]
