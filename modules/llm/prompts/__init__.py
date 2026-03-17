"""
LLM Prompts - Reusable, templated prompts for security analysis.
"""
from .base import PromptTemplate
from .system import SYSTEM_PROMPTS
from .analysis import FULL_ANALYSIS, DOMAIN_ANALYSIS
from .attacks import (
    MASS_ASSIGNMENT,
    IDOR_STRATEGY,
    RACE_CONDITION,
    BUSINESS_LOGIC,
    HIDDEN_PARAMS,
)
from .passive import PASSIVE_REGEX

# Registry of all prompts
PROMPTS = {
    'full_analysis': FULL_ANALYSIS,
    'domain_analysis': DOMAIN_ANALYSIS,
    'mass_assignment': MASS_ASSIGNMENT,
    'idor_strategy': IDOR_STRATEGY,
    'race_condition': RACE_CONDITION,
    'passive_regex': PASSIVE_REGEX,
    'business_logic': BUSINESS_LOGIC,
    'hidden_params': HIDDEN_PARAMS,
}


def get_prompt(name: str) -> PromptTemplate:
    """Get prompt template by name."""
    return PROMPTS.get(name)


def list_prompts() -> dict:
    """List available prompts with descriptions."""
    return {name: p.description for name, p in PROMPTS.items()}


__all__ = [
    'PromptTemplate',
    'PROMPTS',
    'SYSTEM_PROMPTS',
    'get_prompt',
    'list_prompts',
    'FULL_ANALYSIS',
    'DOMAIN_ANALYSIS',
    'MASS_ASSIGNMENT',
    'IDOR_STRATEGY',
    'RACE_CONDITION',
    'PASSIVE_REGEX',
    'BUSINESS_LOGIC',
    'HIDDEN_PARAMS',
]
