"""
LLM Integration Module

Single-call LLM analysis for security testing enrichment.
"""
from .client import LLMClient, LLMConfig, LLMResponse
from .cache import LLMCache
from .context_extractor import HARContextExtractor, HARContext
from .analyzer import LLMSecurityAnalyzer, SecurityPlan, AttackStrategy
from .zap_integration import LLMZAPEnricher, DomainEnrichment, enrich_zap_from_har
from .pattern_store import PatternStore, PatternSession, create_store

# Submodules
from . import prompts
from . import strategies

__all__ = [
    'LLMClient',
    'LLMConfig',
    'LLMResponse',
    'LLMCache',
    'HARContextExtractor',
    'HARContext',
    'LLMSecurityAnalyzer',
    'SecurityPlan',
    'AttackStrategy',
    'LLMZAPEnricher',
    'DomainEnrichment',
    'enrich_zap_from_har',
    'PatternStore',
    'PatternSession',
    'create_store',
    'prompts',
    'strategies',
]
