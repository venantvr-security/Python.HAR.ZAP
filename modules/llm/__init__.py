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
from .adaptive_idor import AdaptiveIDORLoop, IDORFinding, IDORVerdict, IDORObservation, client_from_config
from .adaptive_mass_assignment import AdaptiveMassAssignmentLoop, MAFinding
from .pattern_enricher import PatternEnricher

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
    'AdaptiveIDORLoop',
    'IDORFinding',
    'IDORVerdict',
    'IDORObservation',
    'client_from_config',
    'AdaptiveMassAssignmentLoop',
    'MAFinding',
    'PatternEnricher',
    'prompts',
    'strategies',
]
