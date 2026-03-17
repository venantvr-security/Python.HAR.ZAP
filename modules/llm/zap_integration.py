"""
LLM to ZAP Integration - Bridge between LLM strategies and ZAP enrichment.
Enriches ZAP fuzzer lists with domain-specific payloads.
"""
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

from .analyzer import SecurityPlan
from .strategies import (
    MassAssignmentStrategy,
    IDORStrategy,
    FuzzerVocabularyStrategy,
    RaceConditionStrategy,
    PassiveRegexStrategy,
    BusinessLogicStrategy,
)
from modules.utils import get_logger

logger = get_logger("llm.zap_integration")


@dataclass
class DomainEnrichment:
    """Domain-specific enrichment result."""
    domain: str
    confidence: float
    mass_assignment_payloads: List[Dict] = field(default_factory=list)
    hidden_params: Dict[str, List[str]] = field(default_factory=dict)
    idor_strategies: List[Dict] = field(default_factory=list)
    custom_regex: List[Dict] = field(default_factory=list)
    race_windows: List[Dict] = field(default_factory=list)
    business_logic_tests: List[Dict] = field(default_factory=list)
    prioritized_endpoints: List[Dict] = field(default_factory=list)


class LLMZAPEnricher:
    """
    Bridge between LLM SecurityPlan and ZAP enrichment.
    Converts LLM strategies into ZAP-compatible payloads.
    Auto-persists patterns to PatternStore.
    """

    def __init__(self, plan: SecurityPlan, config: Optional[Dict] = None, auto_persist: bool = True):
        self.plan = plan
        self.config = config or {}
        self.domain = plan.domain_analysis.get('inferred_domain', 'unknown')
        self.confidence = plan.domain_analysis.get('confidence', 0.0)
        self.auto_persist = auto_persist
        self._session_id: Optional[str] = None

    def get_domain_enrichment(self) -> DomainEnrichment:
        """
        Extract all domain-specific enrichments from SecurityPlan.
        Returns structured data ready for ZAP injection.
        Auto-persists to PatternStore if enabled.
        """
        enrichment = DomainEnrichment(
            domain=self.domain,
            confidence=self.confidence,
            prioritized_endpoints=self.plan.prioritized_endpoints
        )

        # Mass Assignment payloads
        mass_strategy = MassAssignmentStrategy(self.plan, self.config)
        if mass_strategy.is_applicable():
            enrichment.mass_assignment_payloads = mass_strategy.get_enriched_payloads()
            logger.info(
                "mass_assignment_enriched",
                domain=self.domain,
                payloads_count=len(enrichment.mass_assignment_payloads)
            )

        # Hidden parameters / Fuzzer vocabulary
        fuzzer_strategy = FuzzerVocabularyStrategy(self.plan, self.config)
        if fuzzer_strategy.is_applicable():
            enrichment.hidden_params = fuzzer_strategy.to_wordlist()
            logger.info(
                "fuzzer_vocab_enriched",
                domain=self.domain,
                params_count=len(enrichment.hidden_params)
            )

        # IDOR strategies
        idor_strategy = IDORStrategy(self.plan, self.config)
        if idor_strategy.is_applicable():
            enrichment.idor_strategies = idor_strategy.get_enriched_payloads()

        # Custom regex for passive analysis
        passive_strategy = PassiveRegexStrategy(self.plan, self.config)
        enrichment.custom_regex = passive_strategy.get_enriched_payloads()

        # Race condition windows
        race_strategy = RaceConditionStrategy(self.plan, self.config)
        if race_strategy.is_applicable():
            enrichment.race_windows = race_strategy.get_enriched_payloads()

        # Business logic tests
        bl_strategy = BusinessLogicStrategy(self.plan, self.config)
        enrichment.business_logic_tests = bl_strategy.get_enriched_payloads()

        # Auto-persist to PatternStore
        if self.auto_persist:
            self._persist_enrichment(enrichment)

        return enrichment

    def _persist_enrichment(self, enrichment: DomainEnrichment):
        """Automatically persist enrichment to PatternStore."""
        from .pattern_store import PatternStore

        store = PatternStore()
        self._session_id = store.store_from_enrichment(enrichment, self.plan.har_hash)
        logger.info(
            "enrichment_auto_persisted",
            session_id=self._session_id,
            domain=self.domain
        )

    @property
    def session_id(self) -> Optional[str]:
        """Get the session ID if auto-persisted."""
        return self._session_id

    def enrich_dictionary_manager(self, dict_manager: 'DictionaryManager') -> Dict[str, int]:
        """
        Inject LLM-generated payloads into DictionaryManager.
        Returns count of items added per dictionary.
        """
        enrichment = self.get_domain_enrichment()
        counts = {}

        # Enrich mass_assignment dictionary
        if enrichment.mass_assignment_payloads:
            mass_dict = dict_manager.load_dictionary('mass_assignment') or {'keys': {}}

            for payload in enrichment.mass_assignment_payloads:
                field = payload.get('field')
                value = payload.get('value')
                reason = payload.get('reason', f'LLM-generated for {self.domain}')

                if field:
                    mass_dict['keys'][field] = {
                        'type': type(value).__name__,
                        'dangerous_values': [value],
                        'description': reason,
                        'severity': 'HIGH',
                        'source': 'llm',
                        'domain': self.domain
                    }

            # Add metadata
            if 'extensions' not in mass_dict:
                mass_dict['extensions'] = []
            mass_dict['extensions'].append({
                'source': 'llm',
                'domain': self.domain,
                'confidence': self.confidence,
                'items_added': len(enrichment.mass_assignment_payloads)
            })

            dict_manager.save_dictionary('mass_assignment', mass_dict, 'generated')
            counts['mass_assignment'] = len(enrichment.mass_assignment_payloads)

        # Enrich hidden_parameters dictionary
        if enrichment.hidden_params:
            params_dict = dict_manager.load_dictionary('hidden_parameters') or {'parameters': {}}

            for param, values in enrichment.hidden_params.items():
                if param in params_dict.get('parameters', {}):
                    # Merge with existing
                    existing = set(params_dict['parameters'][param])
                    existing.update(values)
                    params_dict['parameters'][param] = list(existing)
                else:
                    params_dict['parameters'][param] = values

            # Add metadata
            if 'extensions' not in params_dict:
                params_dict['extensions'] = []
            params_dict['extensions'].append({
                'source': 'llm',
                'domain': self.domain,
                'params_added': len(enrichment.hidden_params)
            })

            dict_manager.save_dictionary('hidden_parameters', params_dict, 'generated')
            counts['hidden_parameters'] = len(enrichment.hidden_params)

        logger.info(
            "dictionaries_enriched",
            domain=self.domain,
            counts=counts
        )

        return counts

    def enrich_zap_payloads(self, zap_enricher: 'ZAPPayloadEnricher') -> Dict[str, List[str]]:
        """
        Get payloads formatted for ZAPPayloadEnricher.
        Returns dict of pattern_type -> payloads.
        """
        enrichment = self.get_domain_enrichment()
        payloads = {}

        # Mass assignment as injection payloads
        if enrichment.mass_assignment_payloads:
            payloads['mass_assignment'] = [
                f"{p['field']}={p['value']}"
                for p in enrichment.mass_assignment_payloads
                if 'field' in p and 'value' in p
            ]

        # Hidden params as query string payloads
        if enrichment.hidden_params:
            hidden = []
            for param, values in enrichment.hidden_params.items():
                for val in values:
                    hidden.append(f"{param}={val}")
            payloads['hidden_params'] = hidden

        # IDOR mutations
        if enrichment.idor_strategies:
            idor_payloads = []
            for strategy in enrichment.idor_strategies:
                mutations = strategy.get('mutations', [])
                idor_payloads.extend(mutations)
            if idor_payloads:
                payloads['idor'] = idor_payloads

        return payloads

    def get_passive_scanner_patterns(self) -> List[Dict]:
        """Get regex patterns for SensitiveDataScanner."""
        enrichment = self.get_domain_enrichment()
        return enrichment.custom_regex

    def get_race_condition_targets(self) -> List[Dict]:
        """Get race condition test configurations."""
        enrichment = self.get_domain_enrichment()
        return enrichment.race_windows

    def get_business_logic_tests(self) -> List[Dict]:
        """Get business logic vulnerability tests."""
        enrichment = self.get_domain_enrichment()
        return enrichment.business_logic_tests

    def export_wordlists(self, output_dir: str) -> Dict[str, str]:
        """
        Export enriched payloads as wordlist files for ZAP fuzzer.
        Returns dict of wordlist_name -> file_path.
        """
        import os
        from pathlib import Path

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        enrichment = self.get_domain_enrichment()
        exported = {}

        # Mass assignment wordlist
        if enrichment.mass_assignment_payloads:
            filepath = output_path / f"llm_{self.domain}_mass_assignment.txt"
            with open(filepath, 'w') as f:
                for p in enrichment.mass_assignment_payloads:
                    if 'field' in p:
                        f.write(f"{p['field']}\n")
            exported['mass_assignment'] = str(filepath)

        # Hidden params wordlist
        if enrichment.hidden_params:
            filepath = output_path / f"llm_{self.domain}_hidden_params.txt"
            with open(filepath, 'w') as f:
                for param, values in enrichment.hidden_params.items():
                    for val in values:
                        f.write(f"{param}={val}\n")
            exported['hidden_params'] = str(filepath)

        # IDOR mutations wordlist
        if enrichment.idor_strategies:
            filepath = output_path / f"llm_{self.domain}_idor.txt"
            with open(filepath, 'w') as f:
                for strategy in enrichment.idor_strategies:
                    for mutation in strategy.get('mutations', []):
                        f.write(f"{mutation}\n")
            exported['idor'] = str(filepath)

        logger.info(
            "wordlists_exported",
            domain=self.domain,
            files=list(exported.keys()),
            output_dir=output_dir
        )

        return exported


def enrich_zap_from_har(
    har_data: Dict,
    config: Dict,
    dict_manager: Optional['DictionaryManager'] = None,
    zap_enricher: Optional['ZAPPayloadEnricher'] = None,
    export_dir: Optional[str] = None,
    auto_persist: bool = True
) -> Dict[str, Any]:
    """
    Full pipeline: HAR → LLM analysis → ZAP enrichment.
    Auto-persists patterns by default.

    Args:
        har_data: Loaded HAR file
        config: Application config (with llm section)
        dict_manager: Optional DictionaryManager to enrich
        zap_enricher: Optional ZAPPayloadEnricher to enrich
        export_dir: Optional directory to export wordlists
        auto_persist: Auto-save patterns to PatternStore (default: True)

    Returns:
        Enrichment summary with domain info, counts, and session_id
    """
    from .analyzer import LLMSecurityAnalyzer

    # Analyze HAR with LLM
    analyzer = LLMSecurityAnalyzer.from_config(config)
    plan = analyzer.analyze(har_data)

    # Create enricher (auto-persist enabled)
    enricher = LLMZAPEnricher(plan, config, auto_persist=auto_persist)

    result = {
        'domain': enricher.domain,
        'confidence': enricher.confidence,
        'har_hash': plan.har_hash,
        'strategies_count': len(plan.strategies),
        'enrichments': {}
    }

    # This triggers auto-persist via get_domain_enrichment
    domain_enrichment = enricher.get_domain_enrichment()

    # Add session info if persisted
    if enricher.session_id:
        result['session_id'] = enricher.session_id
        from .pattern_store import PatternStore
        store = PatternStore()
        result['pattern_files'] = store.persist_session(enricher.session_id)
        result['zap_mount'] = store.get_zap_mount_paths()

    # Enrich DictionaryManager
    if dict_manager:
        counts = enricher.enrich_dictionary_manager(dict_manager)
        result['enrichments']['dictionary_manager'] = counts

    # Get ZAP payloads
    if zap_enricher:
        payloads = enricher.enrich_zap_payloads(zap_enricher)
        result['enrichments']['zap_payloads'] = {
            k: len(v) for k, v in payloads.items()
        }

    # Export wordlists
    if export_dir:
        exported = enricher.export_wordlists(export_dir)
        result['enrichments']['wordlists'] = exported

    # Include passive scanner patterns
    result['custom_regex'] = enricher.get_passive_scanner_patterns()
    result['race_targets'] = enricher.get_race_condition_targets()
    result['business_logic'] = enricher.get_business_logic_tests()

    logger.info(
        "zap_enrichment_complete",
        domain=enricher.domain,
        session_id=enricher.session_id,
        result=result
    )

    return result
