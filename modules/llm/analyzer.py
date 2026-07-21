"""
LLM Security Analyzer - Single-call orchestrator for security testing.
"""
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

from .client import LLMClient, LLMResponse
from .context_extractor import HARContextExtractor, HARContext
from .cache import LLMCache
from .prompts import PROMPTS
from modules.utils import get_logger

logger = get_logger("llm.analyzer")


@dataclass
class AttackStrategy:
    """Single attack strategy from LLM analysis."""
    attack_type: str
    priority: str
    targets: List[Dict[str, Any]] = field(default_factory=list)
    payloads: List[Any] = field(default_factory=list)
    rationale: str = ""
    test_plan: List[str] = field(default_factory=list)


@dataclass
class SecurityPlan:
    """Complete security plan from single LLM analysis."""
    har_hash: str
    domain_analysis: Dict[str, Any]
    strategies: List[AttackStrategy]
    prioritized_endpoints: List[Dict]
    custom_regex_patterns: List[Dict]
    business_logic_flows: List[Dict]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_strategy(self, attack_type: str) -> Optional[AttackStrategy]:
        """Get strategy by type."""
        for s in self.strategies:
            if s.attack_type == attack_type:
                return s
        return None

    def to_dict(self) -> Dict:
        """Convert to dict for serialization."""
        return {
            'har_hash': self.har_hash,
            'domain_analysis': self.domain_analysis,
            'strategies': [
                {
                    'attack_type': s.attack_type,
                    'priority': s.priority,
                    'targets': s.targets,
                    'payloads': s.payloads,
                    'rationale': s.rationale,
                    'test_plan': s.test_plan
                }
                for s in self.strategies
            ],
            'prioritized_endpoints': self.prioritized_endpoints,
            'custom_regex_patterns': self.custom_regex_patterns,
            'business_logic_flows': self.business_logic_flows,
            'metadata': self.metadata
        }




class LLMSecurityAnalyzer:
    """
    Orchestrating analyzer - calls LLM ONCE to get full security plan.
    Results cached by HAR hash.
    """

    def __init__(self, client: LLMClient, cache: Optional[LLMCache] = None):
        self.client = client
        self.cache = cache or LLMCache()

    def analyze(self, har_data: Dict, force_refresh: bool = False) -> SecurityPlan:
        """
        Analyze HAR and generate complete security plan.
        Single LLM call, cached by HAR hash.
        """
        # Extract context
        extractor = HARContextExtractor(har_data)
        context = extractor.extract()

        # Check cache
        if not force_refresh:
            cached = self.cache.get(context.har_hash)
            if cached:
                logger.info("cache_hit", har_hash=context.har_hash)
                cached.metadata['cached'] = True
                return cached

        logger.info(
            "analyzing_har",
            har_hash=context.har_hash,
            endpoints=len(context.endpoints)
        )

        # Get prompt template
        template = PROMPTS['full_analysis']
        system_prompt, user_prompt = template.render(context=context.to_prompt_context())

        # Single LLM call
        response = self.client.complete(user_prompt, system=system_prompt)

        # Parse response
        plan = self._parse_response(response, context)

        # Ne PAS mettre en cache un plan issu d'un échec de parsing : sinon un
        # plan vide serait servi depuis le cache pendant tout le TTL (24 h) sans
        # jamais réessayer, l'erreur étant avalée silencieusement.
        if 'error' not in plan.metadata:
            self.cache.set(context.har_hash, plan)
        else:
            logger.warning("plan_not_cached_due_to_parse_error", har_hash=context.har_hash)

        logger.info(
            "analysis_complete",
            har_hash=context.har_hash,
            strategies=len(plan.strategies),
            latency_ms=round(response.latency_ms, 2)
        )

        return plan

    def _extract_json(self, content: str) -> Optional[Dict]:
        """
        Extract JSON from LLM response with multiple strategies.
        Handles markdown blocks, raw JSON, and partial responses.
        """
        # Strategy 1: Extract from ```json blocks
        json_block = re.search(r'```json\s*([\s\S]*?)\s*```', content)
        if json_block:
            try:
                return json.loads(json_block.group(1).strip())
            except json.JSONDecodeError:
                pass

        # Strategy 2: Extract from any ``` blocks
        code_block = re.search(r'```\s*([\s\S]*?)\s*```', content)
        if code_block:
            try:
                return json.loads(code_block.group(1).strip())
            except json.JSONDecodeError:
                pass

        # Strategy 3: Find JSON object boundaries
        brace_match = re.search(r'\{[\s\S]*\}', content)
        if brace_match:
            try:
                return json.loads(brace_match.group(0))
            except json.JSONDecodeError:
                pass

        # Strategy 4: Try raw content
        try:
            return json.loads(content.strip())
        except json.JSONDecodeError:
            pass

        return None

    def _parse_response(self, response: LLMResponse, context: HARContext) -> SecurityPlan:
        """Parse LLM JSON response into SecurityPlan."""
        try:
            data = self._extract_json(response.content)

            if data is None:
                logger.error("json_extraction_failed", content_preview=response.content[:200])
                raise json.JSONDecodeError("Failed to extract JSON", response.content, 0)

            strategies = [
                AttackStrategy(
                    attack_type=s.get('attack_type', ''),
                    priority=s.get('priority', 'medium'),
                    targets=s.get('targets', []),
                    payloads=s.get('payloads', []),
                    rationale=s.get('rationale', ''),
                    test_plan=s.get('test_plan', [])
                )
                for s in data.get('strategies', [])
            ]

            return SecurityPlan(
                har_hash=context.har_hash,
                domain_analysis=data.get('domain_analysis', {}),
                strategies=strategies,
                prioritized_endpoints=data.get('prioritized_endpoints', []),
                custom_regex_patterns=data.get('custom_regex_patterns', []),
                business_logic_flows=data.get('business_logic_flows', []),
                metadata={
                    'model': response.model,
                    'usage': response.usage,
                    'latency_ms': response.latency_ms,
                    'cached': False
                }
            )
        except (json.JSONDecodeError, KeyError) as e:
            logger.error("parse_error", error=str(e))
            # Return minimal plan on parse failure
            return SecurityPlan(
                har_hash=context.har_hash,
                domain_analysis={'inferred_domain': 'unknown', 'confidence': 0.0},
                strategies=[],
                prioritized_endpoints=[],
                custom_regex_patterns=[],
                business_logic_flows=[],
                metadata={'error': str(e), 'cached': False}
            )

    @staticmethod
    def from_config(config: Dict) -> 'LLMSecurityAnalyzer':
        """Factory from config dict."""
        client = LLMClient.from_config(config)
        cache_config = config.get('llm', {}).get('cache', {})
        cache = LLMCache(
            cache_dir=cache_config.get('directory', './.llm_cache'),
            ttl_hours=cache_config.get('ttl_hours', 24)
        )
        return LLMSecurityAnalyzer(client, cache)
