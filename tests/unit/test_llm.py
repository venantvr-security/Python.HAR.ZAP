"""Tests for LLM integration module"""
import pytest
import json
from unittest.mock import Mock, patch, MagicMock


@pytest.fixture
def sample_har():
    return {
        "log": {
            "entries": [
                {
                    "request": {
                        "url": "https://api.example.com/users/123?page=1",
                        "method": "GET",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer token123"},
                            {"name": "Cookie", "value": "session=abc"}
                        ],
                        "queryString": [{"name": "page", "value": "1"}]
                    },
                    "response": {
                        "status": 200,
                        "headers": [],
                        "content": {
                            "mimeType": "application/json",
                            "text": '{"id": 123, "email": "user@example.com", "role": "customer"}'
                        }
                    }
                },
                {
                    "request": {
                        "url": "https://api.example.com/orders/456",
                        "method": "POST",
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "postData": {
                            "mimeType": "application/json",
                            "text": '{"product_id": 789, "quantity": 2, "price": 49.99}'
                        }
                    },
                    "response": {"status": 201, "headers": [], "content": {}}
                }
            ]
        }
    }


class TestHARContextExtractor:
    """Test HAR context extraction"""

    def test_init(self, sample_har):
        from modules.llm.context_extractor import HARContextExtractor

        extractor = HARContextExtractor(sample_har)
        assert extractor.har_data == sample_har
        assert len(extractor.entries) == 2

    def test_extract(self, sample_har):
        from modules.llm.context_extractor import HARContextExtractor

        extractor = HARContextExtractor(sample_har)
        context = extractor.extract()

        assert context.har_hash is not None
        assert len(context.har_hash) == 16
        assert 'api.example.com' in context.domains
        assert 'GET' in context.methods_used
        assert 'POST' in context.methods_used

    def test_extract_endpoints(self, sample_har):
        from modules.llm.context_extractor import HARContextExtractor

        extractor = HARContextExtractor(sample_har)
        context = extractor.extract()

        # Should normalize IDs
        assert any('/users/{id}' in ep for ep in context.endpoints)
        assert any('/orders/{id}' in ep for ep in context.endpoints)

    def test_extract_json_keys(self, sample_har):
        from modules.llm.context_extractor import HARContextExtractor

        extractor = HARContextExtractor(sample_har)
        context = extractor.extract()

        # From request body
        assert 'product_id' in context.json_keys
        assert 'quantity' in context.json_keys
        # From response body
        assert 'email' in context.json_keys
        assert 'role' in context.json_keys

    def test_extract_auth_types(self, sample_har):
        from modules.llm.context_extractor import HARContextExtractor

        extractor = HARContextExtractor(sample_har)
        context = extractor.extract()

        assert 'Bearer' in context.auth_types
        assert 'Cookie' in context.auth_types

    def test_extract_id_patterns(self, sample_har):
        from modules.llm.context_extractor import HARContextExtractor

        extractor = HARContextExtractor(sample_har)
        context = extractor.extract()

        # Should detect numeric sequential patterns
        numeric_patterns = [p for p in context.id_patterns if p['pattern_type'] == 'numeric_sequential']
        assert len(numeric_patterns) > 0

    def test_normalize_endpoint(self, sample_har):
        from modules.llm.context_extractor import HARContextExtractor

        extractor = HARContextExtractor(sample_har)

        assert extractor._normalize_endpoint('/users/123') == '/users/{id}'
        assert extractor._normalize_endpoint('/orders/456/items/789') == '/orders/{id}/items/{id}'
        assert extractor._normalize_endpoint('/files/abc123') == '/files/abc123'

    def test_normalize_uuid(self, sample_har):
        from modules.llm.context_extractor import HARContextExtractor

        extractor = HARContextExtractor(sample_har)
        uuid_path = '/items/550e8400-e29b-41d4-a716-446655440000'
        normalized = extractor._normalize_endpoint(uuid_path)

        assert '{uuid}' in normalized

    def test_to_prompt_context(self, sample_har):
        from modules.llm.context_extractor import HARContextExtractor

        extractor = HARContextExtractor(sample_har)
        context = extractor.extract()
        prompt_ctx = context.to_prompt_context()

        # Should be valid JSON
        parsed = json.loads(prompt_ctx)
        assert 'endpoints' in parsed
        assert 'json_keys' in parsed
        assert 'methods' in parsed

    def test_empty_har(self):
        from modules.llm.context_extractor import HARContextExtractor

        empty_har = {"log": {"entries": []}}
        extractor = HARContextExtractor(empty_har)
        context = extractor.extract()

        assert context.har_hash is not None
        assert len(context.endpoints) == 0


class TestLLMConfig:
    """Test LLM configuration"""

    def test_default_config(self):
        from modules.llm.client import LLMConfig

        config = LLMConfig()
        assert config.provider == "anthropic"
        assert config.model == "claude-sonnet-4-20250514"
        assert config.max_tokens == 4000
        assert config.temperature == 0.1

    def test_custom_config(self):
        from modules.llm.client import LLMConfig

        config = LLMConfig(
            model="claude-opus-4-20250514",
            max_tokens=8000,
            temperature=0.5,
            api_key="test-key"
        )
        assert config.model == "claude-opus-4-20250514"
        assert config.max_tokens == 8000
        assert config.api_key == "test-key"


class TestLLMClient:
    """Test LLM client"""

    def test_init_without_api_key(self):
        from modules.llm.client import LLMClient, LLMConfig

        config = LLMConfig(api_key="")
        with pytest.raises(ValueError, match="API key required"):
            LLMClient(config)

    def test_init_with_api_key(self):
        from modules.llm.client import LLMClient, LLMConfig

        config = LLMConfig(api_key="test-api-key")
        client = LLMClient(config)
        assert client.config.api_key == "test-api-key"

    @patch.dict('os.environ', {'HARZAP_LLM_API_KEY': 'env-api-key'})
    def test_from_config(self):
        from modules.llm.client import LLMClient

        config = {
            'llm': {
                'model': 'test-model',
                'max_tokens': 2000
            }
        }
        client = LLMClient.from_config(config)
        assert client.config.api_key == 'env-api-key'
        assert client.config.model == 'test-model'

    @patch('modules.llm.client.create_http_session')
    def test_complete(self, mock_session):
        from modules.llm.client import LLMClient, LLMConfig

        mock_response = Mock()
        mock_response.json.return_value = {
            "content": [{"text": '{"test": "response"}'}],
            "model": "claude-test",
            "usage": {"input_tokens": 100, "output_tokens": 50}
        }
        mock_response.raise_for_status = Mock()

        mock_sess = Mock()
        mock_sess.post.return_value = mock_response
        mock_session.return_value = mock_sess

        config = LLMConfig(api_key="test-key")
        client = LLMClient(config)
        response = client.complete("test prompt")

        assert response.content == '{"test": "response"}'
        assert response.model == "claude-test"


class TestLLMCache:
    """Test LLM cache"""

    def test_init(self, tmp_path):
        from modules.llm.cache import LLMCache

        cache = LLMCache(cache_dir=str(tmp_path), ttl_hours=12)
        assert cache.cache_dir == tmp_path
        assert cache.ttl_seconds == 12 * 3600

    def test_set_and_get(self, tmp_path):
        from modules.llm.cache import LLMCache
        from modules.llm.analyzer import SecurityPlan, AttackStrategy

        cache = LLMCache(cache_dir=str(tmp_path))

        plan = SecurityPlan(
            har_hash="test123",
            domain_analysis={"domain": "e-commerce"},
            strategies=[
                AttackStrategy(attack_type="idor", priority="high")
            ],
            prioritized_endpoints=[],
            custom_regex_patterns=[],
            business_logic_flows=[],
            metadata={}
        )

        cache.set("test123", plan)
        retrieved = cache.get("test123")

        assert retrieved is not None
        assert retrieved.har_hash == "test123"
        assert len(retrieved.strategies) == 1

    def test_get_nonexistent(self, tmp_path):
        from modules.llm.cache import LLMCache

        cache = LLMCache(cache_dir=str(tmp_path))
        result = cache.get("nonexistent")
        assert result is None

    def test_invalidate(self, tmp_path):
        from modules.llm.cache import LLMCache
        from modules.llm.analyzer import SecurityPlan

        cache = LLMCache(cache_dir=str(tmp_path))
        plan = SecurityPlan(
            har_hash="todelete",
            domain_analysis={},
            strategies=[],
            prioritized_endpoints=[],
            custom_regex_patterns=[],
            business_logic_flows=[],
            metadata={}
        )

        cache.set("todelete", plan)
        cache.invalidate("todelete")
        assert cache.get("todelete") is None

    def test_clear(self, tmp_path):
        from modules.llm.cache import LLMCache
        from modules.llm.analyzer import SecurityPlan

        cache = LLMCache(cache_dir=str(tmp_path))

        for i in range(3):
            plan = SecurityPlan(
                har_hash=f"hash{i}",
                domain_analysis={},
                strategies=[],
                prioritized_endpoints=[],
                custom_regex_patterns=[],
                business_logic_flows=[],
                metadata={}
            )
            cache.set(f"hash{i}", plan)

        cache.clear()
        for i in range(3):
            assert cache.get(f"hash{i}") is None


class TestSecurityPlan:
    """Test SecurityPlan dataclass"""

    def test_get_strategy(self):
        from modules.llm.analyzer import SecurityPlan, AttackStrategy

        plan = SecurityPlan(
            har_hash="test",
            domain_analysis={},
            strategies=[
                AttackStrategy(attack_type="idor", priority="high"),
                AttackStrategy(attack_type="mass_assignment", priority="medium")
            ],
            prioritized_endpoints=[],
            custom_regex_patterns=[],
            business_logic_flows=[],
            metadata={}
        )

        idor = plan.get_strategy("idor")
        assert idor is not None
        assert idor.priority == "high"

        mass = plan.get_strategy("mass_assignment")
        assert mass is not None

        none_strategy = plan.get_strategy("nonexistent")
        assert none_strategy is None

    def test_to_dict(self):
        from modules.llm.analyzer import SecurityPlan, AttackStrategy

        plan = SecurityPlan(
            har_hash="test",
            domain_analysis={"domain": "fintech"},
            strategies=[AttackStrategy(attack_type="race", priority="critical")],
            prioritized_endpoints=[{"endpoint": "/api/transfer", "risk": 0.9}],
            custom_regex_patterns=[],
            business_logic_flows=[],
            metadata={"model": "test"}
        )

        d = plan.to_dict()
        assert d['har_hash'] == 'test'
        assert d['domain_analysis']['domain'] == 'fintech'
        assert len(d['strategies']) == 1


class TestLLMSecurityAnalyzer:
    """Test LLM Security Analyzer"""

    def test_extract_json_from_markdown(self):
        from modules.llm.analyzer import LLMSecurityAnalyzer
        from modules.llm.client import LLMClient, LLMConfig

        with patch.object(LLMClient, '__init__', return_value=None):
            analyzer = LLMSecurityAnalyzer.__new__(LLMSecurityAnalyzer)
            analyzer.client = Mock()
            analyzer.cache = Mock()

            content = '```json\n{"test": "value"}\n```'
            result = analyzer._extract_json(content)
            assert result == {"test": "value"}

    def test_extract_json_raw(self):
        from modules.llm.analyzer import LLMSecurityAnalyzer

        analyzer = LLMSecurityAnalyzer.__new__(LLMSecurityAnalyzer)
        analyzer.client = Mock()
        analyzer.cache = Mock()

        content = '{"raw": "json"}'
        result = analyzer._extract_json(content)
        assert result == {"raw": "json"}

    def test_extract_json_with_text(self):
        from modules.llm.analyzer import LLMSecurityAnalyzer

        analyzer = LLMSecurityAnalyzer.__new__(LLMSecurityAnalyzer)
        analyzer.client = Mock()
        analyzer.cache = Mock()

        content = 'Here is the analysis:\n{"found": true}\nEnd.'
        result = analyzer._extract_json(content)
        assert result == {"found": True}

    def test_extract_json_invalid(self):
        from modules.llm.analyzer import LLMSecurityAnalyzer

        analyzer = LLMSecurityAnalyzer.__new__(LLMSecurityAnalyzer)
        analyzer.client = Mock()
        analyzer.cache = Mock()

        content = 'No JSON here'
        result = analyzer._extract_json(content)
        assert result is None


class TestPromptTemplates:
    """Test prompt templates"""

    def test_list_prompts(self):
        from modules.llm.prompts import list_prompts

        prompts = list_prompts()
        assert 'full_analysis' in prompts
        assert 'mass_assignment' in prompts
        assert 'idor_strategy' in prompts
        assert 'race_condition' in prompts

    def test_get_prompt(self):
        from modules.llm.prompts import get_prompt

        prompt = get_prompt('full_analysis')
        assert prompt is not None
        assert prompt.name == 'full_analysis'
        assert prompt.system is not None
        assert prompt.user is not None

    def test_prompt_render(self):
        from modules.llm.prompts import get_prompt

        prompt = get_prompt('mass_assignment')
        system, user = prompt.render(
            domain="e-commerce",
            json_keys=["price", "quantity"],
            endpoints=["/api/orders"]
        )

        assert "e-commerce" in user
        assert "price" in user
        assert system is not None

    def test_all_prompts_valid(self):
        from modules.llm.prompts import PROMPTS

        for name, prompt in PROMPTS.items():
            assert prompt.name == name
            assert len(prompt.system) > 0
            assert len(prompt.user) > 0


class TestAttackStrategies:
    """Test attack strategy classes"""

    @pytest.fixture
    def sample_plan(self):
        from modules.llm.analyzer import SecurityPlan, AttackStrategy

        return SecurityPlan(
            har_hash="test",
            domain_analysis={"inferred_domain": "e-commerce"},
            strategies=[
                AttackStrategy(
                    attack_type="mass_assignment",
                    priority="high",
                    targets=[{"endpoint": "/api/users", "method": "POST"}],
                    payloads=[{"field": "role", "value": "admin", "reason": "privilege escalation"}],
                    rationale="E-commerce apps often have role fields"
                ),
                AttackStrategy(
                    attack_type="idor",
                    priority="critical",
                    targets=[{"endpoint": "/api/orders/{id}", "method": "GET"}],
                    payloads=[{"pattern": "/api/orders/{id}", "id_type": "numeric_sequential", "strategy": "enumerate"}]
                ),
                AttackStrategy(
                    attack_type="race_condition",
                    priority="high",
                    payloads=[{"name": "coupon_race", "steps_involved": ["/apply", "/checkout"], "concurrent_requests": 10}]
                )
            ],
            prioritized_endpoints=[],
            custom_regex_patterns=[{"name": "credit_card", "regex": r"\d{16}", "severity": "critical"}],
            business_logic_flows=[{"type": "state_skip", "flow": ["/cart", "/checkout"]}],
            metadata={}
        )

    def test_mass_assignment_strategy(self, sample_plan):
        from modules.llm.strategies import MassAssignmentStrategy

        strategy = MassAssignmentStrategy(sample_plan, {})
        assert strategy.is_applicable()
        assert strategy.get_priority() == "high"

        payloads = strategy.get_enriched_payloads()
        assert len(payloads) == 1
        assert payloads[0]['field'] == 'role'

    def test_idor_strategy(self, sample_plan):
        from modules.llm.strategies import IDORStrategy

        strategy = IDORStrategy(sample_plan, {})
        assert strategy.is_applicable()

        payloads = strategy.get_enriched_payloads()
        assert len(payloads) == 1
        assert payloads[0]['id_type'] == 'numeric_sequential'

    def test_race_condition_strategy(self, sample_plan):
        from modules.llm.strategies import RaceConditionStrategy

        strategy = RaceConditionStrategy(sample_plan, {})
        windows = strategy.get_enriched_payloads()
        assert len(windows) == 1
        assert windows[0]['concurrent'] == 10

    def test_passive_regex_strategy(self, sample_plan):
        from modules.llm.strategies import PassiveRegexStrategy

        strategy = PassiveRegexStrategy(sample_plan, {})
        patterns = strategy.get_enriched_payloads()
        assert len(patterns) == 1
        assert patterns[0]['name'] == 'credit_card'

    def test_business_logic_strategy(self, sample_plan):
        from modules.llm.strategies import BusinessLogicStrategy

        strategy = BusinessLogicStrategy(sample_plan, {})
        flows = strategy.get_enriched_payloads()
        assert len(flows) == 1
        assert flows[0]['type'] == 'state_skip'

    def test_strategy_not_applicable(self):
        from modules.llm.analyzer import SecurityPlan
        from modules.llm.strategies import FuzzerVocabularyStrategy

        empty_plan = SecurityPlan(
            har_hash="empty",
            domain_analysis={},
            strategies=[],
            prioritized_endpoints=[],
            custom_regex_patterns=[],
            business_logic_flows=[],
            metadata={}
        )

        strategy = FuzzerVocabularyStrategy(empty_plan, {})
        assert not strategy.is_applicable()


class TestLLMZAPIntegration:
    """Test LLM to ZAP integration"""

    @pytest.fixture
    def sample_plan(self):
        from modules.llm.analyzer import SecurityPlan, AttackStrategy

        return SecurityPlan(
            har_hash="test_integration",
            domain_analysis={
                "inferred_domain": "e-commerce",
                "confidence": 0.85,
                "business_entities": ["user", "order", "product"]
            },
            strategies=[
                AttackStrategy(
                    attack_type="mass_assignment",
                    priority="high",
                    targets=[{"endpoint": "/api/users", "method": "POST"}],
                    payloads=[
                        {"field": "discount_rate", "value": 100, "reason": "price manipulation"},
                        {"field": "is_vip", "value": True, "reason": "privilege escalation"}
                    ]
                ),
                AttackStrategy(
                    attack_type="fuzzer",
                    priority="medium",
                    payloads=[
                        {"key": "promo_code", "values": ["FREEITEM", "DISCOUNT100"]},
                        {"key": "skip_payment", "values": ["true", "1"]}
                    ]
                ),
                AttackStrategy(
                    attack_type="idor",
                    priority="critical",
                    payloads=[
                        {"pattern": "/orders/{id}", "id_type": "numeric_sequential", "strategy": "enumerate", "mutations": ["0", "1", "-1"]}
                    ]
                )
            ],
            prioritized_endpoints=[{"endpoint": "/api/checkout", "risk_score": 0.9}],
            custom_regex_patterns=[{"name": "promo_code", "regex": "PROMO[A-Z0-9]+", "severity": "medium"}],
            business_logic_flows=[{"type": "state_skip", "flow": ["/cart", "/checkout"], "attack": "skip payment"}],
            metadata={}
        )

    def test_domain_enrichment(self, sample_plan):
        from modules.llm.zap_integration import LLMZAPEnricher

        enricher = LLMZAPEnricher(sample_plan, {})

        assert enricher.domain == "e-commerce"
        assert enricher.confidence == 0.85

    def test_get_domain_enrichment(self, sample_plan):
        from modules.llm.zap_integration import LLMZAPEnricher

        enricher = LLMZAPEnricher(sample_plan, {})
        enrichment = enricher.get_domain_enrichment()

        assert enrichment.domain == "e-commerce"
        assert len(enrichment.mass_assignment_payloads) == 2
        assert enrichment.mass_assignment_payloads[0]['field'] == 'discount_rate'

    def test_enrich_zap_payloads(self, sample_plan):
        from modules.llm.zap_integration import LLMZAPEnricher

        enricher = LLMZAPEnricher(sample_plan, {})
        payloads = enricher.enrich_zap_payloads(None)

        assert 'mass_assignment' in payloads
        # Check mass assignment format
        assert any('discount_rate=' in p for p in payloads['mass_assignment'])

    def test_get_passive_scanner_patterns(self, sample_plan):
        from modules.llm.zap_integration import LLMZAPEnricher

        enricher = LLMZAPEnricher(sample_plan, {})
        patterns = enricher.get_passive_scanner_patterns()

        assert len(patterns) == 1
        assert patterns[0]['name'] == 'promo_code'

    def test_get_business_logic_tests(self, sample_plan):
        from modules.llm.zap_integration import LLMZAPEnricher

        enricher = LLMZAPEnricher(sample_plan, {})
        tests = enricher.get_business_logic_tests()

        assert len(tests) == 1
        assert tests[0]['type'] == 'state_skip'

    def test_export_wordlists(self, sample_plan, tmp_path):
        from modules.llm.zap_integration import LLMZAPEnricher

        enricher = LLMZAPEnricher(sample_plan, {})
        exported = enricher.export_wordlists(str(tmp_path))

        assert 'mass_assignment' in exported

        # Verify files exist
        import os
        for path in exported.values():
            assert os.path.exists(path)

    def test_enrich_dictionary_manager(self, sample_plan, tmp_path):
        from modules.llm.zap_integration import LLMZAPEnricher
        from modules.dictionary_manager import DictionaryManager

        dict_manager = DictionaryManager(base_dict_path=str(tmp_path))

        enricher = LLMZAPEnricher(sample_plan, {})
        counts = enricher.enrich_dictionary_manager(dict_manager)

        assert counts.get('mass_assignment', 0) == 2

        # Verify dictionary was saved
        loaded = dict_manager.load_dictionary('mass_assignment')
        assert loaded is not None
        assert 'discount_rate' in loaded['keys']


class TestPatternStore:
    """Test session-based pattern persistence."""

    @pytest.fixture
    def store(self, tmp_path):
        from modules.llm.pattern_store import PatternStore
        return PatternStore(base_path=str(tmp_path / 'patterns'))

    def test_init_creates_directories(self, store):
        assert store.sessions_path.exists()
        assert store.merged_path.exists()
        assert (store.zap_export_path / 'fuzzers').exists()
        assert (store.zap_export_path / 'custom_payloads').exists()

    def test_create_session(self, store):
        session = store.create_session(
            domain="e-commerce",
            har_hash="abc123",
            confidence=0.85
        )

        assert session.domain == "e-commerce"
        assert session.har_hash == "abc123"
        assert session.confidence == 0.85
        assert "e-commerce" in session.session_id

        # Session directory created
        session_dir = store.sessions_path / session.session_id
        assert session_dir.exists()
        assert (session_dir / 'session.json').exists()

    def test_list_sessions(self, store):
        store.create_session("domain1", "hash1", 0.8)
        store.create_session("domain2", "hash2", 0.9)

        sessions = store.list_sessions()
        assert len(sessions) == 2
        # Sorted by newest first
        assert sessions[0]['domain'] == 'domain2'

    def test_get_session(self, store):
        created = store.create_session("test", "hash123", 0.75)

        loaded = store.get_session(created.session_id)
        assert loaded is not None
        assert loaded.domain == "test"
        assert loaded.har_hash == "hash123"

    def test_get_current_session(self, store):
        store.create_session("old", "hash1", 0.5)
        latest = store.create_session("latest", "hash2", 0.9)

        current = store.get_current_session()
        assert current.session_id == latest.session_id

    def test_add_patterns(self, store):
        session = store.create_session("test", "hash", 0.8)

        patterns = [
            {"field": "is_admin", "value": True, "reason": "privilege escalation"},
            {"field": "discount", "value": 100, "reason": "price manipulation"}
        ]
        added = store.add_patterns(session.session_id, "mass_assignment", patterns)

        assert added == 2

        # Verify patterns saved
        loaded = store.get_patterns(session.session_id, "mass_assignment")
        assert len(loaded) == 2
        assert loaded[0]['field'] == 'is_admin'

    def test_add_patterns_merge(self, store):
        session = store.create_session("test", "hash", 0.8)

        # First batch
        store.add_patterns(session.session_id, "mass_assignment", [
            {"field": "is_admin", "value": True}
        ])

        # Second batch with duplicate
        added = store.add_patterns(session.session_id, "mass_assignment", [
            {"field": "is_admin", "value": True},  # duplicate
            {"field": "role", "value": "admin"}    # new
        ])

        assert added == 1  # Only new one added
        loaded = store.get_patterns(session.session_id, "mass_assignment")
        assert len(loaded) == 2

    def test_add_patterns_creates_wordlist(self, store):
        session = store.create_session("test", "hash", 0.8)

        store.add_patterns(session.session_id, "mass_assignment", [
            {"field": "is_admin", "value": True}
        ])

        txt_file = store.sessions_path / session.session_id / "mass_assignment.txt"
        assert txt_file.exists()
        content = txt_file.read_text()
        assert "is_admin=True" in content

    def test_persist_session(self, store):
        session = store.create_session("test", "hash", 0.8)
        store.add_patterns(session.session_id, "mass_assignment", [
            {"field": "test", "value": 1}
        ])

        files = store.persist_session(session.session_id)

        assert "mass_assignment_json" in files
        assert "mass_assignment_txt" in files
        assert "session_metadata" in files

    def test_push_to_zap_export(self, store):
        session = store.create_session("test", "hash", 0.8)
        store.add_patterns(session.session_id, "mass_assignment", [
            {"field": "admin", "value": True}
        ])
        store.add_patterns(session.session_id, "hidden_params", [
            {"name": "debug", "values": ["true", "1"]}
        ])

        exported = store.push_to_zap_export(session.session_id)

        assert "mass_assignment" in exported
        assert (store.zap_export_path / "fuzzers" / "llm_mass_assignment.txt").exists()

    def test_get_zap_mount_paths(self, store):
        paths = store.get_zap_mount_paths()

        assert "fuzzers" in paths
        assert "custom_payloads" in paths
        assert "docker_mount" in paths
        assert "-v" in paths["docker_mount"]

    def test_merge_all_sessions(self, store):
        # Create two sessions with overlapping patterns
        s1 = store.create_session("domain1", "hash1", 0.8)
        store.add_patterns(s1.session_id, "mass_assignment", [
            {"field": "admin", "value": True}
        ])

        s2 = store.create_session("domain2", "hash2", 0.9)
        store.add_patterns(s2.session_id, "mass_assignment", [
            {"field": "admin", "value": True},  # duplicate
            {"field": "role", "value": "super"}  # new
        ])

        counts = store.merge_all_sessions()

        assert counts["mass_assignment"] == 2  # deduplicated
        assert (store.merged_path / "all_mass_assignment.json").exists()

    def test_store_from_enrichment(self, store):
        from modules.llm.zap_integration import DomainEnrichment

        enrichment = DomainEnrichment(
            domain="fintech",
            confidence=0.9,
            mass_assignment_payloads=[
                {"field": "balance", "value": 999999, "reason": "balance manipulation"}
            ],
            hidden_params={"internal": ["true"]},
            idor_strategies=[{"type": "sequential", "mutations": ["1", "2", "3"]}],
            custom_regex=[{"name": "account", "regex": r"\d{10}"}],
            race_windows=[{"endpoint": "/transfer", "window_ms": 100}],
            business_logic_tests=[{"type": "bypass", "flow": ["/auth", "/admin"]}],
            prioritized_endpoints=[{"endpoint": "/transfer", "risk": 0.95}]
        )

        session_id = store.store_from_enrichment(enrichment, "test_hash")

        # Verify all patterns stored
        assert len(store.get_patterns(session_id, "mass_assignment")) == 1
        assert len(store.get_patterns(session_id, "hidden_params")) == 1
        assert len(store.get_patterns(session_id, "idor")) == 1
        assert len(store.get_patterns(session_id, "regex_patterns")) == 1
        assert len(store.get_patterns(session_id, "race_conditions")) == 1
        assert len(store.get_patterns(session_id, "business_logic")) == 1
        assert len(store.get_patterns(session_id, "prioritized_endpoints")) == 1

        # Verify ZAP export pushed
        assert (store.zap_export_path / "fuzzers" / "llm_mass_assignment.txt").exists()

    def test_invalid_pattern_type(self, store):
        session = store.create_session("test", "hash", 0.8)

        with pytest.raises(ValueError, match="Unknown pattern type"):
            store.add_patterns(session.session_id, "invalid_type", [])

    def test_session_not_found(self, store):
        with pytest.raises(ValueError, match="Session not found"):
            store.add_patterns("nonexistent_session", "mass_assignment", [])
