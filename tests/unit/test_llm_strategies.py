"""Tests for LLM attack strategies."""
import pytest
from modules.llm.analyzer import SecurityPlan, AttackStrategy


@pytest.fixture
def security_plan_with_fuzzer():
    """Plan with fuzzer strategy."""
    return SecurityPlan(
        har_hash="test",
        domain_analysis={"domain": "ecommerce"},
        strategies=[
            AttackStrategy(
                attack_type="fuzzer",
                priority="high",
                targets=[{"endpoint": "/api/products", "params": ["search", "filter"]}],
                payloads=[
                    {"key": "search", "values": ["admin", "test"], "category": "admin"},
                    {"key": "filter", "values": ["all", "none"], "category": "custom"}
                ],
                rationale="API has searchable fields",
                test_plan=["Test search param", "Test filter param"]
            )
        ],
        prioritized_endpoints=[],
        custom_regex_patterns=[],
        business_logic_flows=[],
        metadata={}
    )


@pytest.fixture
def security_plan_with_idor():
    """Plan with IDOR strategy."""
    return SecurityPlan(
        har_hash="test",
        domain_analysis={"domain": "api"},
        strategies=[
            AttackStrategy(
                attack_type="idor",
                priority="critical",
                targets=[
                    {"endpoint": "/users/{id}", "id_param": "id", "id_type": "numeric"}
                ],
                payloads=[],
                rationale="Numeric IDs detected",
                test_plan=["Enumerate user IDs"]
            )
        ],
        prioritized_endpoints=[],
        custom_regex_patterns=[],
        business_logic_flows=[],
        metadata={}
    )


class TestFuzzerVocabularyStrategy:
    """Test fuzzer vocabulary strategy."""

    def test_get_enriched_payloads(self, security_plan_with_fuzzer):
        from modules.llm.strategies.fuzzer_strategy import FuzzerVocabularyStrategy

        strategy = FuzzerVocabularyStrategy(security_plan_with_fuzzer)
        payloads = strategy.get_enriched_payloads()

        assert len(payloads) == 2
        assert payloads[0]['key'] == 'search'
        assert 'admin' in payloads[0]['values']

    def test_get_targets(self, security_plan_with_fuzzer):
        from modules.llm.strategies.fuzzer_strategy import FuzzerVocabularyStrategy

        strategy = FuzzerVocabularyStrategy(security_plan_with_fuzzer)
        targets = strategy.get_targets()

        assert len(targets) == 1
        assert targets[0]['endpoint'] == '/api/products'

    def test_get_vocabulary_by_category(self, security_plan_with_fuzzer):
        from modules.llm.strategies.fuzzer_strategy import FuzzerVocabularyStrategy

        strategy = FuzzerVocabularyStrategy(security_plan_with_fuzzer)
        admin_vocab = strategy.get_vocabulary_by_category('admin')

        assert len(admin_vocab) == 1
        assert admin_vocab[0]['key'] == 'search'

    def test_get_all_keys(self, security_plan_with_fuzzer):
        from modules.llm.strategies.fuzzer_strategy import FuzzerVocabularyStrategy

        strategy = FuzzerVocabularyStrategy(security_plan_with_fuzzer)
        keys = strategy.get_all_keys()

        assert 'search' in keys
        assert 'filter' in keys

    def test_get_values_for_key(self, security_plan_with_fuzzer):
        from modules.llm.strategies.fuzzer_strategy import FuzzerVocabularyStrategy

        strategy = FuzzerVocabularyStrategy(security_plan_with_fuzzer)
        values = strategy.get_values_for_key('search')

        assert 'admin' in values
        assert 'test' in values

    def test_to_wordlist(self, security_plan_with_fuzzer):
        from modules.llm.strategies.fuzzer_strategy import FuzzerVocabularyStrategy

        strategy = FuzzerVocabularyStrategy(security_plan_with_fuzzer)
        wordlist = strategy.to_wordlist()

        assert 'search' in wordlist
        assert 'filter' in wordlist
        assert len(wordlist['search']) == 2

    def test_is_applicable(self, security_plan_with_fuzzer):
        from modules.llm.strategies.fuzzer_strategy import FuzzerVocabularyStrategy

        strategy = FuzzerVocabularyStrategy(security_plan_with_fuzzer)
        assert strategy.is_applicable() is True

    def test_get_priority(self, security_plan_with_fuzzer):
        from modules.llm.strategies.fuzzer_strategy import FuzzerVocabularyStrategy

        strategy = FuzzerVocabularyStrategy(security_plan_with_fuzzer)
        assert strategy.get_priority() == "high"

    def test_get_rationale(self, security_plan_with_fuzzer):
        from modules.llm.strategies.fuzzer_strategy import FuzzerVocabularyStrategy

        strategy = FuzzerVocabularyStrategy(security_plan_with_fuzzer)
        assert "searchable" in strategy.get_rationale()

    def test_get_test_plan(self, security_plan_with_fuzzer):
        from modules.llm.strategies.fuzzer_strategy import FuzzerVocabularyStrategy

        strategy = FuzzerVocabularyStrategy(security_plan_with_fuzzer)
        plan = strategy.get_test_plan()
        assert len(plan) == 2


class TestIDORStrategy:
    """Test IDOR strategy."""

    def test_get_targets(self, security_plan_with_idor):
        from modules.llm.strategies.idor_strategy import IDORStrategy

        strategy = IDORStrategy(security_plan_with_idor)
        targets = strategy.get_targets()

        assert len(targets) == 1
        assert '/users/{id}' in targets[0]['endpoint']

    def test_get_enriched_payloads(self, security_plan_with_idor):
        from modules.llm.strategies.idor_strategy import IDORStrategy

        strategy = IDORStrategy(security_plan_with_idor)
        payloads = strategy.get_enriched_payloads()
        # Should return targets as payloads
        assert isinstance(payloads, list)


class TestMassAssignmentStrategy:
    """Test mass assignment strategy."""

    def test_get_enriched_payloads(self):
        from modules.llm.strategies.mass_assignment import MassAssignmentStrategy

        plan = SecurityPlan(
            har_hash="test",
            domain_analysis={},
            strategies=[
                AttackStrategy(
                    attack_type="mass_assignment",
                    priority="high",
                    targets=[{"endpoint": "/users", "fields": ["role", "admin", "is_active"]}],
                    payloads=[{"field": "role", "test_values": ["admin", "superuser"]}]
                )
            ],
            prioritized_endpoints=[],
            custom_regex_patterns=[],
            business_logic_flows=[],
            metadata={}
        )

        strategy = MassAssignmentStrategy(plan)
        payloads = strategy.get_enriched_payloads()
        assert isinstance(payloads, list)

    def test_get_targets(self):
        from modules.llm.strategies.mass_assignment import MassAssignmentStrategy

        plan = SecurityPlan(
            har_hash="test",
            domain_analysis={},
            strategies=[
                AttackStrategy(
                    attack_type="mass_assignment",
                    priority="high",
                    targets=[{"endpoint": "/users", "fields": ["role"]}]
                )
            ],
            prioritized_endpoints=[],
            custom_regex_patterns=[],
            business_logic_flows=[],
            metadata={}
        )

        strategy = MassAssignmentStrategy(plan)
        targets = strategy.get_targets()
        assert len(targets) == 1

class TestRaceConditionStrategy:
    """Test race condition strategy."""

    def test_get_targets(self):
        from modules.llm.strategies.race_condition import RaceConditionStrategy

        plan = SecurityPlan(
            har_hash="test",
            domain_analysis={},
            strategies=[
                AttackStrategy(
                    attack_type="race_condition",
                    priority="medium",
                    targets=[{"endpoint": "/transfer", "window_ms": 100}]
                )
            ],
            prioritized_endpoints=[],
            custom_regex_patterns=[],
            business_logic_flows=[],
            metadata={}
        )

        strategy = RaceConditionStrategy(plan)
        targets = strategy.get_targets()
        assert len(targets) == 1

    def test_get_enriched_payloads(self):
        from modules.llm.strategies.race_condition import RaceConditionStrategy

        plan = SecurityPlan(
            har_hash="test",
            domain_analysis={},
            strategies=[
                AttackStrategy(
                    attack_type="race_condition",
                    priority="medium",
                    targets=[{"endpoint": "/transfer", "window_ms": 100}]
                )
            ],
            prioritized_endpoints=[],
            custom_regex_patterns=[],
            business_logic_flows=[],
            metadata={}
        )

        strategy = RaceConditionStrategy(plan)
        payloads = strategy.get_enriched_payloads()
        assert isinstance(payloads, list)


class TestBaseStrategy:
    """Test base strategy."""

    def test_no_strategy(self):
        from modules.llm.strategies.base import BaseAttackStrategy

        plan = SecurityPlan(
            har_hash="test",
            domain_analysis={},
            strategies=[],
            prioritized_endpoints=[],
            custom_regex_patterns=[],
            business_logic_flows=[],
            metadata={}
        )

        # Create concrete implementation for testing
        class TestStrategy(BaseAttackStrategy):
            ATTACK_TYPE = "test"

            def get_enriched_payloads(self):
                return []

            def get_targets(self):
                return []

        strategy = TestStrategy(plan)
        assert strategy.strategy is None
        assert strategy.get_priority() == "low"
        assert strategy.get_rationale() == ""
        assert strategy.get_test_plan() == []
        assert strategy.is_applicable() is False
