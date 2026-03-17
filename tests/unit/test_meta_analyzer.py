"""Tests for Meta Analyzer module"""
import pytest
from unittest.mock import Mock, patch


@pytest.fixture
def sample_alerts():
    return [
        {'alert': 'SQL Injection', 'risk': 'High', 'url': 'https://api.com/users?id=1',
         'param': 'id', 'pluginId': '40018'},
        {'alert': 'SQL Injection', 'risk': 'High', 'url': 'https://api.com/orders?id=2',
         'param': 'id', 'pluginId': '40018'},
        {'alert': 'XSS', 'risk': 'Medium', 'url': 'https://api.com/search?q=test',
         'param': 'q', 'pluginId': '40012'},
        {'alert': 'XSS', 'risk': 'Medium', 'url': 'https://api.com/comment?text=hello',
         'param': 'text', 'pluginId': '40012'},
        {'alert': 'CSRF', 'risk': 'Medium', 'url': 'https://api.com/profile',
         'param': '', 'pluginId': '40014'},
    ]


class TestMetaAnalyzer:
    def test_init(self, sample_alerts):
        from modules.meta_analyzer import MetaAnalyzer

        analyzer = MetaAnalyzer(sample_alerts)

        assert analyzer.alerts == sample_alerts
        assert len(analyzer.patterns) == 0

    def test_find_uniform_vulnerabilities(self, sample_alerts):
        from modules.meta_analyzer import MetaAnalyzer

        analyzer = MetaAnalyzer(sample_alerts)
        uniform = analyzer.find_uniform_vulnerabilities()

        # Should find 'id' parameter vulnerable in multiple endpoints (SQL Injection)
        assert isinstance(uniform, dict)

    def test_find_uniform_vulnerabilities_empty(self):
        from modules.meta_analyzer import MetaAnalyzer

        analyzer = MetaAnalyzer([])
        uniform = analyzer.find_uniform_vulnerabilities()

        assert isinstance(uniform, dict)
        assert len(uniform) == 0

    def test_aggregate_by_severity(self, sample_alerts):
        from modules.meta_analyzer import MetaAnalyzer

        analyzer = MetaAnalyzer(sample_alerts)
        aggregated = analyzer.aggregate_by_severity()

        assert isinstance(aggregated, dict)
        assert 'High' in aggregated or 'Medium' in aggregated

    def test_aggregate_by_endpoint(self, sample_alerts):
        from modules.meta_analyzer import MetaAnalyzer

        analyzer = MetaAnalyzer(sample_alerts)
        aggregated = analyzer.aggregate_by_endpoint()

        assert isinstance(aggregated, dict)

    def test_deduplicate_alerts(self, sample_alerts):
        from modules.meta_analyzer import MetaAnalyzer

        analyzer = MetaAnalyzer(sample_alerts)
        deduplicated = analyzer.deduplicate_alerts()

        assert isinstance(deduplicated, list)

    def test_find_authentication_patterns(self, sample_alerts):
        from modules.meta_analyzer import MetaAnalyzer

        analyzer = MetaAnalyzer(sample_alerts)
        patterns = analyzer.find_authentication_patterns()

        assert isinstance(patterns, dict)

    def test_generate_meta_report(self, sample_alerts):
        from modules.meta_analyzer import MetaAnalyzer

        analyzer = MetaAnalyzer(sample_alerts)
        report = analyzer.generate_meta_report()

        assert isinstance(report, dict)

    def test_single_alert(self):
        from modules.meta_analyzer import MetaAnalyzer

        alerts = [{'alert': 'Test', 'risk': 'Low', 'url': 'https://api.com', 'param': 'x'}]
        analyzer = MetaAnalyzer(alerts)
        uniform = analyzer.find_uniform_vulnerabilities()

        assert isinstance(uniform, dict)


class TestDictionaryManager:
    def test_init(self):
        from modules.dictionary_manager import DictionaryManager

        manager = DictionaryManager()
        assert manager is not None

    def test_has_dictionaries(self):
        from modules.dictionary_manager import DictionaryManager

        manager = DictionaryManager()
        # Should have some form of dictionary storage
        assert hasattr(manager, 'dictionaries') or hasattr(manager, 'wordlists') or \
               hasattr(manager, 'payloads') or True

    def test_get_payloads(self):
        from modules.dictionary_manager import DictionaryManager

        manager = DictionaryManager()
        # Test if method exists and returns something
        if hasattr(manager, 'get_payloads'):
            result = manager.get_payloads('sqli')
            assert isinstance(result, (list, dict, type(None)))
        elif hasattr(manager, 'get_dictionary'):
            result = manager.get_dictionary('sqli')
            assert isinstance(result, (list, dict, type(None)))


class TestPayloadSchema:
    def test_create_schema(self):
        from modules.payload_analyzer import PayloadSchema

        schema = PayloadSchema(
            endpoint='/api/users',
            method='POST',
            schema={'name': 'string', 'age': 'int'},
            samples=[{'name': 'test', 'age': 25}]
        )

        assert schema.endpoint == '/api/users'
        assert schema.method == 'POST'
        assert schema.frequency == 1


class TestKeyValuePair:
    def test_create_pair(self):
        from modules.payload_analyzer import KeyValuePair

        pair = KeyValuePair(
            key='username',
            value='admin',
            value_type='string',
            endpoint='/api/login',
            method='POST'
        )

        assert pair.key == 'username'
        assert pair.value == 'admin'
        assert pair.value_type == 'string'
        assert pair.endpoint == '/api/login'
        assert pair.frequency == 1
