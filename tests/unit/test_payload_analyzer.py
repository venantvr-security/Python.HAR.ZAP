"""Tests for payload analyzer module"""
import pytest
from unittest.mock import Mock


class TestPayloadSchemaClass:
    """Test PayloadSchema dataclass"""

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

    def test_schema_with_frequency(self):
        from modules.payload_analyzer import PayloadSchema

        schema = PayloadSchema(
            endpoint='/api/items',
            method='GET',
            schema={'id': 'int'},
            samples=[],
            frequency=5
        )

        assert schema.frequency == 5


class TestKeyValuePairClass:
    """Test KeyValuePair dataclass"""

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

    def test_pair_with_frequency(self):
        from modules.payload_analyzer import KeyValuePair

        pair = KeyValuePair(
            key='token',
            value='abc123',
            value_type='string',
            endpoint='/api/auth',
            method='POST',
            frequency=10
        )

        assert pair.frequency == 10


class TestTrainerClass:
    """Test Trainer module"""

    @pytest.fixture
    def sample_data(self):
        return {
            'requests': [
                {'url': 'https://api.com/user/1', 'response': 200},
                {'url': 'https://api.com/user/2', 'response': 200},
                {'url': 'https://api.com/admin', 'response': 403}
            ]
        }

    def test_init(self, sample_data):
        from modules.trainer import Trainer

        trainer = Trainer(sample_data)
        assert trainer is not None

    def test_train(self, sample_data):
        from modules.trainer import Trainer

        trainer = Trainer(sample_data)
        if hasattr(trainer, 'train'):
            trainer.train()


class TestHARPreprocessor:
    """Test HAR preprocessor module"""

    @pytest.fixture
    def sample_har(self):
        return {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://api.example.com/users?id=123",
                            "headers": [{"name": "Accept", "value": "application/json"}]
                        },
                        "response": {"status": 200, "content": {"text": "{}"}}
                    }
                ]
            }
        }

    def test_init(self, sample_har):
        from modules.har_preprocessor import HARPreprocessor

        preprocessor = HARPreprocessor(har_data=sample_har)
        assert preprocessor.har_data == sample_har

    def test_process(self, sample_har):
        from modules.har_preprocessor import HARPreprocessor

        preprocessor = HARPreprocessor(har_data=sample_har)
        result = preprocessor.process()

        assert result is not None

    def test_set_filters(self, sample_har):
        from modules.har_preprocessor import HARPreprocessor

        preprocessor = HARPreprocessor(har_data=sample_har)
        result = preprocessor.set_filters(include_domains=['api.example.com'])

        assert result == preprocessor  # Returns self for chaining


class TestMetaAnalyzerExtended:
    """Extended tests for MetaAnalyzer"""

    @pytest.fixture
    def sample_alerts(self):
        return [
            {'alert': 'SQL Injection', 'risk': 'High', 'url': 'https://api.com/users?id=1',
             'param': 'id', 'pluginId': '40018'},
            {'alert': 'XSS', 'risk': 'Medium', 'url': 'https://api.com/search?q=test',
             'param': 'q', 'pluginId': '40012'}
        ]

    def test_find_uniform_vulnerabilities(self, sample_alerts):
        from modules.meta_analyzer import MetaAnalyzer

        analyzer = MetaAnalyzer(sample_alerts)
        result = analyzer.find_uniform_vulnerabilities()
        assert isinstance(result, dict)

    def test_aggregate_by_severity(self, sample_alerts):
        from modules.meta_analyzer import MetaAnalyzer

        analyzer = MetaAnalyzer(sample_alerts)
        result = analyzer.aggregate_by_severity()
        assert isinstance(result, dict)

    def test_aggregate_by_endpoint(self, sample_alerts):
        from modules.meta_analyzer import MetaAnalyzer

        analyzer = MetaAnalyzer(sample_alerts)
        result = analyzer.aggregate_by_endpoint()
        assert isinstance(result, dict)

    def test_deduplicate_alerts(self, sample_alerts):
        from modules.meta_analyzer import MetaAnalyzer

        analyzer = MetaAnalyzer(sample_alerts)
        result = analyzer.deduplicate_alerts()
        assert isinstance(result, list)

    def test_generate_meta_report(self, sample_alerts):
        from modules.meta_analyzer import MetaAnalyzer

        analyzer = MetaAnalyzer(sample_alerts)
        result = analyzer.generate_meta_report()
        assert isinstance(result, dict)
