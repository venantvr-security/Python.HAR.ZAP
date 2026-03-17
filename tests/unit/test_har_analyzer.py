"""Tests for HAR analyzer module"""
import json
import os
import pytest
from unittest.mock import patch, MagicMock

from modules.har_analyzer import HARAnalyzer


@pytest.fixture
def sample_har_data():
    return {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/users/123?id=456",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer token123"},
                            {"name": "Content-Type", "value": "application/json"}
                        ]
                    },
                    "response": {"status": 200}
                },
                {
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.com/api/login",
                        "headers": [
                            {"name": "Content-Type", "value": "application/json"},
                            {"name": "X-Auth-Token", "value": "secret"}
                        ],
                        "postData": {
                            "mimeType": "application/json",
                            "text": '{"user_id": 123, "admin": true}'
                        }
                    },
                    "response": {"status": 200}
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://cdn.example.com/image.png",
                        "headers": []
                    },
                    "response": {"status": 200}
                }
            ]
        }
    }


@pytest.fixture
def config():
    return {
        'scope_domains': [],
        'exclude_domains': ['google-analytics.com'],
        'allowed_methods': ['GET', 'POST', 'PUT', 'DELETE']
    }


class TestHARAnalyzer:
    """Test HAR analysis functionality"""

    def test_init(self, config):
        analyzer = HARAnalyzer('/path/to/har', config)
        assert analyzer.har_path == '/path/to/har'
        assert analyzer.config == config

    def test_load_har(self, sample_har_data, config, tmp_path):
        har_file = tmp_path / "test.har"
        har_file.write_text(json.dumps(sample_har_data))

        analyzer = HARAnalyzer(str(har_file), config)
        loaded = analyzer.load_har()

        assert 'log' in loaded
        assert len(loaded['log']['entries']) == 3

    def test_load_har_file_too_large(self, config, tmp_path):
        har_file = tmp_path / "large.har"
        har_file.write_text('x' * (HARAnalyzer.MAX_FILE_SIZE + 1))

        analyzer = HARAnalyzer(str(har_file), config)

        with pytest.raises(ValueError, match="exceeds the limit"):
            analyzer.load_har()

    def test_analyze_extracts_urls(self, sample_har_data, config, tmp_path):
        har_file = tmp_path / "test.har"
        har_file.write_text(json.dumps(sample_har_data))

        analyzer = HARAnalyzer(str(har_file), config)
        result = analyzer.analyze()

        assert 'https://api.example.com/users/123?id=456' in result['urls']
        assert 'https://api.example.com/api/login' in result['urls']

    def test_analyze_filters_static_resources(self, sample_har_data, config, tmp_path):
        har_file = tmp_path / "test.har"
        har_file.write_text(json.dumps(sample_har_data))

        analyzer = HARAnalyzer(str(har_file), config)
        result = analyzer.analyze()

        # Static resource should be filtered
        assert 'https://cdn.example.com/image.png' not in result['urls']

    def test_analyze_detects_api_endpoints(self, sample_har_data, config, tmp_path):
        har_file = tmp_path / "test.har"
        har_file.write_text(json.dumps(sample_har_data))

        analyzer = HARAnalyzer(str(har_file), config)
        result = analyzer.analyze()

        api_urls = [ep['url'] for ep in result['api_endpoints']]
        assert 'https://api.example.com/api/login' in api_urls

    def test_analyze_extracts_fuzzable_params(self, sample_har_data, config, tmp_path):
        har_file = tmp_path / "test.har"
        har_file.write_text(json.dumps(sample_har_data))

        analyzer = HARAnalyzer(str(har_file), config)
        result = analyzer.analyze()

        # 'id' is a suspicious param
        fuzzable = result['fuzzable_urls']
        assert len(fuzzable) > 0

    def test_analyze_extracts_auth_headers(self, sample_har_data, config, tmp_path):
        har_file = tmp_path / "test.har"
        har_file.write_text(json.dumps(sample_har_data))

        analyzer = HARAnalyzer(str(har_file), config)
        result = analyzer.analyze()

        assert 'Authorization' in result['auth_headers']
        assert 'X-Auth-Token' in result['auth_headers']

    def test_analyze_extracts_domains(self, sample_har_data, config, tmp_path):
        har_file = tmp_path / "test.har"
        har_file.write_text(json.dumps(sample_har_data))

        analyzer = HARAnalyzer(str(har_file), config)
        result = analyzer.analyze()

        assert 'api.example.com' in result['domains']
        assert 'cdn.example.com' in result['domains']

    def test_should_process_scope_filter(self, config):
        config['scope_domains'] = ['target.com']
        analyzer = HARAnalyzer('/path', config)

        request_in_scope = {'url': 'https://target.com/api', 'method': 'GET'}
        request_out_scope = {'url': 'https://other.com/api', 'method': 'GET'}

        assert analyzer._should_process(request_in_scope) is True
        assert analyzer._should_process(request_out_scope) is False

    def test_should_process_exclude_filter(self, config):
        config['exclude_domains'] = ['analytics.com']
        analyzer = HARAnalyzer('/path', config)

        request = {'url': 'https://analytics.com/track', 'method': 'GET'}
        assert analyzer._should_process(request) is False

    def test_should_process_method_filter(self, config):
        config['allowed_methods'] = ['GET', 'POST']
        analyzer = HARAnalyzer('/path', config)

        get_request = {'url': 'https://api.com', 'method': 'GET'}
        delete_request = {'url': 'https://api.com', 'method': 'DELETE'}

        assert analyzer._should_process(get_request) is True
        assert analyzer._should_process(delete_request) is False

    def test_is_static_resource(self, config):
        analyzer = HARAnalyzer('/path', config)

        assert analyzer._is_static_resource('https://cdn.com/image.png') is True
        assert analyzer._is_static_resource('https://cdn.com/style.css') is True
        assert analyzer._is_static_resource('https://api.com/users') is False

    def test_is_api_endpoint_json(self, config):
        headers = {'Content-Type': 'application/json'}
        assert HARAnalyzer._is_api_endpoint('https://api.com/data', headers) is True

    def test_is_api_endpoint_url_pattern(self, config):
        headers = {}
        assert HARAnalyzer._is_api_endpoint('https://site.com/api/v1/users', headers) is True
        assert HARAnalyzer._is_api_endpoint('https://site.com/page', headers) is False

    def test_is_suspicious_param(self, config):
        analyzer = HARAnalyzer('/path', config)

        assert analyzer._is_suspicious_param('user_id') is True
        assert analyzer._is_suspicious_param('id') is True
        assert analyzer._is_suspicious_param('admin') is True
        assert analyzer._is_suspicious_param('name') is False

    def test_extract_fuzzable_params_query(self, config):
        analyzer = HARAnalyzer('/path', config)
        request = {
            'url': 'https://api.com/users?id=123&name=john',
            'method': 'GET'
        }

        params = analyzer._extract_fuzzable_params(request)
        assert 'id' in params
        assert 'name' not in params

    def test_extract_fuzzable_params_json_body(self, config):
        analyzer = HARAnalyzer('/path', config)
        request = {
            'url': 'https://api.com/users',
            'method': 'POST',
            'postData': {
                'text': '{"user_id": 123, "email": "test@test.com"}'
            }
        }

        params = analyzer._extract_fuzzable_params(request)
        assert 'body.user_id' in params

    def test_extract_fuzzable_params_form_body(self, config):
        analyzer = HARAnalyzer('/path', config)
        request = {
            'url': 'https://api.com/users',
            'method': 'POST',
            'postData': {
                'text': 'user_id=123&email=test@test.com'
            }
        }

        params = analyzer._extract_fuzzable_params(request)
        assert 'form.user_id' in params

    def test_get_request_body(self, config):
        request_with_body = {
            'postData': {'text': '{"key": "value"}'}
        }
        request_without_body = {}

        assert HARAnalyzer._get_request_body(request_with_body) == '{"key": "value"}'
        assert HARAnalyzer._get_request_body(request_without_body) is None

    def test_extract_auth(self, config):
        headers = {
            'Authorization': 'Bearer token',
            'Cookie': 'session=abc',
            'X-API-Token': 'secret',
            'Content-Type': 'application/json'
        }

        auth = HARAnalyzer._extract_auth(headers)

        assert 'Authorization' in auth
        assert 'Cookie' in auth
        assert 'X-API-Token' in auth
        assert 'Content-Type' not in auth

    def test_get_summary(self, sample_har_data, config, tmp_path):
        har_file = tmp_path / "test.har"
        har_file.write_text(json.dumps(sample_har_data))

        analyzer = HARAnalyzer(str(har_file), config)
        analyzer.analyze()
        summary = analyzer.get_summary()

        assert 'Total URLs' in summary
        assert 'API Endpoints' in summary
        assert 'Domains' in summary

    def test_max_entries_truncation(self, config, tmp_path):
        # Create HAR with many entries
        entries = [
            {
                "request": {"method": "GET", "url": f"https://api.com/{i}", "headers": []},
                "response": {"status": 200}
            }
            for i in range(100)
        ]
        har_data = {"log": {"entries": entries}}

        har_file = tmp_path / "large.har"
        har_file.write_text(json.dumps(har_data))

        analyzer = HARAnalyzer(str(har_file), config)

        # Temporarily lower max entries
        original_max = HARAnalyzer.MAX_ENTRIES
        HARAnalyzer.MAX_ENTRIES = 50

        try:
            analyzer.analyze()
            assert len(analyzer.entries) == 50
        finally:
            HARAnalyzer.MAX_ENTRIES = original_max

    def test_token_extraction_integration(self, sample_har_data, config, tmp_path):
        har_file = tmp_path / "test.har"
        har_file.write_text(json.dumps(sample_har_data))

        analyzer = HARAnalyzer(str(har_file), config)
        result = analyzer.analyze()

        assert 'extracted_tokens' in result
        assert 'fuzzing_recommendations' in result
