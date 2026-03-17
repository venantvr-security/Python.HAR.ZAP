"""Tests for ZAP Fuzzer module"""
import sys
import pytest
from unittest.mock import Mock, patch, MagicMock

# Mock zapv2 before import
mock_zapv2_module = MagicMock()
sys.modules['zapv2'] = mock_zapv2_module


class TestZAPFuzzer:
    """Test ZAP fuzzer functionality"""

    @pytest.fixture
    def mock_zap(self):
        zap = Mock()
        zap.fuzzer.add_fuzzer.return_value = 'fuzzer-123'
        zap.fuzzer.status.return_value = {'state': 'FINISHED', 'progress': 100}
        zap.fuzzer.messages.return_value = []
        return zap

    @pytest.fixture
    def wordlists(self):
        return {
            'ids': ['1', '2', '3', '100', '999'],
            'usernames': ['admin', 'user', 'test', 'guest'],
            'sqli': ["'", "' OR 1=1--", "' AND 1=1--"]
        }

    @pytest.fixture
    def config(self):
        return {
            'max_workers': 2,
            'max_payloads': 50,
            'fuzzer_timeout': 60,
            'idor_threshold': 0.1,
            'rate_limit': 10.0
        }

    def test_init(self, mock_zap, wordlists, config):
        from modules.zap_fuzzer import ZAPFuzzer

        fuzzer = ZAPFuzzer(mock_zap, wordlists, config)

        assert fuzzer.zap == mock_zap
        assert fuzzer.wordlists == wordlists
        assert fuzzer.max_workers == 2
        assert fuzzer.max_payloads == 50

    def test_init_defaults(self, mock_zap, wordlists):
        from modules.zap_fuzzer import ZAPFuzzer

        fuzzer = ZAPFuzzer(mock_zap, wordlists)

        assert fuzzer.max_workers == 5
        assert fuzzer.max_payloads == 200

    def test_fuzz_idor_endpoints_no_ids(self, mock_zap, config):
        from modules.zap_fuzzer import ZAPFuzzer

        fuzzer = ZAPFuzzer(mock_zap, {}, config)
        results = fuzzer.fuzz_idor_endpoints([{'url': 'https://api.com/user/1', 'params': ['id']}])

        assert results == []

    @patch('modules.zap_fuzzer.time.sleep')
    def test_fuzz_idor_endpoints(self, mock_sleep, mock_zap, wordlists, config):
        from modules.zap_fuzzer import ZAPFuzzer

        mock_zap.fuzzer.messages.return_value = [
            {'responseHeader': {'statusCode': 200}, 'responseBody': 'data1'},
            {'responseHeader': {'statusCode': 200}, 'responseBody': 'data2'},
        ]

        fuzzer = ZAPFuzzer(mock_zap, wordlists, config)
        endpoints = [{'url': 'https://api.com/user/1', 'params': ['user_id']}]
        results = fuzzer.fuzz_idor_endpoints(endpoints)

        assert mock_zap.fuzzer.add_fuzzer.called

    def test_fuzz_authentication_no_usernames(self, mock_zap, config):
        from modules.zap_fuzzer import ZAPFuzzer

        fuzzer = ZAPFuzzer(mock_zap, {'ids': ['1', '2']}, config)
        results = fuzzer.fuzz_authentication([{'url': 'https://api.com/login', 'params': ['username']}])

        assert results == []

    @patch('modules.zap_fuzzer.time.sleep')
    def test_fuzz_authentication(self, mock_sleep, mock_zap, wordlists, config):
        from modules.zap_fuzzer import ZAPFuzzer

        fuzzer = ZAPFuzzer(mock_zap, wordlists, config)
        endpoints = [{'url': 'https://api.com/login', 'params': ['username', 'password']}]
        results = fuzzer.fuzz_authentication(endpoints)

        assert mock_zap.fuzzer.add_fuzzer.called

    @patch('modules.zap_fuzzer.time.sleep')
    def test_fuzz_custom_params(self, mock_sleep, mock_zap, wordlists, config):
        from modules.zap_fuzzer import ZAPFuzzer

        mock_zap.fuzzer.messages.return_value = [
            {'responseHeader': {'statusCode': 200}, 'responseBody': 'a'},
            {'responseHeader': {'statusCode': 500}, 'responseBody': 'error'},
        ]

        fuzzer = ZAPFuzzer(mock_zap, wordlists, config)
        result = fuzzer.fuzz_custom_params(
            'https://api.com/search',
            'query',
            'sqli'
        )

        assert result['url'] == 'https://api.com/search'
        assert result['param'] == 'query'
        assert result['wordlist'] == 'sqli'

    def test_fuzz_custom_params_missing_wordlist(self, mock_zap, wordlists, config):
        from modules.zap_fuzzer import ZAPFuzzer

        fuzzer = ZAPFuzzer(mock_zap, wordlists, config)
        result = fuzzer.fuzz_custom_params(
            'https://api.com/search',
            'query',
            'nonexistent'
        )

        assert 'error' in result

    @patch('modules.zap_fuzzer.time.sleep')
    def test_fuzz_with_payloads(self, mock_sleep, mock_zap, wordlists, config):
        from modules.zap_fuzzer import ZAPFuzzer

        mock_zap.fuzzer.messages.return_value = [
            {'responseHeader': {'statusCode': 200}, 'responseBody': 'ok'},
        ]

        fuzzer = ZAPFuzzer(mock_zap, wordlists, config)
        payloads = ['payload1', 'payload2', 'payload3']
        result = fuzzer.fuzz_with_payloads(
            'https://api.com/test',
            'param',
            payloads,
            payload_type='test'
        )

        assert result['url'] == 'https://api.com/test'
        assert result['param'] == 'param'
        assert result['payload_type'] == 'test'
        assert result['total_payloads'] == 3

    def test_analyze_idor_results_empty(self, mock_zap, wordlists, config):
        from modules.zap_fuzzer import ZAPFuzzer

        fuzzer = ZAPFuzzer(mock_zap, wordlists, config)
        assert fuzzer._analyze_idor_results([]) is False

    def test_analyze_idor_results_vulnerable(self, mock_zap, wordlists, config):
        from modules.zap_fuzzer import ZAPFuzzer

        fuzzer = ZAPFuzzer(mock_zap, wordlists, config)
        results = [
            {'responseHeader': {'statusCode': 200}},
            {'responseHeader': {'statusCode': 200}},
            {'responseHeader': {'statusCode': 200}},
        ]
        assert fuzzer._analyze_idor_results(results) is True

    def test_analyze_idor_results_protected(self, mock_zap, wordlists, config):
        from modules.zap_fuzzer import ZAPFuzzer

        fuzzer = ZAPFuzzer(mock_zap, wordlists, config)
        results = [
            {'responseHeader': {'statusCode': 403}},
            {'responseHeader': {'statusCode': 403}},
            {'responseHeader': {'statusCode': 403}},
        ]
        assert fuzzer._analyze_idor_results(results) is False

    def test_count_unique_responses(self, mock_zap, wordlists, config):
        from modules.zap_fuzzer import ZAPFuzzer

        fuzzer = ZAPFuzzer(mock_zap, wordlists, config)
        results = [
            {'responseHeader': {'statusCode': 200}, 'responseBody': 'a'},
            {'responseHeader': {'statusCode': 200}, 'responseBody': 'ab'},
            {'responseHeader': {'statusCode': 404}, 'responseBody': 'not found'},
        ]
        assert fuzzer._count_unique_responses(results) == 3

    def test_status_breakdown(self, mock_zap, wordlists, config):
        from modules.zap_fuzzer import ZAPFuzzer

        fuzzer = ZAPFuzzer(mock_zap, wordlists, config)
        messages = [
            {'responseHeader': {'statusCode': 200}},
            {'responseHeader': {'statusCode': 200}},
            {'responseHeader': {'statusCode': 404}},
            {'responseHeader': {'statusCode': 500}},
        ]
        breakdown = fuzzer._status_breakdown(messages)

        assert breakdown[200] == 2
        assert breakdown[404] == 1
        assert breakdown[500] == 1

    def test_get_interesting_responses(self, mock_zap, wordlists, config):
        from modules.zap_fuzzer import ZAPFuzzer

        mock_zap.fuzzer.messages.return_value = [
            {'responseHeader': {'statusCode': 200}},
            {'responseHeader': {'statusCode': 201}},
            {'responseHeader': {'statusCode': 404}},
            {'responseHeader': {'statusCode': 500}},
        ]

        fuzzer = ZAPFuzzer(mock_zap, wordlists, config)
        results = fuzzer.get_interesting_responses('fuzzer-123', min_status=200, max_status=299)

        assert len(results) == 2

    def test_stop_all(self, mock_zap, wordlists, config):
        from modules.zap_fuzzer import ZAPFuzzer

        fuzzer = ZAPFuzzer(mock_zap, wordlists, config)
        fuzzer.fuzzer_ids = ['fuzzer-1', 'fuzzer-2', 'fuzzer-3']
        fuzzer.stop_all()

        assert mock_zap.fuzzer.stop_fuzzer.call_count == 3

    def test_generate_report(self, mock_zap, wordlists, config):
        from modules.zap_fuzzer import ZAPFuzzer

        mock_zap.fuzzer.status.return_value = {'state': 'FINISHED'}
        mock_zap.fuzzer.messages.return_value = [
            {'responseHeader': {'statusCode': 200}},
        ]

        fuzzer = ZAPFuzzer(mock_zap, wordlists, config)
        fuzzer.fuzzer_ids = ['fuzzer-1']
        report = fuzzer.generate_report()

        assert report['total_fuzzers'] == 1
        assert len(report['fuzzers']) == 1
