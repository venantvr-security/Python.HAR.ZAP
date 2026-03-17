"""Tests for cache poisoning module"""
import pytest
from unittest.mock import Mock, patch

from modules.cache_poisoning import CachePoisoningTester, CachePoisonResult


@pytest.fixture
def sample_har():
    return {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://example.com/page",
                        "headers": []
                    },
                    "response": {
                        "status": 200,
                        "headers": [
                            {"name": "X-Cache", "value": "HIT"},
                            {"name": "Age", "value": "300"}
                        ]
                    }
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://example.com/no-cache",
                        "headers": []
                    },
                    "response": {
                        "status": 200,
                        "headers": []
                    }
                }
            ]
        }
    }


@pytest.fixture
def config():
    return {'cache_timeout': 5}


class TestCachePoisoningTester:
    """Test cache poisoning detection"""

    def test_init(self, sample_har, config):
        tester = CachePoisoningTester(sample_har, config)
        assert tester.har_data == sample_har
        assert tester.timeout == 5
        assert tester._use_zap is False

    def test_init_with_zap_client(self, sample_har, config):
        mock_zap = Mock()
        tester = CachePoisoningTester(sample_har, config, zap_client=mock_zap)
        assert tester._use_zap is True

    @patch('requests.get')
    def test_get_without_zap(self, mock_get, sample_har, config):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'x-cache': 'HIT'}
        mock_response.text = '<html>test</html>'
        mock_get.return_value = mock_response

        tester = CachePoisoningTester(sample_har, config)
        result = tester._get('https://example.com/page')

        assert result['status_code'] == 200
        assert 'x-cache' in result['headers']

    def test_get_with_zap_client(self, sample_har, config):
        mock_zap = Mock()
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {'x-cache': 'HIT'}
        mock_resp.text = 'OK'
        mock_zap.get.return_value = mock_resp

        tester = CachePoisoningTester(sample_har, config, zap_client=mock_zap)
        result = tester._get('https://example.com/page')

        assert result['status_code'] == 200

    @patch('requests.get')
    def test_get_handles_exception(self, mock_get, sample_har, config):
        mock_get.side_effect = Exception("Connection error")

        tester = CachePoisoningTester(sample_har, config)
        result = tester._get('https://example.com/page')

        assert result is None

    @patch('requests.request')
    def test_request_without_zap(self, mock_request, sample_har, config):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.text = 'OK'
        mock_request.return_value = mock_response

        tester = CachePoisoningTester(sample_har, config)
        result = tester._request('POST', 'https://example.com/api')

        assert result['status_code'] == 200

    def test_request_with_zap_client(self, sample_har, config):
        mock_zap = Mock()
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.text = 'OK'
        mock_zap.request.return_value = mock_resp

        tester = CachePoisoningTester(sample_har, config, zap_client=mock_zap)
        result = tester._request('POST', 'https://example.com/api')

        assert result['status_code'] == 200

    def test_raise_alert_with_zap(self, sample_har, config):
        mock_zap = Mock()
        tester = CachePoisoningTester(sample_har, config, zap_client=mock_zap)

        result = CachePoisonResult(
            url='https://example.com/page',
            poison_header='X-Forwarded-Host',
            poison_value='evil.com',
            vulnerable=True,
            confidence=0.9,
            evidence={'reflected': True}
        )

        tester._raise_alert(result)
        mock_zap.raise_alert.assert_called_once()

    def test_raise_alert_not_vulnerable(self, sample_har, config):
        mock_zap = Mock()
        tester = CachePoisoningTester(sample_har, config, zap_client=mock_zap)

        result = CachePoisonResult(
            url='https://example.com/page',
            poison_header='X-Test',
            poison_value='test',
            vulnerable=False,
            confidence=0.0,
            evidence={}
        )

        tester._raise_alert(result)
        mock_zap.raise_alert.assert_not_called()

    def test_poison_headers_constant(self):
        headers = [h[0] for h in CachePoisoningTester.POISON_HEADERS]
        assert 'X-Forwarded-Host' in headers
        assert 'X-Original-URL' in headers
        assert 'X-Forwarded-For' in headers

    def test_cache_indicators_constant(self):
        assert 'x-cache' in CachePoisoningTester.CACHE_INDICATORS
        assert 'age' in CachePoisoningTester.CACHE_INDICATORS
        assert 'cf-cache-status' in CachePoisoningTester.CACHE_INDICATORS


class TestCachePoisonResult:
    """Test CachePoisonResult dataclass"""

    def test_create_result(self):
        result = CachePoisonResult(
            url='https://example.com/page',
            poison_header='X-Forwarded-Host',
            poison_value='evil.com',
            vulnerable=True,
            confidence=0.9,
            evidence={'header': 'reflected'}
        )

        assert result.url == 'https://example.com/page'
        assert result.vulnerable is True
        assert result.severity == 'High'
        assert result.cwe == 'CWE-349'

    def test_default_values(self):
        result = CachePoisonResult(
            url='https://example.com',
            poison_header='X-Test',
            poison_value='test',
            vulnerable=False,
            confidence=0.0,
            evidence={}
        )

        assert result.severity == 'High'
        assert result.cvss == 7.5
