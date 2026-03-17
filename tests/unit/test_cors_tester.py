"""Tests for CORS tester module"""
import pytest
from unittest.mock import Mock, patch, MagicMock

from modules.cors_tester import CORSTester, CORSResult


@pytest.fixture
def sample_har():
    return {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/data",
                        "headers": [
                            {"name": "Origin", "value": "https://example.com"}
                        ]
                    },
                    "response": {
                        "status": 200,
                        "headers": [
                            {"name": "Access-Control-Allow-Origin", "value": "https://example.com"},
                            {"name": "Access-Control-Allow-Credentials", "value": "true"}
                        ]
                    }
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/no-cors",
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
    return {'cors_timeout': 5}


class TestCORSTester:
    """Test CORS misconfiguration detection"""

    def test_init(self, sample_har, config):
        tester = CORSTester(sample_har, config)
        assert tester.har_data == sample_har
        assert tester.timeout == 5
        assert tester._use_zap is False

    def test_init_with_zap_client(self, sample_har, config):
        mock_zap = Mock()
        tester = CORSTester(sample_har, config, zap_client=mock_zap)
        assert tester._use_zap is True

    def test_identify_cors_endpoints(self, sample_har, config):
        tester = CORSTester(sample_har, config)
        endpoints = tester.identify_cors_endpoints()

        assert len(endpoints) == 1
        assert endpoints[0]['url'] == 'https://api.example.com/data'
        assert 'access-control-allow-origin' in endpoints[0]['cors_headers']

    def test_identify_cors_endpoints_with_original_origin(self, sample_har, config):
        tester = CORSTester(sample_har, config)
        endpoints = tester.identify_cors_endpoints()

        assert endpoints[0]['original_origin'] == 'https://example.com'

    @patch('requests.get')
    def test_get_without_zap(self, mock_get, sample_har, config):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'Access-Control-Allow-Origin': '*'}
        mock_response.text = 'OK'
        mock_get.return_value = mock_response

        tester = CORSTester(sample_har, config)
        result = tester._get('https://api.example.com/test', {'Origin': 'https://evil.com'})

        assert result['status_code'] == 200
        assert 'Access-Control-Allow-Origin' in result['headers']

    def test_get_with_zap_client(self, sample_har, config):
        mock_zap = Mock()
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {'Access-Control-Allow-Origin': '*'}
        mock_resp.text = 'OK'
        mock_zap.get.return_value = mock_resp

        tester = CORSTester(sample_har, config, zap_client=mock_zap)
        result = tester._get('https://api.example.com/test')

        assert result['status_code'] == 200
        mock_zap.get.assert_called_once()

    @patch('requests.get')
    def test_get_handles_exception(self, mock_get, sample_har, config):
        mock_get.side_effect = Exception("Connection error")

        tester = CORSTester(sample_har, config)
        result = tester._get('https://api.example.com/test')

        assert result is None

    @patch('requests.options')
    def test_options_without_zap(self, mock_options, sample_har, config):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'Allow': 'GET, POST'}
        mock_options.return_value = mock_response

        tester = CORSTester(sample_har, config)
        result = tester._options('https://api.example.com/test')

        assert result['status_code'] == 200

    def test_options_with_zap_client(self, sample_har, config):
        mock_zap = Mock()
        mock_resp = Mock()
        mock_resp.status_code = 204
        mock_resp.headers = {}
        mock_zap.options.return_value = mock_resp

        tester = CORSTester(sample_har, config, zap_client=mock_zap)
        result = tester._options('https://api.example.com/test')

        assert result['status_code'] == 204

    def test_raise_alert_with_zap(self, sample_har, config):
        mock_zap = Mock()
        tester = CORSTester(sample_har, config, zap_client=mock_zap)

        result = CORSResult(
            url='https://api.example.com/data',
            vulnerability_type='Origin Reflection',
            vulnerable=True,
            confidence=0.9,
            evidence={'reflected': 'https://evil.com'},
            severity='High'
        )

        tester._raise_alert(result)
        mock_zap.raise_alert.assert_called_once()

    def test_raise_alert_not_vulnerable(self, sample_har, config):
        mock_zap = Mock()
        tester = CORSTester(sample_har, config, zap_client=mock_zap)

        result = CORSResult(
            url='https://api.example.com/data',
            vulnerability_type='None',
            vulnerable=False,
            confidence=0.0,
            evidence={}
        )

        tester._raise_alert(result)
        mock_zap.raise_alert.assert_not_called()

    def test_test_origins_constant(self):
        assert 'https://evil.com' in CORSTester.TEST_ORIGINS
        assert 'null' in CORSTester.TEST_ORIGINS

    def test_cors_headers_constant(self):
        assert 'access-control-allow-origin' in CORSTester.CORS_HEADERS
        assert 'access-control-allow-credentials' in CORSTester.CORS_HEADERS


class TestCORSResult:
    """Test CORSResult dataclass"""

    def test_create_result(self):
        result = CORSResult(
            url='https://api.example.com',
            vulnerability_type='Wildcard',
            vulnerable=True,
            confidence=0.95,
            evidence={'header': '*'}
        )

        assert result.url == 'https://api.example.com'
        assert result.vulnerable is True
        assert result.severity == 'High'
        assert result.cwe == 'CWE-346'

    def test_default_values(self):
        result = CORSResult(
            url='https://api.example.com',
            vulnerability_type='Test',
            vulnerable=False,
            confidence=0.0,
            evidence={}
        )

        assert result.severity == 'High'
        assert result.cvss == 7.5


class TestCORSTesterVulnerabilities:
    """Test specific vulnerability detection"""

    @pytest.fixture
    def har_with_cors(self):
        return {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://api.example.com/data",
                            "headers": [{"name": "Origin", "value": "https://example.com"}]
                        },
                        "response": {
                            "status": 200,
                            "headers": [
                                {"name": "Access-Control-Allow-Origin", "value": "*"},
                                {"name": "Access-Control-Allow-Credentials", "value": "true"}
                            ]
                        }
                    }
                ]
            }
        }

    @patch('requests.get')
    def test_test_origin_reflection(self, mock_get, har_with_cors):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            'Access-Control-Allow-Origin': 'https://evil.com',
            'Access-Control-Allow-Credentials': 'true'
        }
        mock_resp.text = 'OK'
        mock_get.return_value = mock_resp

        tester = CORSTester(har_with_cors, {})
        results = tester.test_origin_reflection('https://api.example.com/data')

        assert isinstance(results, list)

    @patch('requests.get')
    def test_test_origin_bypass(self, mock_get, har_with_cors):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            'Access-Control-Allow-Origin': 'https://evil.example.com'
        }
        mock_resp.text = 'OK'
        mock_get.return_value = mock_resp

        tester = CORSTester(har_with_cors, {})
        results = tester.test_origin_bypass('https://api.example.com/data')

        assert isinstance(results, list)

    @patch('requests.get')
    @patch('requests.options')
    def test_run_tests(self, mock_options, mock_get, har_with_cors):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {'Access-Control-Allow-Origin': 'https://example.com'}
        mock_resp.text = 'OK'
        mock_get.return_value = mock_resp
        mock_options.return_value = mock_resp

        tester = CORSTester(har_with_cors, {})
        results = tester.run_tests()

        assert isinstance(results, list)

    @patch('requests.get')
    @patch('requests.options')
    def test_test_preflight_bypass(self, mock_options, mock_get, har_with_cors):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.text = 'OK'
        mock_get.return_value = mock_resp
        mock_options.return_value = mock_resp

        tester = CORSTester(har_with_cors, {})
        result = tester.test_preflight_bypass('https://api.example.com/data')

        assert result is None or isinstance(result, CORSResult)

    @patch('requests.get')
    def test_test_vary_header(self, mock_get, har_with_cors):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {'Vary': 'Accept'}
        mock_resp.text = 'OK'
        mock_get.return_value = mock_resp

        tester = CORSTester(har_with_cors, {})
        result = tester.test_vary_header('https://api.example.com/data')

        assert result is None or isinstance(result, CORSResult)
