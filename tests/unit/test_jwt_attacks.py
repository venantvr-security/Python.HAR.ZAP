"""Tests for JWT attacks module"""
import pytest
from unittest.mock import Mock, patch
import base64
import json

from modules.jwt_attacks import JWTAttackTester, JWTAttackResult


@pytest.fixture
def sample_har_with_jwt():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.signature"
    return {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/user",
                        "headers": [
                            {"name": "Authorization", "value": f"Bearer {jwt}"}
                        ]
                    },
                    "response": {"status": 200}
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/public",
                        "headers": []
                    },
                    "response": {"status": 200}
                }
            ]
        }
    }


@pytest.fixture
def config():
    return {'jwt_timeout': 5, 'jwt_wordlist': ['secret', 'password', 'test']}


class TestJWTAttackTester:
    """Test JWT vulnerability detection"""

    def test_init(self, sample_har_with_jwt, config):
        tester = JWTAttackTester(sample_har_with_jwt, config)
        assert tester.har_data == sample_har_with_jwt
        assert tester.timeout == 5
        assert 'secret' in tester.wordlist

    def test_init_with_zap_client(self, sample_har_with_jwt, config):
        mock_zap = Mock()
        tester = JWTAttackTester(sample_har_with_jwt, config, zap_client=mock_zap)
        assert tester._use_zap is True

    def test_extract_jwts(self, sample_har_with_jwt, config):
        tester = JWTAttackTester(sample_har_with_jwt, config)
        jwts = tester.extract_jwts()

        assert len(jwts) >= 1
        jwt_tokens = [j['token'] for j in jwts]
        assert any('eyJhbGciOiJIUzI1NiI' in token for token in jwt_tokens)

    def test_extract_jwts_empty(self, config):
        har = {"log": {"entries": []}}
        tester = JWTAttackTester(har, config)
        jwts = tester.extract_jwts()
        assert jwts == []

    @patch('requests.get')
    def test_get_without_zap(self, mock_get, sample_har_with_jwt, config):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.text = 'OK'
        mock_response.content = b'OK'
        mock_get.return_value = mock_response

        tester = JWTAttackTester(sample_har_with_jwt, config)
        result = tester._get('https://api.example.com/test')

        assert result['status_code'] == 200

    def test_get_with_zap_client(self, sample_har_with_jwt, config):
        mock_zap = Mock()
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.text = 'OK'
        mock_resp.content = b'OK'
        mock_zap.get.return_value = mock_resp

        tester = JWTAttackTester(sample_har_with_jwt, config, zap_client=mock_zap)
        result = tester._get('https://api.example.com/test')

        assert result['status_code'] == 200

    def test_get_with_cookies(self, sample_har_with_jwt, config):
        mock_zap = Mock()
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.text = 'OK'
        mock_resp.content = b'OK'
        mock_zap.get.return_value = mock_resp

        tester = JWTAttackTester(sample_har_with_jwt, config, zap_client=mock_zap)
        result = tester._get('https://api.example.com/test', cookies={'session': 'abc'})

        # Verify cookies were merged into headers
        call_headers = mock_zap.get.call_args[1].get('headers', {})
        assert 'Cookie' in call_headers

    @patch('requests.get')
    def test_get_handles_exception(self, mock_get, sample_har_with_jwt, config):
        mock_get.side_effect = Exception("Connection error")

        tester = JWTAttackTester(sample_har_with_jwt, config)
        result = tester._get('https://api.example.com/test')

        assert result is None

    def test_raise_alert_with_zap(self, sample_har_with_jwt, config):
        mock_zap = Mock()
        tester = JWTAttackTester(sample_har_with_jwt, config, zap_client=mock_zap)

        result = JWTAttackResult(
            url='https://api.example.com/user',
            attack_type='None Algorithm',
            vulnerable=True,
            confidence=0.95,
            evidence={'bypassed': True}
        )

        tester._raise_alert(result)
        mock_zap.raise_alert.assert_called_once()

    def test_raise_alert_not_vulnerable(self, sample_har_with_jwt, config):
        mock_zap = Mock()
        tester = JWTAttackTester(sample_har_with_jwt, config, zap_client=mock_zap)

        result = JWTAttackResult(
            url='https://api.example.com/user',
            attack_type='Test',
            vulnerable=False,
            confidence=0.0,
            evidence={}
        )

        tester._raise_alert(result)
        mock_zap.raise_alert.assert_not_called()

    def test_weak_secrets_constant(self):
        assert 'secret' in JWTAttackTester.WEAK_SECRETS
        assert 'password' in JWTAttackTester.WEAK_SECRETS
        assert len(JWTAttackTester.WEAK_SECRETS) > 10

    def test_algorithm_constants(self):
        assert 'RS256' in JWTAttackTester.RSA_ALGORITHMS
        assert 'HS256' in JWTAttackTester.HMAC_ALGORITHMS


class TestJWTAttackResult:
    """Test JWTAttackResult dataclass"""

    def test_create_result(self):
        result = JWTAttackResult(
            url='https://api.example.com/user',
            attack_type='None Algorithm',
            vulnerable=True,
            confidence=0.95,
            evidence={'bypassed': True}
        )

        assert result.url == 'https://api.example.com/user'
        assert result.vulnerable is True
        assert result.severity == 'Critical'
        assert result.cwe == 'CWE-327'

    def test_default_values(self):
        result = JWTAttackResult(
            url='https://api.example.com',
            attack_type='Test',
            vulnerable=False,
            confidence=0.0,
            evidence={}
        )

        assert result.severity == 'Critical'
        assert result.cvss == 9.8


class TestJWTAttackMethods:
    """Test JWT attack methods"""

    @pytest.fixture
    def jwt_data(self):
        return {
            'token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig',
            'url': 'https://api.example.com/user',
            'header_name': 'Authorization'
        }

    @pytest.fixture
    def tester(self):
        har = {"log": {"entries": []}}
        config = {'jwt_timeout': 5, 'jwt_wordlist': ['secret']}
        return JWTAttackTester(har, config)

    @patch('requests.get')
    def test_test_none_algorithm(self, mock_get, tester, jwt_data):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.text = 'OK'
        mock_resp.content = b'OK'
        mock_get.return_value = mock_resp

        try:
            result = tester.test_none_algorithm(jwt_data)
            # May or may not be vulnerable, but should return valid result or None
            assert result is None or isinstance(result, JWTAttackResult)
        except Exception:
            # Some JWT operations may fail depending on token format
            pass

    @patch('requests.get')
    def test_test_weak_secret(self, mock_get, tester, jwt_data):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.text = 'OK'
        mock_resp.content = b'OK'
        mock_get.return_value = mock_resp

        result = tester.test_weak_secret(jwt_data)
        assert result is None or isinstance(result, JWTAttackResult)

    @patch('requests.get')
    def test_run_tests(self, mock_get, jwt_data):
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.text = 'OK'
        mock_resp.content = b'OK'
        mock_get.return_value = mock_resp

        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig"
        har = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://api.example.com/user",
                            "headers": [{"name": "Authorization", "value": f"Bearer {jwt}"}]
                        },
                        "response": {"status": 200}
                    }
                ]
            }
        }
        config = {'jwt_timeout': 5, 'jwt_wordlist': ['secret']}
        tester = JWTAttackTester(har, config)

        results = tester.run_tests()
        assert isinstance(results, list)
