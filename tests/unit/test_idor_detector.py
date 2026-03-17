"""Tests for IDOR detector module"""
import pytest
from unittest.mock import Mock, patch

from modules.idor_detector import IDORDetector, IDORTestResult, IDORStatus


@pytest.fixture
def session_a_har():
    return {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/user/123",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer token_a"},
                            {"name": "Cookie", "value": "session=abc123"}
                        ]
                    },
                    "response": {"status": 200}
                }
            ]
        }
    }


@pytest.fixture
def session_b_har():
    return {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/user/456",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer token_b"},
                            {"name": "X-Auth-Token", "value": "secret"}
                        ]
                    },
                    "response": {"status": 200}
                }
            ]
        }
    }


@pytest.fixture
def config():
    return {'max_workers': 2}


class TestIDORDetector:
    """Test IDOR detection"""

    def test_init(self, session_a_har, session_b_har, config):
        detector = IDORDetector(session_a_har, session_b_har, config)
        assert detector.session_a == session_a_har
        assert detector.session_b == session_b_har
        assert detector.max_workers == 2

    def test_init_with_zap_client(self, session_a_har, session_b_har, config):
        mock_zap = Mock()
        detector = IDORDetector(session_a_har, session_b_har, config, zap_client=mock_zap)
        assert detector._use_zap is True

    def test_extract_auth_tokens(self, session_a_har, session_b_har, config):
        detector = IDORDetector(session_a_har, session_b_har, config)

        tokens_a = detector.extract_auth_tokens(session_a_har)
        assert 'Authorization' in tokens_a
        assert 'Cookie' in tokens_a

        tokens_b = detector.extract_auth_tokens(session_b_har)
        assert 'Authorization' in tokens_b
        assert 'X-Auth-Token' in tokens_b

    def test_extract_auth_tokens_empty(self, session_a_har, session_b_har, config):
        empty_har = {"log": {"entries": []}}
        detector = IDORDetector(session_a_har, session_b_har, config)
        tokens = detector.extract_auth_tokens(empty_har)
        assert tokens == {}

    @patch('requests.Session')
    def test_request_without_zap(self, mock_session_class, session_a_har, session_b_har, config):
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_response.text = '<html>content</html>'
        mock_response.content = b'<html>content</html>'
        mock_session.request.return_value = mock_response
        mock_session_class.return_value = mock_session

        detector = IDORDetector(session_a_har, session_b_har, config)
        result = detector._request('GET', 'https://api.example.com/user/123')

        assert result['status_code'] == 200

    def test_request_with_zap_client(self, session_a_har, session_b_har, config):
        mock_zap = Mock()
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.headers = {'Content-Type': 'text/html'}
        mock_resp.text = 'OK'
        mock_resp.content = b'OK'
        mock_zap.request.return_value = mock_resp

        detector = IDORDetector(session_a_har, session_b_har, config, zap_client=mock_zap)
        result = detector._request('GET', 'https://api.example.com/user/123')

        assert result['status_code'] == 200

    @patch('requests.Session')
    def test_request_handles_exception(self, mock_session_class, session_a_har, session_b_har, config):
        mock_session = Mock()
        mock_session.request.side_effect = Exception("Connection error")
        mock_session_class.return_value = mock_session

        detector = IDORDetector(session_a_har, session_b_har, config)
        result = detector._request('GET', 'https://api.example.com/user/123')

        assert 'error' in result

    def test_raise_alert_vulnerable(self, session_a_har, session_b_har, config):
        mock_zap = Mock()
        detector = IDORDetector(session_a_har, session_b_har, config, zap_client=mock_zap)

        result = IDORTestResult(
            url='https://api.example.com/user/123',
            method='GET',
            status=IDORStatus.VULNERABLE,
            baseline_response={},
            test_response={},
            confidence=0.9,
            proof={'param': 'id', 'original_value': '123', 'test_value': '456'}
        )

        detector._raise_alert(result)
        mock_zap.raise_alert.assert_called_once()

    def test_raise_alert_protected(self, session_a_har, session_b_har, config):
        mock_zap = Mock()
        detector = IDORDetector(session_a_har, session_b_har, config, zap_client=mock_zap)

        result = IDORTestResult(
            url='https://api.example.com/user/123',
            method='GET',
            status=IDORStatus.PROTECTED,
            baseline_response={},
            test_response={},
            confidence=0.0,
            proof={}
        )

        detector._raise_alert(result)
        mock_zap.raise_alert.assert_not_called()

    def test_suspicious_params_constant(self):
        assert 'id' in IDORDetector.SUSPICIOUS_PARAMS
        assert 'user_id' in IDORDetector.SUSPICIOUS_PARAMS
        assert 'account_id' in IDORDetector.SUSPICIOUS_PARAMS


class TestIDORTestResult:
    """Test IDORTestResult dataclass"""

    def test_create_vulnerable_result(self):
        result = IDORTestResult(
            url='https://api.example.com/user/123',
            method='GET',
            status=IDORStatus.VULNERABLE,
            baseline_response={'status': 200},
            test_response={'status': 200},
            confidence=0.95,
            proof={'param': 'id'}
        )

        assert result.status == IDORStatus.VULNERABLE
        assert result.confidence == 0.95

    def test_create_protected_result(self):
        result = IDORTestResult(
            url='https://api.example.com/user/123',
            method='GET',
            status=IDORStatus.PROTECTED,
            baseline_response={'status': 200},
            test_response={'status': 403},
            confidence=0.0,
            proof={}
        )

        assert result.status == IDORStatus.PROTECTED


class TestIDORStatus:
    """Test IDORStatus enum"""

    def test_enum_values(self):
        assert IDORStatus.VULNERABLE.value == "VULNERABLE"
        assert IDORStatus.PROTECTED.value == "PROTECTED"
        assert IDORStatus.FALSE_POSITIVE.value == "FALSE_POSITIVE"
        assert IDORStatus.ERROR.value == "ERROR"


class TestIDORDetectorAdvanced:
    """Advanced IDOR tests"""

    @pytest.fixture
    def har_with_ids(self):
        return {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://api.example.com/user?id=123&account_id=456",
                            "headers": [{"name": "Authorization", "value": "Bearer token_a"}]
                        },
                        "response": {"status": 200, "content": {"text": "User data"}}
                    }
                ]
            }
        }

    def test_identify_idor_targets(self, har_with_ids):
        har_b = {"log": {"entries": []}}
        detector = IDORDetector(har_with_ids, har_b, {})
        targets = detector.identify_idor_targets(har_with_ids)

        assert isinstance(targets, list)

    def test_create_test_variants(self, har_with_ids):
        har_b = {"log": {"entries": []}}
        detector = IDORDetector(har_with_ids, har_b, {})
        targets = detector.identify_idor_targets(har_with_ids)

        if targets:
            variants = detector.create_test_variants(targets[0])
            assert isinstance(variants, list)

    def test_analyze_responses_protected(self, har_with_ids):
        har_b = {"log": {"entries": []}}
        detector = IDORDetector(har_with_ids, har_b, {})

        baseline = {'status_code': 200, 'content_length': 100, 'content': 'data'}
        test = {'status_code': 403, 'content_length': 50, 'content': 'forbidden'}
        variant = {'url': 'https://api.example.com/user?id=124', 'method': 'GET'}

        result = detector.analyze_responses(baseline, test, variant)
        assert result.status == IDORStatus.PROTECTED

    def test_analyze_responses_error(self, har_with_ids):
        har_b = {"log": {"entries": []}}
        detector = IDORDetector(har_with_ids, har_b, {})

        baseline = {'error': 'Connection failed'}
        test = {'status_code': 200}
        variant = {'url': 'https://api.example.com/user?id=124', 'method': 'GET'}

        result = detector.analyze_responses(baseline, test, variant)
        assert result.status == IDORStatus.ERROR

    def test_calculate_similarity(self, har_with_ids):
        har_b = {"log": {"entries": []}}
        detector = IDORDetector(har_with_ids, har_b, {})

        sim = detector._calculate_similarity("hello world", "hello world")
        assert sim == 1.0

        sim2 = detector._calculate_similarity("hello", "world")
        assert 0.0 <= sim2 <= 1.0

    def test_generate_curl_commands(self, har_with_ids):
        result = IDORTestResult(
            url='https://api.example.com/user?id=124',
            method='GET',
            status=IDORStatus.VULNERABLE,
            baseline_response={},
            test_response={},
            confidence=0.9,
            proof={}
        )

        curl = IDORDetector.generate_curl_commands(result, {'Authorization': 'Bearer xxx'})
        assert 'curl' in curl

    @patch('requests.Session')
    def test_run_detection(self, mock_session_class, har_with_ids):
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.text = 'OK'
        mock_response.content = b'OK'
        mock_session.request.return_value = mock_response
        mock_session_class.return_value = mock_session

        har_b = {"log": {"entries": [{"request": {"headers": [{"name": "Authorization", "value": "Bearer b"}]}}]}}
        detector = IDORDetector(har_with_ids, har_b, {'max_workers': 1})

        results = detector.run_detection()
        assert isinstance(results, list)

    def test_get_summary(self, har_with_ids):
        har_b = {"log": {"entries": []}}
        detector = IDORDetector(har_with_ids, har_b, {})

        summary = detector.get_summary()
        assert isinstance(summary, dict)
