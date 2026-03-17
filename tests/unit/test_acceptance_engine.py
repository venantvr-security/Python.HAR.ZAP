"""Tests for Acceptance Engine module"""
import pytest
from unittest.mock import Mock, MagicMock


@pytest.fixture
def sample_criteria():
    return [
        {'type': 'max_high', 'threshold': 0},
        {'type': 'max_medium', 'threshold': 5},
        {'type': 'max_total_alerts', 'threshold': 20},
        {'type': 'no_sql_injection'},
        {'type': 'no_xss'}
    ]


@pytest.fixture
def sample_scan_results():
    return {
        'zap_alerts': [
            {'risk': 'High', 'alert': 'SQL Injection', 'url': 'https://api.com/user'},
            {'risk': 'Medium', 'alert': 'XSS', 'url': 'https://api.com/search'},
            {'risk': 'Medium', 'alert': 'CSRF', 'url': 'https://api.com/action'},
            {'risk': 'Low', 'alert': 'Cookie Flag', 'url': 'https://api.com/'},
            {'risk': 'Informational', 'alert': 'Server Header', 'url': 'https://api.com/'}
        ],
        'idor_results': [],
        'cors_results': [],
        'custom_results': {}
    }


class TestAcceptanceEngine:
    def test_init(self, sample_criteria):
        from modules.acceptance_engine import AcceptanceEngine

        engine = AcceptanceEngine(sample_criteria)
        assert engine.criteria == sample_criteria

    def test_evaluate_all_pass(self):
        from modules.acceptance_engine import AcceptanceEngine

        criteria = [
            {'type': 'max_high', 'threshold': 5},
            {'type': 'max_medium', 'threshold': 10}
        ]
        results = {
            'zap_alerts': [
                {'risk': 'Low', 'alert': 'Info leak'}
            ]
        }

        engine = AcceptanceEngine(criteria)
        evaluation = engine.evaluate(results)

        assert evaluation['passed'] is True
        assert len(evaluation['results']) == 2

    def test_evaluate_fail(self, sample_criteria, sample_scan_results):
        from modules.acceptance_engine import AcceptanceEngine

        engine = AcceptanceEngine(sample_criteria)
        evaluation = engine.evaluate(sample_scan_results)

        assert evaluation['passed'] is False  # Has 1 high alert but threshold is 0

    def test_check_max_high_pass(self):
        from modules.acceptance_engine import AcceptanceEngine

        criterion = {'type': 'max_high', 'threshold': 2}
        results = {
            'zap_alerts': [
                {'risk': 'High', 'alert': 'SQLi'},
                {'risk': 'Medium', 'alert': 'XSS'}
            ]
        }

        engine = AcceptanceEngine([criterion])
        result = engine._check_max_high(criterion, results)

        assert result['passed'] is True
        assert result['details']['count'] == 1

    def test_check_max_high_fail(self):
        from modules.acceptance_engine import AcceptanceEngine

        criterion = {'type': 'max_high', 'threshold': 0}
        results = {
            'zap_alerts': [
                {'risk': 'High', 'alert': 'SQLi'},
                {'risk': 'High', 'alert': 'RCE'}
            ]
        }

        engine = AcceptanceEngine([criterion])
        result = engine._check_max_high(criterion, results)

        assert result['passed'] is False
        assert result['details']['count'] == 2

    def test_check_max_medium(self):
        from modules.acceptance_engine import AcceptanceEngine

        criterion = {'type': 'max_medium', 'threshold': 1}
        results = {
            'zap_alerts': [
                {'risk': 'Medium', 'alert': 'XSS'},
                {'risk': 'Medium', 'alert': 'CSRF'}
            ]
        }

        engine = AcceptanceEngine([criterion])
        result = engine._check_max_medium(criterion, results)

        assert result['passed'] is False
        assert result['details']['count'] == 2

    def test_check_no_idor_pass(self):
        from modules.acceptance_engine import AcceptanceEngine

        criterion = {'type': 'no_idor'}
        results = {'idor_results': []}

        engine = AcceptanceEngine([criterion])
        result = engine._check_no_idor(criterion, results)

        assert result['passed'] is True

    def test_check_no_idor_fail(self):
        from modules.acceptance_engine import AcceptanceEngine
        from modules.idor_detector import IDORStatus

        mock_result = Mock()
        mock_result.status = IDORStatus.VULNERABLE
        mock_result.url = 'https://api.com/user/123'

        criterion = {'type': 'no_idor'}
        results = {'idor_results': [mock_result]}

        engine = AcceptanceEngine([criterion])
        result = engine._check_no_idor(criterion, results)

        assert result['passed'] is False
        assert result['details']['count'] == 1

    def test_check_max_total_alerts(self):
        from modules.acceptance_engine import AcceptanceEngine

        criterion = {'type': 'max_total_alerts', 'threshold': 5}
        results = {
            'zap_alerts': [
                {'risk': 'High', 'alert': 'Test1'},
                {'risk': 'Medium', 'alert': 'Test2'},
                {'risk': 'Low', 'alert': 'Test3'}
            ]
        }

        engine = AcceptanceEngine([criterion])
        result = engine._check_max_total(criterion, results)

        assert result['passed'] is True

    def test_check_no_sql_injection_pass(self):
        from modules.acceptance_engine import AcceptanceEngine

        criterion = {'type': 'no_sql_injection'}
        results = {
            'zap_alerts': [
                {'risk': 'Medium', 'alert': 'XSS Vulnerability'}
            ]
        }

        engine = AcceptanceEngine([criterion])
        result = engine._check_no_sql_injection(criterion, results)

        assert result['passed'] is True

    def test_check_no_sql_injection_fail(self):
        from modules.acceptance_engine import AcceptanceEngine

        criterion = {'type': 'no_sql_injection'}
        results = {
            'zap_alerts': [
                {'risk': 'High', 'alert': 'SQL Injection', 'url': 'https://api.com/user'}
            ]
        }

        engine = AcceptanceEngine([criterion])
        result = engine._check_no_sql_injection(criterion, results)

        assert result['passed'] is False

    def test_check_no_xss(self):
        from modules.acceptance_engine import AcceptanceEngine

        criterion = {'type': 'no_xss'}
        results = {
            'zap_alerts': [
                {'risk': 'Medium', 'alert': 'XSS Reflected', 'url': 'https://api.com'}
            ]
        }

        engine = AcceptanceEngine([criterion])
        result = engine._check_no_xss(criterion, results)

        assert result['passed'] is False

    def test_check_clean_url(self):
        from modules.acceptance_engine import AcceptanceEngine

        criterion = {'type': 'clean_url', 'pattern': '/admin'}
        results = {
            'zap_alerts': [
                {'risk': 'High', 'alert': 'SQLi', 'url': 'https://api.com/admin/users'},
                {'risk': 'Medium', 'alert': 'XSS', 'url': 'https://api.com/public'}
            ]
        }

        engine = AcceptanceEngine([criterion])
        result = engine._check_clean_url(criterion, results)

        assert result['passed'] is False

    def test_unknown_criterion_type(self):
        from modules.acceptance_engine import AcceptanceEngine

        criterion = {'type': 'unknown_type'}
        results = {'zap_alerts': []}

        engine = AcceptanceEngine([criterion])
        result = engine._evaluate_criterion(criterion, results)

        assert result['passed'] is False
        assert 'Unknown criterion type' in result['message']

    def test_generate_summary(self, sample_criteria):
        from modules.acceptance_engine import AcceptanceEngine

        engine = AcceptanceEngine(sample_criteria)
        results = {
            'zap_alerts': [],
            'idor_results': []
        }

        evaluation = engine.evaluate(results)

        assert 'summary' in evaluation
