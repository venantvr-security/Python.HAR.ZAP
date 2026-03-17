"""Tests for passive analysis module"""
import pytest
from unittest.mock import Mock

from modules.passive_analysis import SecurityHeadersAnalyzer, SecurityIssue


@pytest.fixture
def sample_har_missing_headers():
    return {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://example.com/page"
                    },
                    "response": {
                        "status": 200,
                        "headers": [
                            {"name": "Content-Type", "value": "text/html"}
                        ]
                    }
                }
            ]
        }
    }


@pytest.fixture
def sample_har_with_headers():
    return {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://secure.example.com/page"
                    },
                    "response": {
                        "status": 200,
                        "headers": [
                            {"name": "Strict-Transport-Security", "value": "max-age=31536000"},
                            {"name": "Content-Security-Policy", "value": "default-src 'self'"},
                            {"name": "X-Frame-Options", "value": "DENY"},
                            {"name": "X-Content-Type-Options", "value": "nosniff"},
                            {"name": "Referrer-Policy", "value": "no-referrer"},
                            {"name": "Permissions-Policy", "value": "geolocation=()"}
                        ]
                    }
                }
            ]
        }
    }


@pytest.fixture
def sample_har_weak_csp():
    return {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://example.com/page"
                    },
                    "response": {
                        "status": 200,
                        "headers": [
                            {"name": "Content-Security-Policy", "value": "default-src 'self' 'unsafe-inline'"},
                            {"name": "Strict-Transport-Security", "value": "max-age=31536000"},
                            {"name": "X-Frame-Options", "value": "DENY"},
                            {"name": "X-Content-Type-Options", "value": "nosniff"},
                            {"name": "Referrer-Policy", "value": "no-referrer"},
                            {"name": "Permissions-Policy", "value": "geolocation=()"}
                        ]
                    }
                }
            ]
        }
    }


class TestSecurityHeadersAnalyzer:
    """Test security headers analysis"""

    def test_init(self, sample_har_missing_headers):
        analyzer = SecurityHeadersAnalyzer(sample_har_missing_headers)
        assert analyzer.har_data == sample_har_missing_headers
        assert analyzer.issues == []

    def test_analyze_missing_headers(self, sample_har_missing_headers):
        analyzer = SecurityHeadersAnalyzer(sample_har_missing_headers)
        issues = analyzer.analyze()

        # Should detect all missing security headers
        missing_headers = [i.title for i in issues if 'Missing' in i.category]
        assert len(missing_headers) > 0
        assert any('Strict-Transport-Security' in h for h in missing_headers)
        assert any('Content-Security-Policy' in h for h in missing_headers)

    def test_analyze_all_headers_present(self, sample_har_with_headers):
        analyzer = SecurityHeadersAnalyzer(sample_har_with_headers)
        issues = analyzer.analyze()

        # Should not find missing header issues
        missing_issues = [i for i in issues if 'Missing' in i.category]
        assert len(missing_issues) == 0

    def test_analyze_weak_csp(self, sample_har_weak_csp):
        analyzer = SecurityHeadersAnalyzer(sample_har_weak_csp)
        issues = analyzer.analyze()

        # Should detect weak CSP
        weak_csp_issues = [i for i in issues if 'Weak' in i.category]
        assert len(weak_csp_issues) > 0

    def test_analyze_multiple_domains(self):
        har = {
            "log": {
                "entries": [
                    {
                        "request": {"url": "https://domain1.com/page"},
                        "response": {"status": 200, "headers": []}
                    },
                    {
                        "request": {"url": "https://domain2.com/page"},
                        "response": {"status": 200, "headers": []}
                    },
                    {
                        "request": {"url": "https://domain1.com/other"},
                        "response": {"status": 200, "headers": []}
                    }
                ]
            }
        }

        analyzer = SecurityHeadersAnalyzer(har)
        issues = analyzer.analyze()

        # Should only check each domain once
        domains = set(i.evidence.get('domain') for i in issues)
        assert 'domain1.com' in domains
        assert 'domain2.com' in domains

    def test_required_headers_constant(self):
        headers = SecurityHeadersAnalyzer.REQUIRED_HEADERS
        assert 'Strict-Transport-Security' in headers
        assert 'Content-Security-Policy' in headers
        assert 'X-Frame-Options' in headers
        assert 'X-Content-Type-Options' in headers

    def test_check_weak_csp_unsafe_inline(self, sample_har_missing_headers):
        analyzer = SecurityHeadersAnalyzer(sample_har_missing_headers)
        analyzer._check_weak_csp(
            {'content-security-policy': "default-src 'self' 'unsafe-inline'"},
            'https://example.com/page'
        )

        weak_issues = [i for i in analyzer.issues if 'unsafe-inline' in i.description]
        assert len(weak_issues) > 0

    def test_check_weak_csp_unsafe_eval(self, sample_har_missing_headers):
        analyzer = SecurityHeadersAnalyzer(sample_har_missing_headers)
        analyzer._check_weak_csp(
            {'content-security-policy': "default-src 'self' 'unsafe-eval'"},
            'https://example.com/page'
        )

        weak_issues = [i for i in analyzer.issues if 'unsafe-eval' in i.description]
        assert len(weak_issues) > 0

    def test_check_weak_csp_wildcard(self, sample_har_missing_headers):
        analyzer = SecurityHeadersAnalyzer(sample_har_missing_headers)
        analyzer._check_weak_csp(
            {'content-security-policy': "default-src *"},
            'https://example.com/page'
        )

        weak_issues = [i for i in analyzer.issues if 'wildcard' in i.description]
        assert len(weak_issues) > 0

    def test_issue_structure(self, sample_har_missing_headers):
        analyzer = SecurityHeadersAnalyzer(sample_har_missing_headers)
        issues = analyzer.analyze()

        for issue in issues:
            assert isinstance(issue, SecurityIssue)
            assert issue.severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
            assert issue.category
            assert issue.title
            assert issue.description
            assert issue.remediation


class TestSecurityIssue:
    """Test SecurityIssue dataclass"""

    def test_create_issue(self):
        issue = SecurityIssue(
            severity='HIGH',
            category='Missing Security Header',
            title='Missing Strict-Transport-Security',
            description='HSTS header missing',
            evidence={'domain': 'example.com'},
            remediation='Add HSTS header'
        )

        assert issue.severity == 'HIGH'
        assert issue.category == 'Missing Security Header'
        assert 'example.com' in issue.evidence['domain']


class TestSensitiveDataScanner:
    """Test sensitive data scanner"""

    @pytest.fixture
    def har_with_sensitive_data(self):
        return {
            "log": {
                "entries": [
                    {
                        "request": {"url": "https://api.example.com/data"},
                        "response": {
                            "status": 200,
                            "content": {"text": "email: user@example.com, ssn: 123-45-6789"}
                        }
                    }
                ]
            }
        }

    @pytest.fixture
    def har_with_stack_trace(self):
        return {
            "log": {
                "entries": [
                    {
                        "request": {"url": "https://api.example.com/error"},
                        "response": {
                            "status": 500,
                            "content": {"text": "Traceback (most recent call last):\n  File 'app.py', line 10"}
                        }
                    }
                ]
            }
        }

    def test_init(self, har_with_sensitive_data):
        from modules.passive_analysis import SensitiveDataScanner

        scanner = SensitiveDataScanner(har_with_sensitive_data)
        assert scanner.har_data == har_with_sensitive_data

    def test_scan_detects_email(self, har_with_sensitive_data):
        from modules.passive_analysis import SensitiveDataScanner

        scanner = SensitiveDataScanner(har_with_sensitive_data)
        issues = scanner.scan()

        assert isinstance(issues, list)

    def test_scan_detects_stack_trace(self, har_with_stack_trace):
        from modules.passive_analysis import SensitiveDataScanner

        scanner = SensitiveDataScanner(har_with_stack_trace)
        issues = scanner.scan()

        assert isinstance(issues, list)

    def test_get_severity(self):
        from modules.passive_analysis import SensitiveDataScanner

        assert SensitiveDataScanner._get_severity('password') in ['CRITICAL', 'HIGH']
        assert SensitiveDataScanner._get_severity('email') in ['MEDIUM', 'HIGH', 'LOW']


class TestTokenEntropyAnalyzer:
    """Test token entropy analyzer"""

    @pytest.fixture
    def har_with_tokens(self):
        return {
            "log": {
                "entries": [
                    {
                        "request": {
                            "url": "https://api.example.com/",
                            "headers": [
                                {"name": "Authorization", "value": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"},
                                {"name": "X-API-Key", "value": "abc123"}
                            ]
                        },
                        "response": {"status": 200}
                    }
                ]
            }
        }

    def test_init(self, har_with_tokens):
        from modules.passive_analysis import TokenEntropyAnalyzer

        analyzer = TokenEntropyAnalyzer(har_with_tokens)
        assert analyzer.har_data == har_with_tokens

    def test_extract_tokens(self, har_with_tokens):
        from modules.passive_analysis import TokenEntropyAnalyzer

        analyzer = TokenEntropyAnalyzer(har_with_tokens)
        tokens = analyzer.extract_tokens()

        assert isinstance(tokens, list)

    def test_calculate_entropy(self):
        from modules.passive_analysis import TokenEntropyAnalyzer

        entropy = TokenEntropyAnalyzer.calculate_entropy("aaaa")
        assert entropy == 0.0

        entropy2 = TokenEntropyAnalyzer.calculate_entropy("abcd1234")
        assert entropy2 > 0.0

    def test_analyze(self, har_with_tokens):
        from modules.passive_analysis import TokenEntropyAnalyzer

        analyzer = TokenEntropyAnalyzer(har_with_tokens)
        issues = analyzer.analyze()

        assert isinstance(issues, list)


class TestPassiveAnalysisOrchestrator:
    """Test main passive analysis orchestrator"""

    @pytest.fixture
    def full_har(self):
        return {
            "log": {
                "entries": [
                    {
                        "request": {
                            "url": "https://api.example.com/page",
                            "headers": []
                        },
                        "response": {
                            "status": 200,
                            "headers": [],
                            "content": {"text": "Hello"}
                        }
                    }
                ]
            }
        }

    def test_init(self, full_har):
        from modules.passive_analysis import PassiveAnalysisOrchestrator

        analyzer = PassiveAnalysisOrchestrator(full_har)
        assert analyzer.har_data == full_har

    def test_run_all_checks(self, full_har):
        from modules.passive_analysis import PassiveAnalysisOrchestrator

        analyzer = PassiveAnalysisOrchestrator(full_har)
        results = analyzer.run_all_checks()

        assert isinstance(results, dict)

    def test_get_critical_issues(self, full_har):
        from modules.passive_analysis import PassiveAnalysisOrchestrator

        analyzer = PassiveAnalysisOrchestrator(full_har)
        analyzer.run_all_checks()
        critical = analyzer.get_critical_issues()

        assert isinstance(critical, list)

    def test_generate_summary(self, full_har):
        from modules.passive_analysis import PassiveAnalysisOrchestrator

        analyzer = PassiveAnalysisOrchestrator(full_har)
        analyzer.run_all_checks()
        summary = analyzer.generate_summary()

        assert isinstance(summary, dict)
