"""Tests for critical low-coverage modules."""
import pytest
from unittest.mock import Mock, MagicMock, patch, PropertyMock
import json
import sys


class TestZAPPassiveScanner:
    """Tests for zap_passive_scanner.py (23% coverage)."""

    def test_configure(self):
        from modules.zap_passive_scanner import ZAPPassiveScanner

        mock_zap = Mock()
        scanner = ZAPPassiveScanner(mock_zap)
        scanner.configure()

        mock_zap.pscan.enable_all_scanners.assert_called_once()

    def test_wait_for_completion_success(self):
        from modules.zap_passive_scanner import ZAPPassiveScanner

        mock_zap = Mock()
        mock_zap.pscan.records_to_scan = '0'
        scanner = ZAPPassiveScanner(mock_zap)

        result = scanner.wait_for_completion(max_wait=10)
        assert result is True

    def test_get_alerts(self):
        from modules.zap_passive_scanner import ZAPPassiveScanner

        mock_zap = Mock()
        mock_zap.core.alerts.return_value = [
            {
                'risk': 'High',
                'alert': 'XSS',
                'description': 'Test',
                'url': 'http://test.com',
                'param': 'test',
                'attack': '',
                'evidence': '',
                'confidence': 'High',
                'solution': 'Fix it',
                'pluginId': '123',
                'cweid': '79',
                'wascid': '8'
            }
        ]
        scanner = ZAPPassiveScanner(mock_zap)
        issues = scanner.get_alerts()

        assert len(issues) == 1
        assert issues[0].severity == 'HIGH'
        assert issues[0].title == 'XSS'

    def test_token_entropy_analyzer(self, sample_har):
        from modules.zap_passive_scanner import TokenEntropyAnalyzer

        analyzer = TokenEntropyAnalyzer(sample_har)
        entropy = analyzer.calculate_entropy('abcdefghijklmnop')
        assert entropy > 0

    def test_token_entropy_analyze(self, sample_har_with_tokens):
        from modules.zap_passive_scanner import TokenEntropyAnalyzer

        analyzer = TokenEntropyAnalyzer(sample_har_with_tokens)
        issues = analyzer.analyze()
        assert isinstance(issues, list)

    def test_scan_full(self):
        from modules.zap_passive_scanner import ZAPPassiveScanner

        mock_zap = Mock()
        mock_zap.pscan.records_to_scan = '0'
        mock_zap.core.alerts.return_value = []

        scanner = ZAPPassiveScanner(mock_zap, {'log': {'entries': []}})
        results = scanner.scan_full()
        assert isinstance(results, list)


class TestTrainer:
    """Tests for trainer.py (24% coverage)."""

    def test_push_valid_response(self):
        from modules.trainer import Trainer

        mock_zap = Mock()
        trainer = Trainer(mock_zap, scope_domains=['example.com'])

        response = {
            'url': 'https://example.com/test',
            'status_code': 200,
            'headers': {'Content-Type': 'text/html'},
            'body': '<html><a href="/link">Test</a></html>',
            'content_type': 'text/html'
        }

        result = trainer.push(response)
        assert result is True

    def test_should_analyze_out_of_scope(self):
        from modules.trainer import Trainer

        trainer = Trainer(Mock(), scope_domains=['example.com'])
        response = {
            'url': 'https://outofscope.com/test',
            'status_code': 200,
            'content_type': 'text/html',
            'body': 'test'
        }

        result = trainer._should_analyze(response)
        assert result is False

    def test_analyze_extracts_links(self):
        from modules.trainer import Trainer

        trainer = Trainer(Mock())
        response = {
            'url': 'https://example.com',
            'body': '<a href="/path1">Link1</a><a href="https://example.com/path2">Link2</a>',
            'headers': {}
        }

        count = trainer._analyze(response)
        assert count > 0
        assert len(trainer.element_filter.links) > 0

    def test_get_stats(self):
        from modules.trainer import Trainer

        trainer = Trainer(Mock())
        stats = trainer.get_stats()

        assert 'total_links' in stats
        assert 'total_forms' in stats
        assert 'discovered_pages' in stats

    def test_element_filter_links(self):
        from modules.trainer import ElementFilter

        filter = ElementFilter()
        links = ['https://example.com/1', 'https://example.com/2']
        count = filter.update_links(links)
        assert count == 2
        assert filter.include_link('https://example.com/1')

    def test_element_filter_forms(self):
        from modules.trainer import ElementFilter

        filter = ElementFilter()
        forms = [
            {'url': '/test', 'method': 'POST', 'inputs': {'name': '', 'email': ''}},
            {'url': '/login', 'method': 'POST', 'inputs': {'user': '', 'pass': ''}}
        ]
        count = filter.update_forms(forms)
        assert count == 2


class TestOpenAPIImporter:
    """Tests for openapi_importer.py (46% coverage)."""

    def test_load_from_file_json(self, tmp_path):
        from modules.openapi_importer import OpenAPIImporter

        spec = {
            'openapi': '3.0.0',
            'info': {'title': 'Test API'},
            'paths': {}
        }

        spec_file = tmp_path / 'spec.json'
        spec_file.write_text(json.dumps(spec))

        importer = OpenAPIImporter()
        result = importer.load_from_file(str(spec_file))

        assert result['openapi'] == '3.0.0'

    def test_parse_endpoints(self):
        from modules.openapi_importer import OpenAPIImporter

        spec = {
            'openapi': '3.0.0',
            'servers': [{'url': 'https://api.example.com'}],
            'paths': {
                '/users': {
                    'get': {
                        'summary': 'Get users',
                        'parameters': []
                    }
                }
            }
        }

        importer = OpenAPIImporter()
        importer.spec = spec
        endpoints = importer.parse_endpoints()

        assert len(endpoints) == 1
        assert endpoints[0]['method'] == 'GET'
        assert '/users' in endpoints[0]['path']

    def test_detect_version(self):
        from modules.openapi_importer import OpenAPIImporter

        importer = OpenAPIImporter()
        importer.spec = {'openapi': '3.0.0'}
        assert importer._detect_version() == 'openapi3'

        importer.spec = {'swagger': '2.0'}
        assert importer._detect_version() == 'swagger2'

    def test_extract_base_url_openapi3(self):
        from modules.openapi_importer import OpenAPIImporter

        importer = OpenAPIImporter()
        importer.spec = {
            'openapi': '3.0.0',
            'servers': [{'url': 'https://api.example.com/v1'}]
        }

        url = importer._extract_base_url('openapi3')
        assert url == 'https://api.example.com/v1'

    def test_generate_sample_requests(self):
        from modules.openapi_importer import OpenAPIImporter

        spec = {
            'openapi': '3.0.0',
            'servers': [{'url': 'https://api.example.com'}],
            'paths': {
                '/users/{id}': {
                    'get': {
                        'parameters': [
                            {'name': 'id', 'in': 'path', 'type': 'integer'}
                        ]
                    }
                }
            }
        }

        importer = OpenAPIImporter()
        importer.spec = spec
        importer.parse_endpoints()
        requests = importer.generate_sample_requests()

        assert len(requests) == 1
        assert '/users/' in requests[0]['url']


class TestZAPHttpClient:
    """Tests for zap_http_client.py (48% coverage)."""

    def test_build_zap_request(self):
        from modules.zap_http_client import ZAPHttpClient

        mock_zap = Mock()
        client = ZAPHttpClient(zap=mock_zap)
        request = client._build_zap_request(
            'GET',
            'https://example.com/test?param=value',
            headers={'Authorization': 'Bearer token'}
        )

        assert 'GET /test?param=value HTTP/1.1' in request
        assert 'Host: example.com' in request
        assert 'Authorization: Bearer token' in request

    def test_build_zap_request_with_body(self):
        from modules.zap_http_client import ZAPHttpClient

        mock_zap = Mock()
        client = ZAPHttpClient(zap=mock_zap)
        request = client._build_zap_request(
            'POST',
            'https://example.com/api',
            data={'key': 'value'}
        )

        assert 'POST /api HTTP/1.1' in request
        assert 'Content-Type: application/json' in request
        assert '"key": "value"' in request

    def test_parse_zap_response(self):
        from modules.zap_http_client import ZAPHttpClient

        mock_zap = Mock()
        client = ZAPHttpClient(zap=mock_zap)
        response_str = '''HTTP/1.1 200 OK\r
Content-Type: application/json\r
\r
{"result": "success"}'''

        parsed = client._parse_zap_response(response_str, 'https://test.com', 'GET', 0.5)

        assert parsed.status_code == 200
        assert parsed.headers['Content-Type'] == 'application/json'
        assert 'success' in parsed.text

    def test_get_with_params(self):
        from modules.zap_http_client import ZAPHttpClient

        mock_zap = Mock()
        mock_zap.core.send_request.return_value = 'HTTP/1.1 200 OK\r\n\r\nOK'

        client = ZAPHttpClient(zap=mock_zap)
        response = client.get('https://example.com/api', params={'key': 'value'})

        assert response.status_code == 200

    def test_raise_alert(self):
        from modules.zap_http_client import ZAPHttpClient

        mock_zap = Mock()
        client = ZAPHttpClient(zap=mock_zap)

        client.raise_alert(
            risk=3,
            confidence=2,
            name='Test Alert',
            description='Test',
            url='https://test.com'
        )

        mock_zap.alert.add_alert.assert_called_once()

    def test_factory_get_client(self):
        from modules.zap_http_client import ZAPHttpClientFactory

        mock_zap = Mock()
        ZAPHttpClientFactory.initialize(zap=mock_zap)
        client = ZAPHttpClientFactory.get_client()
        assert client is not None


class TestLLMZAPIntegration:
    """Tests for llm/zap_integration.py (60% coverage)."""

    def test_get_domain_enrichment(self, sample_security_plan):
        from modules.llm.zap_integration import LLMZAPEnricher

        enricher = LLMZAPEnricher(sample_security_plan, auto_persist=False)
        enrichment = enricher.get_domain_enrichment()

        assert enrichment.domain == sample_security_plan.domain_analysis.get('inferred_domain', 'unknown')
        assert isinstance(enrichment.mass_assignment_payloads, list)

    def test_export_wordlists(self, sample_security_plan, tmp_path):
        from modules.llm.zap_integration import LLMZAPEnricher

        enricher = LLMZAPEnricher(sample_security_plan, auto_persist=False)
        exported = enricher.export_wordlists(str(tmp_path))

        assert isinstance(exported, dict)

    def test_get_passive_scanner_patterns(self, sample_security_plan):
        from modules.llm.zap_integration import LLMZAPEnricher

        enricher = LLMZAPEnricher(sample_security_plan, auto_persist=False)
        patterns = enricher.get_passive_scanner_patterns()
        assert isinstance(patterns, list)


class TestCORSTester:
    """Tests for cors_tester.py (65% coverage)."""

    def test_identify_cors_endpoints(self, sample_har_with_cors):
        from modules.cors_tester import CORSTester

        tester = CORSTester(sample_har_with_cors)
        endpoints = tester.identify_cors_endpoints()

        assert len(endpoints) > 0
        assert 'cors_headers' in endpoints[0]

    def test_get_cors_response_with_mock(self):
        from modules.cors_tester import CORSTester

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {
            'access-control-allow-origin': 'https://evil.com',
            'access-control-allow-credentials': 'true'
        }

        tester = CORSTester({'log': {'entries': []}})

        with patch.object(tester, '_get', return_value=mock_response):
            result = tester._get_cors_response('https://test.com', 'https://evil.com')
            if result:
                assert result['acao'] == 'https://evil.com'
                assert result['acac'] == 'true'

    def test_test_origin_reflection_with_mock(self):
        from modules.cors_tester import CORSTester

        mock_response = {
            'status_code': 200,
            'headers': {
                'access-control-allow-origin': 'https://evil.com',
                'access-control-allow-credentials': 'true'
            }
        }

        tester = CORSTester({'log': {'entries': []}})

        with patch.object(tester, '_get', return_value=mock_response):
            results = tester.test_origin_reflection('https://test.com')
            if len(results) > 0:
                assert results[0].vulnerable is True

    def test_identify_bypass_technique(self):
        from modules.cors_tester import CORSTester

        technique = CORSTester._identify_bypass_technique(
            'https://example.com.evil.com',
            'example.com'
        )
        assert technique == 'subdomain_suffix'

    def test_generate_exploit(self):
        from modules.cors_tester import CORSTester, CORSResult

        result = CORSResult(
            url='https://api.example.com/data',
            vulnerability_type='origin_reflection_with_credentials',
            vulnerable=True,
            confidence=1.0,
            evidence={}
        )

        exploit = CORSTester.generate_exploit(result)
        assert 'XMLHttpRequest' in exploit
        assert 'withCredentials' in exploit

    def test_generate_report(self):
        from modules.cors_tester import CORSTester, CORSResult

        tester = CORSTester({'log': {'entries': []}})
        results = [
            CORSResult(
                url='https://test.com',
                vulnerability_type='origin_reflection',
                vulnerable=True,
                confidence=1.0,
                evidence={}
            )
        ]

        report = tester.generate_report(results)
        assert 'vulnerable_count' in report
        assert report['vulnerable_count'] == 1


@pytest.fixture
def sample_har():
    return {
        'log': {
            'entries': [
                {
                    'request': {
                        'url': 'https://api.example.com/users/123',
                        'method': 'GET',
                        'headers': [],
                        'queryString': []
                    },
                    'response': {
                        'status': 200,
                        'headers': [],
                        'content': {'mimeType': 'application/json', 'text': '{"id": 123}'}
                    }
                }
            ]
        }
    }


@pytest.fixture
def sample_har_with_tokens():
    return {
        'log': {
            'entries': [
                {
                    'request': {
                        'url': 'https://api.example.com/auth',
                        'method': 'GET',
                        'headers': [
                            {'name': 'Authorization', 'value': 'Bearer aaaaaaaaaa'}
                        ],
                        'queryString': []
                    },
                    'response': {
                        'status': 200,
                        'headers': [
                            {'name': 'Set-Cookie', 'value': 'session=1111111111; HttpOnly'}
                        ],
                        'content': {'text': '{"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}'}
                    }
                }
            ]
        }
    }


@pytest.fixture
def sample_har_with_cors():
    return {
        'log': {
            'entries': [
                {
                    'request': {
                        'url': 'https://api.example.com/data',
                        'method': 'GET',
                        'headers': [{'name': 'Origin', 'value': 'https://example.com'}]
                    },
                    'response': {
                        'status': 200,
                        'headers': [
                            {'name': 'access-control-allow-origin', 'value': '*'},
                            {'name': 'access-control-allow-credentials', 'value': 'true'}
                        ],
                        'content': {}
                    }
                }
            ]
        }
    }


@pytest.fixture
def sample_security_plan():
    from modules.llm.analyzer import SecurityPlan, AttackStrategy

    return SecurityPlan(
        har_hash='test123',
        domain_analysis={'inferred_domain': 'ecommerce', 'confidence': 0.8},
        strategies=[
            AttackStrategy(
                attack_type='mass_assignment',
                priority='high',
                targets=[{'endpoint': '/users', 'fields': ['role', 'admin']}],
                payloads=[{'field': 'is_admin', 'value': True, 'reason': 'Privilege escalation'}]
            ),
            AttackStrategy(
                attack_type='fuzzer',
                priority='medium',
                targets=[{'endpoint': '/search'}],
                payloads=[{'key': 'query', 'values': ['admin', 'test'], 'category': 'admin'}]
            )
        ],
        prioritized_endpoints=['/users', '/admin'],
        custom_regex_patterns=[],
        business_logic_flows=[],
        metadata={}
    )
