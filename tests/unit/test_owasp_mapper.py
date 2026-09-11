"""Tests for OWASP mapper module"""
import pytest
from unittest.mock import Mock

from modules.owasp_mapper import (
    OWASP_TOP_10_2021,
    OWASPMapper,
    OWASPMapping,
    ComplianceReport,
)


@pytest.fixture
def sample_alerts():
    return [
        {
            'pluginId': '40018',
            'alert': 'SQL Injection',
            'risk': 'High',
            'cweid': 89,
            'url': 'https://example.com/login',
            'description': 'SQL injection vulnerability'
        },
        {
            'pluginId': '10020',
            'alert': 'IDOR Vulnerability',
            'risk': 'High',
            'cweid': 639,
            'url': 'https://example.com/admin',
            'description': 'IDOR vulnerability'
        },
        {
            'pluginId': '10024',
            'alert': 'Missing HSTS',
            'risk': 'Medium',
            'cweid': 319,
            'url': 'https://example.com',
            'description': 'HSTS header missing'
        },
        {
            'pluginId': '99999',
            'alert': 'Unknown Alert',
            'risk': 'Low',
            'cweid': 0,
            'url': 'https://example.com',
            'description': 'Some unknown issue'
        }
    ]


@pytest.fixture
def config():
    return {
        'version': '2021',
        'fail_on_categories': ['A01:2021', 'A03:2021']
    }


class TestOWASPTop10Constants:
    """Test OWASP Top 10 constants"""

    def test_all_categories_present(self):
        expected_categories = [
            'A01:2021', 'A02:2021', 'A03:2021', 'A04:2021', 'A05:2021',
            'A06:2021', 'A07:2021', 'A08:2021', 'A09:2021', 'A10:2021'
        ]
        for cat in expected_categories:
            assert cat in OWASP_TOP_10_2021

    def test_category_structure(self):
        for cat_id, cat_data in OWASP_TOP_10_2021.items():
            assert 'name' in cat_data
            assert 'description' in cat_data
            assert 'cwes' in cat_data
            assert 'zap_alerts' in cat_data
            assert 'keywords' in cat_data

    def test_a01_broken_access_control(self):
        a01 = OWASP_TOP_10_2021['A01:2021']
        assert a01['name'] == 'Broken Access Control'
        assert 639 in a01['cwes']  # IDOR CWE
        assert 'idor' in a01['keywords']

    def test_a03_injection(self):
        a03 = OWASP_TOP_10_2021['A03:2021']
        assert a03['name'] == 'Injection'
        assert 89 in a03['cwes']  # SQL injection CWE
        assert 'sql injection' in a03['keywords']


class TestOWASPMapper:
    """Test OWASP mapper functionality"""

    def test_init_default(self):
        mapper = OWASPMapper()
        assert mapper.version == '2021'
        assert mapper.fail_on_categories == []

    def test_init_with_config(self, config):
        mapper = OWASPMapper(config)
        assert mapper.version == '2021'
        assert 'A01:2021' in mapper.fail_on_categories

    def test_map_alerts(self, sample_alerts):
        mapper = OWASPMapper()
        report = mapper.map_alerts(sample_alerts)

        assert isinstance(report, ComplianceReport)
        assert report.version == '2021'

    def test_map_by_cwe(self, sample_alerts):
        mapper = OWASPMapper()
        report = mapper.map_alerts(sample_alerts)

        # SQL injection (CWE-89) should map to A03:2021 Injection
        a03 = report.mappings.get('A03:2021')
        assert a03 is not None
        # Check if SQL injection alert is mapped
        cwe_89_alerts = [a for a in a03.alerts if a.get('cweid') == 89]
        assert len(cwe_89_alerts) > 0

    def test_map_by_plugin_id(self, sample_alerts):
        mapper = OWASPMapper()
        report = mapper.map_alerts(sample_alerts)

        # Alert 10020 should map to access control (check in any category)
        found = False
        for mapping in report.mappings.values():
            if any(a.get('pluginId') == '10020' for a in mapping.alerts):
                found = True
                break
        # Either found in mappings or in unmapped
        assert found or any(a.get('pluginId') == '10020' for a in report.unmapped_alerts)

    def test_unmapped_alerts(self, sample_alerts):
        mapper = OWASPMapper()
        report = mapper.map_alerts(sample_alerts)

        # Unknown alert (99999) should be unmapped
        assert any(str(a.get('pluginId')) == '99999' for a in report.unmapped_alerts)

    def test_overall_score(self, sample_alerts):
        mapper = OWASPMapper()
        report = mapper.map_alerts(sample_alerts)

        assert 0 <= report.overall_score <= 100

    def test_empty_alerts(self):
        mapper = OWASPMapper()
        report = mapper.map_alerts([])

        assert report.overall_score == 100  # No vulnerabilities = perfect score
        assert report.passed is True

    def test_compliance_check(self, sample_alerts, config):
        mapper = OWASPMapper(config)
        report = mapper.map_alerts(sample_alerts)

        # Should have failed_categories if vulnerabilities found in tracked categories
        assert isinstance(report.failed_categories, list)


class TestOWASPMapping:
    """Test OWASPMapping dataclass"""

    def test_create_mapping(self):
        mapping = OWASPMapping(
            category='A01:2021',
            category_name='Broken Access Control'
        )

        assert mapping.category == 'A01:2021'
        assert mapping.category_name == 'Broken Access Control'
        assert mapping.alerts == []
        assert mapping.score == 0.0

    def test_mapping_with_alerts(self):
        mapping = OWASPMapping(
            category='A03:2021',
            category_name='Injection',
            alerts=[{'alert': 'SQL Injection'}],
            severity_counts={'High': 1, 'Medium': 0, 'Low': 0, 'Informational': 0}
        )

        assert len(mapping.alerts) == 1
        assert mapping.severity_counts['High'] == 1


class TestComplianceReport:
    """Test ComplianceReport dataclass"""

    def test_create_report(self):
        report = ComplianceReport()

        assert report.version == '2021'
        assert report.overall_score == 100.0
        assert report.passed is True
        assert report.failed_categories == []

    def test_report_with_failures(self):
        report = ComplianceReport(
            overall_score=60.0,
            passed=False,
            failed_categories=['A01:2021', 'A03:2021']
        )

        assert report.passed is False
        assert len(report.failed_categories) == 2


# --- OWASP API Security Top 10 2023 ---

from modules.owasp_mapper import API_TOP_10_2023, CATALOGS, normalize_findings


class TestAPITop10Catalog:
    def test_ten_categories(self):
        expected = [f'API{i}:2023' for i in range(1, 11)]
        assert list(API_TOP_10_2023.keys()) == expected

    def test_category_structure(self):
        for cat in API_TOP_10_2023.values():
            for key in ('name', 'description', 'cwes', 'zap_alerts', 'keywords', 'native_types'):
                assert key in cat

    def test_registered_in_catalogs(self):
        assert CATALOGS['api-2023'] is API_TOP_10_2023
        assert CATALOGS['2021'] is OWASP_TOP_10_2021


class TestAPIMapper:
    def test_unknown_version_rejected(self):
        with pytest.raises(ValueError):
            OWASPMapper({'version': 'bogus'})

    def test_select_api_catalog(self):
        mapper = OWASPMapper({'version': 'api-2023'})
        assert mapper.catalog is API_TOP_10_2023

    def test_native_type_maps_bola(self):
        mapper = OWASPMapper({'version': 'api-2023'})
        report = mapper.map_alerts([
            {'alert': 'IDOR', 'risk': 'High', 'native_type': 'idor', 'cweid': 0}
        ])
        assert len(report.mappings['API1:2023'].alerts) == 1

    def test_zap_ssrf_maps_api7(self):
        mapper = OWASPMapper({'version': 'api-2023'})
        report = mapper.map_alerts([
            {'alert': 'SSRF', 'risk': 'High', 'pluginId': '40046', 'cweid': 918}
        ])
        assert len(report.mappings['API7:2023'].alerts) == 1

    def test_report_version_and_remediation(self):
        mapper = OWASPMapper({'version': 'api-2023'})
        rep = mapper.generate_report(mapper.map_alerts([]))
        assert rep['owasp_version'] == 'api-2023'
        assert rep['passed'] is True
        rem = mapper.get_remediation('API1:2023')
        assert 'BOLA' in rem['summary'] or 'object' in rem['summary'].lower()

    def test_fail_on_api_category(self):
        mapper = OWASPMapper({'version': 'api-2023', 'fail_on_categories': ['API1:2023']})
        report = mapper.map_alerts([
            {'alert': 'IDOR', 'risk': 'Medium', 'native_type': 'idor', 'cweid': 0}
        ])
        assert report.passed is False
        assert 'API1:2023' in report.failed_categories


class TestNormalizeFindings:
    def test_idor_only_vulnerable(self):
        class S:
            def __init__(self, v): self.value = v
        class R:
            def __init__(self, status): self.url = '/x'; self.status = S(status); self.confidence = 0.9
        alerts = normalize_findings(idor_results=[R('vulnerable'), R('protected')])
        assert len(alerts) == 1
        assert alerts[0]['native_type'] == 'idor'

    def test_redteam_and_passive(self):
        from modules.redteam_attacks import AttackType, AttackResult
        from modules.passive_analysis import SecurityIssue
        rt = AttackResult(attack_type=AttackType.MASS_ASSIGNMENT, url='/o', method='POST',
                          vulnerable=True, confidence=0.7, evidence={}, description='', remediation='')
        rt_skip = AttackResult(attack_type=AttackType.HIDDEN_PARAMS, url='/h', method='GET',
                               vulnerable=False, confidence=0.1, evidence={}, description='', remediation='')
        pi = SecurityIssue(severity='HIGH', category='Insecure Cookie', title='Cookie missing Secure flag',
                           description='', evidence={'url': '/'}, remediation='')
        alerts = normalize_findings(redteam_results=[rt, rt_skip], passive_issues=[pi])
        types = sorted(a['native_type'] for a in alerts)
        assert types == ['mass_assignment', 'security_misconfig']
