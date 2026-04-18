"""Tests for Reporter module"""
import pytest
from unittest.mock import Mock, patch
import tempfile
import os


@pytest.fixture
def sample_alerts():
    return [
        {'risk': 'High', 'alert': 'SQL Injection', 'url': 'https://api.com/user', 'cweid': '89',
         'description': 'SQL injection vulnerability', 'pluginId': '40018', 'method': 'GET',
         'param': 'id', 'attack': "' OR 1=1--", 'evidence': 'error in your SQL syntax'},
        {'risk': 'Medium', 'alert': 'XSS', 'url': 'https://api.com/search', 'cweid': '79',
         'description': 'Cross-site scripting', 'pluginId': '40012', 'method': 'POST',
         'param': 'q', 'attack': '<script>alert(1)</script>'},
        {'risk': 'Low', 'alert': 'Cookie No HttpOnly', 'url': 'https://api.com/', 'cweid': '16',
         'description': 'Cookie without HttpOnly flag', 'pluginId': '10010'},
        {'risk': 'Informational', 'alert': 'Server Header', 'url': 'https://api.com/',
         'description': 'Server header disclosed', 'pluginId': '10036'}
    ]


@pytest.fixture
def config():
    return {
        'include_curl': True,
        'include_timeline': True,
        'include_owasp': True
    }


class TestReporter:
    def test_init(self, config):
        from modules.reporter import Reporter

        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = Reporter(output_dir=tmpdir, config=config)

            assert reporter.include_curl is True
            assert reporter.include_timeline is True
            assert reporter.include_owasp is True

    def test_init_creates_directory(self):
        from modules.reporter import Reporter

        with tempfile.TemporaryDirectory() as tmpdir:
            new_dir = os.path.join(tmpdir, 'new_output')
            reporter = Reporter(output_dir=new_dir)

            assert os.path.exists(new_dir)

    def test_add_timeline_event(self, config):
        from modules.reporter import Reporter

        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = Reporter(output_dir=tmpdir, config=config)
            reporter.add_timeline_event('scan_start', 'Started scan', {'target': 'https://api.com'})

            assert len(reporter.timeline) == 1
            assert reporter.timeline[0]['type'] == 'scan_start'
            assert reporter.timeline[0]['description'] == 'Started scan'

    def test_generate_console_report(self, sample_alerts, config, capsys):
        from modules.reporter import Reporter

        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = Reporter(output_dir=tmpdir, config=config)
            reporter.generate_console_report(sample_alerts)

            captured = capsys.readouterr()
            assert 'SECURITY SCAN RESULTS' in captured.out
            assert 'High:   1' in captured.out
            assert 'Medium: 1' in captured.out

    def test_save_json_report(self, sample_alerts, config):
        from modules.reporter import Reporter

        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = Reporter(output_dir=tmpdir, config=config)
            reporter.add_timeline_event('test', 'Test event')
            output_file = reporter.save_json_report(sample_alerts, 'HAR summary')

            assert os.path.exists(output_file)
            with open(output_file) as f:
                import json
                data = json.load(f)
                assert data['summary']['total_alerts'] == 4
                assert data['summary']['high'] == 1
                assert 'owasp_compliance' in data
                assert 'timeline' in data

    def test_save_sarif_report(self, sample_alerts, config):
        from modules.reporter import Reporter

        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = Reporter(output_dir=tmpdir, config=config)
            output_file = reporter.save_sarif_report(sample_alerts)

            assert os.path.exists(output_file)
            with open(output_file) as f:
                import json
                data = json.load(f)
                assert data['version'] == '2.1.0'
                assert len(data['runs']) == 1
                assert 'results' in data['runs'][0]

    def test_save_critical_findings(self, sample_alerts, config):
        from modules.reporter import Reporter

        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = Reporter(output_dir=tmpdir, config=config)
            output_file = reporter.save_critical_findings(sample_alerts)

            assert output_file is not None
            with open(output_file) as f:
                content = f.read()
                assert 'SQL Injection' in content
                assert 'XSS' in content
                assert 'curl' in content

    def test_save_critical_findings_no_critical(self, config):
        from modules.reporter import Reporter

        alerts = [{'risk': 'Low', 'alert': 'Info'}]

        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = Reporter(output_dir=tmpdir, config=config)
            output_file = reporter.save_critical_findings(alerts)

            assert output_file is None

    def test_generate_curl_get(self, config):
        from modules.reporter import Reporter

        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = Reporter(output_dir=tmpdir, config=config)

            alert = {'url': 'https://api.com/user', 'method': 'GET', 'param': 'id',
                     'attack': "' OR 1=1--", 'evidence': 'SQL error'}
            curl = reporter._generate_curl(alert)

            assert 'curl' in curl
            assert "id=' OR 1=1--" in curl or 'id=%27' in curl

    def test_generate_curl_post(self, config):
        from modules.reporter import Reporter

        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = Reporter(output_dir=tmpdir, config=config)

            alert = {'url': 'https://api.com/login', 'method': 'POST', 'param': 'username',
                     'attack': 'admin'}
            curl = reporter._generate_curl(alert)

            assert '-X POST' in curl
            assert "username=admin" in curl
            assert ("--data-raw" in curl) or ("-d " in curl)

    def test_risk_to_sarif_level(self):
        from modules.reporter import Reporter

        assert Reporter._risk_to_sarif_level('High') == 'error'
        assert Reporter._risk_to_sarif_level('Medium') == 'warning'
        assert Reporter._risk_to_sarif_level('Low') == 'note'
        assert Reporter._risk_to_sarif_level('Unknown') == 'none'

    def test_generate_executive_summary(self, sample_alerts, config):
        from modules.reporter import Reporter

        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = Reporter(output_dir=tmpdir, config=config)
            summary = reporter.generate_executive_summary(sample_alerts, '10 minutes')

            assert summary['total_findings'] == 4
            assert summary['critical_findings'] == 1
            assert summary['duration'] == '10 minutes'
            assert 'owasp_score' in summary

    def test_save_all_reports(self, sample_alerts, config):
        from modules.reporter import Reporter

        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = Reporter(output_dir=tmpdir, config=config)
            saved = reporter.save_all_reports(sample_alerts, formats=['json', 'sarif'])

            assert 'json' in saved
            assert 'sarif' in saved

    def test_save_html_report_with_zap(self, config):
        from modules.reporter import Reporter

        mock_zap = Mock()
        mock_zap.core.htmlreport.return_value = '<html>Report</html>'

        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = Reporter(output_dir=tmpdir, config=config)
            output_file = reporter.save_html_report(zap_client=mock_zap)

            assert output_file is not None
            with open(output_file) as f:
                assert '<html>Report</html>' in f.read()

    def test_save_html_report_no_zap(self, config):
        from modules.reporter import Reporter

        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = Reporter(output_dir=tmpdir, config=config)
            output_file = reporter.save_html_report()

            assert output_file is None

    def test_print_alert(self, capsys):
        from modules.reporter import Reporter

        alert = {'risk': 'High', 'alert': 'Test Alert', 'url': 'https://api.com',
                 'cweid': '89', 'description': 'Test description'}
        Reporter._print_alert(alert)

        captured = capsys.readouterr()
        assert '[High] Test Alert' in captured.out
        assert 'CWE: 89' in captured.out
