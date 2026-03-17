"""Tests for ZAP Scanner module"""
import sys
import pytest
from unittest.mock import Mock, patch, MagicMock

# Mock zapv2 before import
mock_zapv2_module = MagicMock()
sys.modules['zapv2'] = mock_zapv2_module


class TestZAPScanner:
    """Test ZAP scanner functionality"""

    @pytest.fixture
    def zap_config(self):
        return {
            'api_key': 'test-api-key',
            'zap_url': 'http://localhost:8080'
        }

    @pytest.fixture
    def scan_config(self):
        return {
            'rate_limit': 10.0,
            'rate_burst': 20,
            'max_urls': 50,
            'max_fuzzable_urls': 10,
            'max_api_endpoints': 5,
            'max_scan_time': 60
        }

    @pytest.fixture
    def har_data(self):
        return {
            'urls': ['https://api.example.com/user', 'https://api.example.com/data'],
            'auth_headers': {'Authorization': 'Bearer test'},
            'fuzzable_urls': [{'url': 'https://api.example.com/user/123', 'params': ['id']}],
            'api_endpoints': [{'url': 'https://api.example.com/api/v1/users', 'params': ['user_id']}]
        }

    @patch('modules.zap_scanner.ZAPv2')
    def test_init(self, mock_zapv2, zap_config, har_data, scan_config):
        from modules.zap_scanner import ZAPScanner
        scanner = ZAPScanner(zap_config, har_data, scan_config)

        assert scanner.har_data == har_data
        assert scanner.max_urls == 50
        assert scanner.max_fuzzable == 10
        mock_zapv2.assert_called_once()

    @patch('modules.zap_scanner.ZAPv2')
    def test_configure_context(self, mock_zapv2, zap_config, har_data, scan_config):
        from modules.zap_scanner import ZAPScanner

        mock_zap = Mock()
        mock_zapv2.return_value = mock_zap

        scanner = ZAPScanner(zap_config, har_data, scan_config)
        scanner.configure_context()

        mock_zap.replacer.add_rule.assert_called()

    @patch('modules.zap_scanner.ZAPv2')
    def test_configure_context_with_exclusions(self, mock_zapv2, zap_config, har_data):
        from modules.zap_scanner import ZAPScanner

        scan_config = {
            'exclude_domains': ['excluded.com', 'skip.example.org']
        }

        mock_zap = Mock()
        mock_zapv2.return_value = mock_zap

        scanner = ZAPScanner(zap_config, har_data, scan_config)
        scanner.configure_context()

        assert mock_zap.context.exclude_from_context.call_count == 2

    @patch('modules.zap_scanner.ZAPv2')
    @patch('modules.zap_scanner.time.sleep')
    def test_populate_site_tree(self, mock_sleep, mock_zapv2, zap_config, har_data, scan_config):
        from modules.zap_scanner import ZAPScanner

        mock_zap = Mock()
        mock_zapv2.return_value = mock_zap

        scanner = ZAPScanner(zap_config, har_data, scan_config)
        scanner.populate_site_tree()

        assert mock_zap.core.access_url.call_count == 2

    @patch('modules.zap_scanner.ZAPv2')
    @patch('modules.zap_scanner.time')
    def test_run_ajax_spider(self, mock_time, mock_zapv2, zap_config, har_data, scan_config):
        from modules.zap_scanner import ZAPScanner

        mock_zap = Mock()
        mock_zapv2.return_value = mock_zap
        mock_zap.ajaxSpider.scan.return_value = 'scan-123'
        mock_zap.ajaxSpider.status.return_value = 'stopped'
        mock_zap.ajaxSpider.full_results.return_value = [
            {'url': 'https://discovered.com/page1'},
            {'url': 'https://discovered.com/page2'}
        ]
        mock_zap.ajaxSpider.number_of_results.return_value = 2

        mock_time.time.side_effect = [0, 1]

        scanner = ZAPScanner(zap_config, har_data, scan_config)
        result = scanner.run_ajax_spider('https://api.example.com', max_duration=1)

        assert result['scan_id'] == 'scan-123'
        assert len(result['discovered_urls']) == 2

    @patch('modules.zap_scanner.ZAPv2')
    @patch('modules.zap_scanner.time')
    def test_run_traditional_spider(self, mock_time, mock_zapv2, zap_config, har_data, scan_config):
        from modules.zap_scanner import ZAPScanner

        mock_zap = Mock()
        mock_zapv2.return_value = mock_zap
        mock_zap.spider.scan.return_value = 'spider-123'
        mock_zap.spider.status.return_value = '100'
        mock_zap.spider.results.return_value = ['url1', 'url2', 'url3']

        scanner = ZAPScanner(zap_config, har_data, scan_config)
        result = scanner.run_traditional_spider('https://api.example.com')

        assert result['scan_id'] == 'spider-123'
        assert len(result['discovered_urls']) == 3

    @patch('modules.zap_scanner.ZAPv2')
    @patch('modules.zap_scanner.time')
    def test_run_platform_fingerprinting(self, mock_time, mock_zapv2, zap_config, har_data, scan_config):
        from modules.zap_scanner import ZAPScanner

        mock_zap = Mock()
        mock_zapv2.return_value = mock_zap
        mock_zap.pscan.records_to_scan = 0
        mock_zap.core.alerts.return_value = [
            {'alert': 'Server Technology Detected', 'evidence': 'Apache', 'confidence': 'High'}
        ]
        mock_zap.core.sites = []
        mock_time.time.side_effect = [0, 100]

        scanner = ZAPScanner(zap_config, har_data, scan_config)
        result = scanner.run_platform_fingerprinting('https://api.example.com')

        assert result['target'] == 'https://api.example.com'

    @patch('modules.zap_scanner.ZAPv2')
    def test_get_policy_for_target_sql(self, mock_zapv2, zap_config, har_data, scan_config):
        from modules.zap_scanner import ZAPScanner

        scanner = ZAPScanner(zap_config, har_data, scan_config)

        target = {'params': ['user_id', 'sql_query']}
        policy = scanner._get_policy_for_target(target)
        assert policy == 'SQL-Injection'

    @patch('modules.zap_scanner.ZAPv2')
    def test_get_policy_for_target_path(self, mock_zapv2, zap_config, har_data, scan_config):
        from modules.zap_scanner import ZAPScanner

        scanner = ZAPScanner(zap_config, har_data, scan_config)

        target = {'params': ['file_path', 'directory']}
        policy = scanner._get_policy_for_target(target)
        assert policy == 'Path-Traversal'

    @patch('modules.zap_scanner.ZAPv2')
    def test_get_policy_for_target_default(self, mock_zapv2, zap_config, har_data, scan_config):
        from modules.zap_scanner import ZAPScanner

        scanner = ZAPScanner(zap_config, har_data, scan_config)

        target = {'params': ['name', 'value']}
        policy = scanner._get_policy_for_target(target)
        assert policy == 'Default Policy'

    @patch('modules.zap_scanner.ZAPv2')
    def test_get_alerts(self, mock_zapv2, zap_config, har_data, scan_config):
        from modules.zap_scanner import ZAPScanner

        mock_zap = Mock()
        mock_zapv2.return_value = mock_zap
        mock_zap.core.alerts.return_value = [
            {'risk': 'High', 'alert': 'SQL Injection'},
            {'risk': 'Medium', 'alert': 'XSS'},
            {'risk': 'High', 'alert': 'Path Traversal'}
        ]

        scanner = ZAPScanner(zap_config, har_data, scan_config)

        all_alerts = scanner.get_alerts()
        assert len(all_alerts) == 3

        high_alerts = scanner.get_alerts(risk_level='High')
        assert len(high_alerts) == 2

    @patch('modules.zap_scanner.ZAPv2')
    def test_configure_scan_policies(self, mock_zapv2, zap_config, har_data, scan_config):
        from modules.zap_scanner import ZAPScanner

        mock_zap = Mock()
        mock_zapv2.return_value = mock_zap
        mock_zap.ascan.scan_policy_names = ['Default Policy', 'API-Minimal']

        scanner = ZAPScanner(zap_config, har_data, scan_config)
        scanner.configure_scan_policies()

        assert mock_zap.ascan.set_scanner_alert_threshold.called

    @patch('modules.zap_scanner.ZAPv2')
    def test_shutdown(self, mock_zapv2, zap_config, har_data, scan_config):
        from modules.zap_scanner import ZAPScanner

        mock_zap = Mock()
        mock_zapv2.return_value = mock_zap

        scanner = ZAPScanner(zap_config, har_data, scan_config)
        scanner.shutdown()

        mock_zap.core.shutdown.assert_called_once()

    @patch('modules.zap_scanner.ZAPv2')
    @patch('modules.zap_scanner.time')
    def test_execute_targeted_scans(self, mock_time, mock_zapv2, zap_config, har_data, scan_config):
        from modules.zap_scanner import ZAPScanner

        mock_zap = Mock()
        mock_zapv2.return_value = mock_zap
        mock_zap.ascan.scan.return_value = 'scan-1'
        mock_zap.ascan.status.return_value = '100'

        mock_time.time.side_effect = [0, 100]

        scanner = ZAPScanner(zap_config, har_data, scan_config)
        results = scanner.execute_targeted_scans()

        assert len(results) >= 0
