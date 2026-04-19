"""Tests for the progress-callback + get_scan_progress additions to ZAPScanner."""
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.modules.setdefault('zapv2', MagicMock())


@pytest.fixture
def zap_config():
    return {'api_key': 'k', 'zap_url': 'http://localhost:8080'}


@pytest.fixture
def scan_config():
    return {
        'rate_limit': 10.0,
        'rate_burst': 20,
        'max_urls': 10,
        'max_fuzzable_urls': 3,
        'max_api_endpoints': 3,
        'max_scan_time': 1,
    }


@pytest.fixture
def har_data():
    return {
        'fuzzable_urls': [
            {'url': 'https://x/a', 'params': ['id']},
            {'url': 'https://x/b', 'params': ['file']},
        ],
        'api_endpoints': [
            {'url': 'https://x/api/u', 'params': []},
        ],
    }


class TestExecuteTargetedScansProgress:
    @patch('modules.zap_scanner.ZAPv2')
    @patch('modules.zap_scanner.time')
    def test_callback_receives_each_target(self, mock_time, mock_zapv2, zap_config, har_data, scan_config):
        from modules.zap_scanner import ZAPScanner

        mock_zap = MagicMock()
        mock_zap.ascan.scan.return_value = 'scan-1'
        mock_zap.ascan.status.return_value = '100'
        mock_zapv2.return_value = mock_zap
        mock_time.time.side_effect = [0.0] * 200

        events = []

        def cb(event):
            events.append(event)

        scanner = ZAPScanner(zap_config, har_data, scan_config)
        scanner.execute_targeted_scans(progress_callback=cb)

        # At least one 'scanning' event per target + one 'target_done' per target
        scanning_events = [e for e in events if e.get('phase') == 'scanning']
        done_events = [e for e in events if e.get('phase') == 'target_done']
        assert len(scanning_events) >= 3
        assert len(done_events) == 3
        assert done_events[0]['target_index'] == 1
        assert done_events[-1]['target_index'] == 3

    @patch('modules.zap_scanner.ZAPv2')
    @patch('modules.zap_scanner.time')
    def test_callback_exception_does_not_crash(self, mock_time, mock_zapv2, zap_config, har_data, scan_config):
        from modules.zap_scanner import ZAPScanner

        mock_zap = MagicMock()
        mock_zap.ascan.scan.return_value = 'scan-1'
        mock_zap.ascan.status.return_value = '100'
        mock_zapv2.return_value = mock_zap
        mock_time.time.side_effect = [0.0] * 200

        def bad_cb(event):
            raise RuntimeError("boom")

        scanner = ZAPScanner(zap_config, har_data, scan_config)
        results = scanner.execute_targeted_scans(progress_callback=bad_cb)
        # Should still complete without propagating the exception
        assert isinstance(results, list)

    @patch('modules.zap_scanner.ZAPv2')
    @patch('modules.zap_scanner.time')
    def test_no_callback_backward_compatible(self, mock_time, mock_zapv2, zap_config, har_data, scan_config):
        from modules.zap_scanner import ZAPScanner

        mock_zap = MagicMock()
        mock_zap.ascan.scan.return_value = 'scan-1'
        mock_zap.ascan.status.return_value = '100'
        mock_zapv2.return_value = mock_zap
        mock_time.time.side_effect = [0.0] * 200

        scanner = ZAPScanner(zap_config, har_data, scan_config)
        results = scanner.execute_targeted_scans()
        assert isinstance(results, list)


class TestGetScanProgress:
    @patch('modules.zap_scanner.ZAPv2')
    def test_returns_snapshot(self, mock_zapv2, zap_config, har_data, scan_config):
        from modules.zap_scanner import ZAPScanner

        mock_zap = MagicMock()
        mock_zap.pscan.records_to_scan = 3
        mock_zap.core.alerts.return_value = [
            {'risk': 'High'},
            {'risk': 'High'},
            {'risk': 'Medium'},
            {'risk': 'Low'},
        ]
        mock_zap.core.sites = ['https://x.com']
        mock_zapv2.return_value = mock_zap

        scanner = ZAPScanner(zap_config, har_data, scan_config)
        snap = scanner.get_scan_progress()
        assert snap['passive_records_to_scan'] == 3
        assert snap['alerts_by_risk']['High'] == 2
        assert snap['alerts_by_risk']['Medium'] == 1
        assert 'https://x.com' in snap['sites']

    @patch('modules.zap_scanner.ZAPv2')
    def test_get_scan_progress_swallows_errors(self, mock_zapv2, zap_config, har_data, scan_config):
        from modules.zap_scanner import ZAPScanner

        mock_zap = MagicMock()
        # pscan/alerts/sites all raise
        type(mock_zap.pscan).records_to_scan = property(lambda s: (_ for _ in ()).throw(RuntimeError("down")))
        mock_zap.core.alerts.side_effect = RuntimeError("down")
        type(mock_zap.core).sites = property(lambda s: (_ for _ in ()).throw(RuntimeError("down")))
        mock_zapv2.return_value = mock_zap

        scanner = ZAPScanner(zap_config, har_data, scan_config)
        snap = scanner.get_scan_progress()
        assert snap['passive_records_to_scan'] is None
        assert snap['alerts_by_risk']['High'] == 0
        assert snap['sites'] == []
