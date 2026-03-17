"""Tests for Timing Analysis module"""
import pytest
from unittest.mock import Mock, patch


@pytest.fixture
def sample_har():
    return {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/user?id=123&name=test",
                        "headers": [{"name": "Authorization", "value": "Bearer token"}]
                    },
                    "response": {"status": 200}
                },
                {
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.com/search",
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "postData": {"text": '{"query": "test", "filter": "active"}'}
                    },
                    "response": {"status": 200}
                },
                {
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.com/login",
                        "headers": [{"name": "Content-Type", "value": "application/x-www-form-urlencoded"}],
                        "postData": {"text": "username=admin&password=secret"}
                    },
                    "response": {"status": 200}
                }
            ]
        }
    }


@pytest.fixture
def config():
    return {
        'timing_timeout': 10,
        'timing_delay': 3,
        'timing_max_params': 5
    }


class TestTimingResult:
    def test_create_result(self):
        from modules.timing_analysis import TimingResult

        result = TimingResult(
            url='https://api.example.com/user',
            parameter='id',
            payload="' AND SLEEP(3)--",
            vulnerable=True,
            confidence=0.85,
            evidence={'category': 'sql_mysql', 'time_difference': 3.2}
        )

        assert result.vulnerable is True
        assert result.confidence == 0.85
        assert result.severity == 'High'
        assert result.cwe == 'CWE-208'


class TestTimingStats:
    def test_calculate_stats(self):
        from modules.timing_analysis import TimingStats

        stats = TimingStats(samples=[1.0, 1.2, 0.9, 1.1, 1.0])
        stats.calculate()

        assert abs(stats.mean - 1.04) < 0.01
        assert stats.median == 1.0
        assert stats.min_time == 0.9
        assert stats.max_time == 1.2

    def test_calculate_empty(self):
        from modules.timing_analysis import TimingStats

        stats = TimingStats(samples=[])
        stats.calculate()

        assert stats.mean == 0.0

    def test_calculate_single_sample(self):
        from modules.timing_analysis import TimingStats

        stats = TimingStats(samples=[1.5])
        stats.calculate()

        assert stats.mean == 0.0


class TestTimingAnalyzer:
    def test_init(self, sample_har, config):
        from modules.timing_analysis import TimingAnalyzer

        analyzer = TimingAnalyzer(sample_har, config)

        assert analyzer.har_data == sample_har
        assert analyzer.timeout == 10
        assert analyzer.delay_target == 3
        assert analyzer._use_zap is False

    def test_init_with_zap(self, sample_har, config):
        from modules.timing_analysis import TimingAnalyzer

        mock_zap = Mock()
        analyzer = TimingAnalyzer(sample_har, config, zap_client=mock_zap)

        assert analyzer._use_zap is True

    def test_identify_injection_points_query(self, sample_har, config):
        from modules.timing_analysis import TimingAnalyzer

        analyzer = TimingAnalyzer(sample_har, config)
        points = analyzer.identify_injection_points()

        query_points = [p for p in points if p['location'] == 'query']
        assert len(query_points) >= 2
        param_names = [p['param_name'] for p in query_points]
        assert 'id' in param_names
        assert 'name' in param_names

    def test_identify_injection_points_json_body(self, sample_har, config):
        from modules.timing_analysis import TimingAnalyzer

        analyzer = TimingAnalyzer(sample_har, config)
        points = analyzer.identify_injection_points()

        json_points = [p for p in points if p['location'] == 'body_json']
        assert len(json_points) >= 1

    def test_identify_injection_points_form_body(self, sample_har, config):
        from modules.timing_analysis import TimingAnalyzer

        analyzer = TimingAnalyzer(sample_har, config)
        points = analyzer.identify_injection_points()

        form_points = [p for p in points if p['location'] == 'body_form']
        assert len(form_points) >= 1

    def test_identify_injection_points_empty(self, config):
        from modules.timing_analysis import TimingAnalyzer

        har = {"log": {"entries": []}}
        analyzer = TimingAnalyzer(har, config)
        points = analyzer.identify_injection_points()

        assert points == []

    @patch('requests.get')
    def test_get_without_zap(self, mock_get, sample_har, config):
        from modules.timing_analysis import TimingAnalyzer

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'OK'
        mock_response.headers = {}
        mock_response.text = 'OK'
        mock_get.return_value = mock_response

        analyzer = TimingAnalyzer(sample_har, config)
        result = analyzer._get('https://api.example.com/test')

        assert result['status_code'] == 200

    def test_get_with_zap(self, sample_har, config):
        from modules.timing_analysis import TimingAnalyzer

        mock_zap = Mock()
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.content = b'OK'
        mock_resp.headers = {}
        mock_resp.text = 'OK'
        mock_zap.get.return_value = mock_resp

        analyzer = TimingAnalyzer(sample_har, config, zap_client=mock_zap)
        result = analyzer._get('https://api.example.com/test')

        assert result['status_code'] == 200

    @patch('requests.post')
    def test_post_without_zap(self, mock_post, sample_har, config):
        from modules.timing_analysis import TimingAnalyzer

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'OK'
        mock_response.headers = {}
        mock_response.text = 'OK'
        mock_post.return_value = mock_response

        analyzer = TimingAnalyzer(sample_har, config)
        result = analyzer._post('https://api.example.com/test', data='test=1')

        assert result['status_code'] == 200

    def test_post_with_zap(self, sample_har, config):
        from modules.timing_analysis import TimingAnalyzer

        mock_zap = Mock()
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_resp.content = b'OK'
        mock_resp.headers = {}
        mock_resp.text = 'OK'
        mock_zap.post.return_value = mock_resp

        analyzer = TimingAnalyzer(sample_har, config, zap_client=mock_zap)
        result = analyzer._post('https://api.example.com/test', data='test=1')

        assert result['status_code'] == 200

    def test_raise_alert_with_zap(self, sample_har, config):
        from modules.timing_analysis import TimingAnalyzer, TimingResult

        mock_zap = Mock()
        analyzer = TimingAnalyzer(sample_har, config, zap_client=mock_zap)

        result = TimingResult(
            url='https://api.example.com/user',
            parameter='id',
            payload="' AND SLEEP(3)--",
            vulnerable=True,
            confidence=0.85,
            evidence={'category': 'sql_mysql', 'time_difference': 3.2}
        )

        analyzer._raise_alert(result)
        mock_zap.raise_alert.assert_called_once()

    def test_raise_alert_without_zap(self, sample_har, config):
        from modules.timing_analysis import TimingAnalyzer, TimingResult

        analyzer = TimingAnalyzer(sample_har, config)

        result = TimingResult(
            url='https://api.example.com/user',
            parameter='id',
            payload="' AND SLEEP(3)--",
            vulnerable=True,
            confidence=0.85,
            evidence={'category': 'sql_mysql'}
        )

        # Should not raise exception
        analyzer._raise_alert(result)

    def test_inject_payload_query(self, sample_har, config):
        from modules.timing_analysis import TimingAnalyzer

        analyzer = TimingAnalyzer(sample_har, config)
        injection_point = {
            'url': 'https://api.example.com/user?id=123',
            'param_name': 'id',
            'location': 'query'
        }

        result = analyzer._inject_payload(injection_point, "' OR 1=1--")
        assert "' OR 1=1--" in result or "%27" in result

    def test_inject_body_json(self, sample_har, config):
        from modules.timing_analysis import TimingAnalyzer

        analyzer = TimingAnalyzer(sample_har, config)
        injection_point = {
            'location': 'body_json',
            'param_name': 'query',
            'original_body': {'query': 'test', 'filter': 'active'}
        }

        result = analyzer._inject_body(injection_point, "malicious")
        assert result['query'] == 'malicious'
        assert result['filter'] == 'active'

    def test_inject_body_form(self, sample_har, config):
        from modules.timing_analysis import TimingAnalyzer

        analyzer = TimingAnalyzer(sample_har, config)
        injection_point = {
            'location': 'body_form',
            'param_name': 'username',
            'original_body': 'username=admin&password=secret'
        }

        result = analyzer._inject_body(injection_point, "hacker")
        assert 'username=hacker' in result
        assert 'password=secret' in result

    @patch('requests.get')
    def test_measure_baseline(self, mock_get, sample_har, config):
        from modules.timing_analysis import TimingAnalyzer

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'OK'
        mock_response.headers = {}
        mock_response.text = 'OK'
        mock_get.return_value = mock_response

        analyzer = TimingAnalyzer(sample_har, config)
        injection_point = {
            'url': 'https://api.example.com/test',
            'method': 'GET',
            'headers': {}
        }

        stats = analyzer.measure_baseline(injection_point)
        assert len(stats.samples) == 5

    def test_analyze_timing_difference_no_samples(self, sample_har, config):
        from modules.timing_analysis import TimingAnalyzer, TimingStats

        analyzer = TimingAnalyzer(sample_har, config)

        baseline = TimingStats(samples=[])
        payload = TimingStats(samples=[])

        vulnerable, confidence = analyzer.analyze_timing_difference(baseline, payload)
        assert vulnerable is False
        assert confidence == 0.0

    def test_analyze_timing_difference_not_vulnerable(self, sample_har, config):
        from modules.timing_analysis import TimingAnalyzer, TimingStats

        analyzer = TimingAnalyzer(sample_har, config)

        baseline = TimingStats(samples=[0.5, 0.6, 0.5, 0.55, 0.52])
        baseline.calculate()

        payload = TimingStats(samples=[0.6, 0.7, 0.65])
        payload.calculate()

        vulnerable, confidence = analyzer.analyze_timing_difference(baseline, payload)
        assert vulnerable is False

    def test_analyze_timing_difference_vulnerable(self, sample_har, config):
        from modules.timing_analysis import TimingAnalyzer, TimingStats

        analyzer = TimingAnalyzer(sample_har, config)

        baseline = TimingStats(samples=[0.5, 0.6, 0.5, 0.55, 0.52])
        baseline.calculate()

        payload = TimingStats(samples=[3.5, 3.6, 3.55])
        payload.calculate()

        vulnerable, confidence = analyzer.analyze_timing_difference(baseline, payload)
        assert vulnerable is True
        assert confidence > 0.6

    def test_generate_report(self, sample_har, config):
        from modules.timing_analysis import TimingAnalyzer, TimingResult

        analyzer = TimingAnalyzer(sample_har, config)

        results = [
            TimingResult(
                url='https://api.example.com/user',
                parameter='id',
                payload="' AND SLEEP(3)--",
                vulnerable=True,
                confidence=0.85,
                evidence={'category': 'sql_mysql', 'time_difference': 3.2}
            ),
            TimingResult(
                url='https://api.example.com/search',
                parameter='query',
                payload="; sleep 3",
                vulnerable=True,
                confidence=0.75,
                evidence={'category': 'command_unix', 'time_difference': 3.1}
            )
        ]

        report = analyzer.generate_report(results)

        assert report['vulnerable_count'] == 2
        assert 'sql_mysql' in report['by_category']
        assert 'command_unix' in report['by_category']
        assert len(report['findings']) == 2

    def test_timing_payloads_constant(self):
        from modules.timing_analysis import TimingAnalyzer

        assert 'sql_mysql' in TimingAnalyzer.TIMING_PAYLOADS
        assert 'sql_postgres' in TimingAnalyzer.TIMING_PAYLOADS
        assert 'command_unix' in TimingAnalyzer.TIMING_PAYLOADS
        assert len(TimingAnalyzer.TIMING_PAYLOADS['sql_mysql']) > 0
