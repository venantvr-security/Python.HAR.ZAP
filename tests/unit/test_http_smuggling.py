"""Tests for HTTP smuggling module"""
import pytest
from unittest.mock import Mock, patch, MagicMock
import socket

from modules.http_smuggling import HTTPSmugglingTester, SmugglingResult


@pytest.fixture
def sample_har():
    return {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://example.com/api",
                        "headers": []
                    },
                    "response": {"status": 200}
                },
                {
                    "request": {
                        "method": "POST",
                        "url": "http://api.example.com:8080/data",
                        "headers": []
                    },
                    "response": {"status": 200}
                }
            ]
        }
    }


@pytest.fixture
def config():
    return {'smuggling_timeout': 5}


class TestHTTPSmugglingTester:
    """Test HTTP smuggling detection"""

    def test_init(self, sample_har, config):
        tester = HTTPSmugglingTester(sample_har, config)
        assert tester.har_data == sample_har
        assert tester.timeout == 5

    def test_identify_targets(self, sample_har, config):
        tester = HTTPSmugglingTester(sample_har, config)
        targets = tester.identify_targets()

        assert 'https://example.com' in targets
        assert 'http://api.example.com:8080' in targets

    def test_identify_targets_unique(self, config):
        har = {
            "log": {
                "entries": [
                    {"request": {"url": "https://example.com/page1"}},
                    {"request": {"url": "https://example.com/page2"}},
                    {"request": {"url": "https://example.com/page3"}}
                ]
            }
        }

        tester = HTTPSmugglingTester(har, config)
        targets = tester.identify_targets()

        assert len(targets) == 1
        assert 'https://example.com' in targets

    def test_build_raw_request(self, sample_har, config):
        tester = HTTPSmugglingTester(sample_har, config)
        payload = {
            'headers': {
                'Content-Length': '6',
                'Transfer-Encoding': 'chunked'
            },
            'body': '0\r\n\r\nG'
        }

        raw = tester._build_raw_request('example.com', payload)

        assert b'POST / HTTP/1.1' in raw
        assert b'Host: example.com' in raw
        assert b'Content-Length: 6' in raw
        assert b'Transfer-Encoding: chunked' in raw

    def test_build_raw_request_with_smuggled(self, sample_har, config):
        tester = HTTPSmugglingTester(sample_har, config)
        payload = {'headers': {}, 'body': '0\r\n\r\n'}
        smuggled = 'GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n'

        raw = tester._build_raw_request('example.com', payload, smuggled)

        assert b'GET /admin HTTP/1.1' in raw

    @patch('socket.create_connection')
    def test_send_raw_request_http(self, mock_conn, sample_har, config):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b'HTTP/1.1 200 OK\r\n\r\n'
        mock_conn.return_value.__enter__.return_value = mock_sock

        tester = HTTPSmugglingTester(sample_har, config)
        response = tester._send_raw_request('example.com', 80, b'GET / HTTP/1.1\r\n\r\n', False)

        assert b'200 OK' in response

    @patch('socket.create_connection')
    @patch('ssl.create_default_context')
    def test_send_raw_request_https(self, mock_ssl_ctx, mock_conn, sample_har, config):
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.recv.return_value = b'HTTP/1.1 200 OK\r\n\r\n'

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value.__enter__.return_value = mock_ssl_sock
        mock_ssl_ctx.return_value = mock_ctx

        mock_sock = MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock

        tester = HTTPSmugglingTester(sample_har, config)
        response = tester._send_raw_request('example.com', 443, b'GET / HTTP/1.1\r\n\r\n', True)

        assert response is not None

    @patch('socket.create_connection')
    def test_send_raw_request_timeout(self, mock_conn, sample_har, config):
        mock_conn.side_effect = socket.timeout("Connection timed out")

        tester = HTTPSmugglingTester(sample_har, config)
        response = tester._send_raw_request('example.com', 80, b'test', False)

        assert response == b'TIMEOUT'

    @patch('socket.create_connection')
    def test_send_raw_request_error(self, mock_conn, sample_har, config):
        mock_conn.side_effect = Exception("Connection refused")

        tester = HTTPSmugglingTester(sample_har, config)
        response = tester._send_raw_request('example.com', 80, b'test', False)

        assert b'Connection refused' in response

    def test_smuggle_payloads_constant(self):
        payloads = HTTPSmugglingTester.SMUGGLE_PAYLOADS
        assert 'CL.TE' in payloads
        assert 'TE.CL' in payloads
        assert 'TE.TE_obfuscate' in payloads

    def test_clte_payload_structure(self):
        payload = HTTPSmugglingTester.SMUGGLE_PAYLOADS['CL.TE']
        assert 'Content-Length' in payload['headers']
        assert 'Transfer-Encoding' in payload['headers']
        assert 'body' in payload

    def test_tecl_payload_structure(self):
        payload = HTTPSmugglingTester.SMUGGLE_PAYLOADS['TE.CL']
        assert 'Transfer-Encoding' in payload['headers']
        assert 'Content-Length' in payload['headers']


class TestSmugglingResult:
    """Test SmugglingResult dataclass"""

    def test_create_result(self):
        result = SmugglingResult(
            url='https://example.com',
            variant='CL.TE',
            vulnerable=True,
            confidence=0.9,
            evidence={'response': 'delayed'}
        )

        assert result.url == 'https://example.com'
        assert result.variant == 'CL.TE'
        assert result.vulnerable is True
        assert result.severity == 'Critical'
        assert result.cwe == 'CWE-444'

    def test_default_values(self):
        result = SmugglingResult(
            url='https://example.com',
            variant='Test',
            vulnerable=False,
            confidence=0.0,
            evidence={}
        )

        assert result.severity == 'Critical'
        assert result.cvss == 9.8
