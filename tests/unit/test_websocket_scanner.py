"""Tests for WebSocket Scanner module"""
import pytest
from unittest.mock import Mock, patch, AsyncMock
import asyncio
import sys

# Skip async tests if websockets not installed
websockets_installed = pytest.importorskip("websockets", reason="websockets not installed")


@pytest.fixture
def sample_har():
    return {
        'entries': [
            {
                'request': {
                    'url': 'https://api.example.com/socket',
                    'headers': [
                        {'name': 'Upgrade', 'value': 'websocket'},
                        {'name': 'Origin', 'value': 'https://example.com'},
                        {'name': 'Sec-WebSocket-Protocol', 'value': 'graphql-ws,subscriptions-transport-ws'}
                    ]
                },
                'response': {'status': 101}
            },
            {
                'request': {
                    'url': 'wss://api.example.com/ws/chat',
                    'headers': []
                },
                'response': {'status': 101}
            },
            {
                'request': {
                    'url': 'https://api.example.com/socket.io/path',
                    'headers': []
                },
                'response': {'status': 200}
            },
            {
                'request': {
                    'url': 'https://api.example.com/rest/users',
                    'headers': []
                },
                'response': {'status': 200}
            }
        ]
    }


@pytest.fixture
def config():
    return {
        'timeout': 10,
        'max_messages': 50
    }


class TestWebSocketEndpoint:
    def test_create_endpoint(self):
        from modules.websocket_scanner import WebSocketEndpoint

        endpoint = WebSocketEndpoint(url='wss://api.com/ws')

        assert endpoint.url == 'wss://api.com/ws'
        assert endpoint.origin is None
        assert endpoint.protocols == []
        assert endpoint.requires_auth is False
        assert endpoint.messages_captured == []


class TestWebSocketVulnerability:
    def test_create_vulnerability(self):
        from modules.websocket_scanner import WebSocketVulnerability

        vuln = WebSocketVulnerability(
            type='CSWSH',
            endpoint='wss://api.com/ws',
            severity='High',
            description='Cross-Site WebSocket Hijacking',
            remediation='Validate Origin header'
        )

        assert vuln.type == 'CSWSH'
        assert vuln.severity == 'High'


class TestWebSocketScanner:
    def test_init(self, sample_har, config):
        from modules.websocket_scanner import WebSocketScanner

        scanner = WebSocketScanner(sample_har, config)

        assert scanner.har_data == sample_har
        assert scanner.timeout == 10
        assert scanner.max_messages == 50

    def test_init_with_zap(self, sample_har, config):
        from modules.websocket_scanner import WebSocketScanner

        mock_zap = Mock()
        scanner = WebSocketScanner(sample_har, config, zap_client=mock_zap)

        assert scanner.zap_client == mock_zap

    def test_detect_endpoints_upgrade_header(self, sample_har, config):
        from modules.websocket_scanner import WebSocketScanner

        scanner = WebSocketScanner(sample_har, config)
        endpoints = scanner.detect_endpoints()

        urls = [e.url for e in endpoints]
        assert any('socket' in url for url in urls)

    def test_detect_endpoints_ws_url(self, sample_har, config):
        from modules.websocket_scanner import WebSocketScanner

        scanner = WebSocketScanner(sample_har, config)
        endpoints = scanner.detect_endpoints()

        urls = [e.url for e in endpoints]
        assert any(url.startswith('wss://') for url in urls)

    def test_detect_endpoints_socket_io(self, sample_har, config):
        from modules.websocket_scanner import WebSocketScanner

        scanner = WebSocketScanner(sample_har, config)
        endpoints = scanner.detect_endpoints()

        urls = [e.url for e in endpoints]
        assert any('socket.io' in url for url in urls)

    def test_detect_endpoints_101_response(self, config):
        from modules.websocket_scanner import WebSocketScanner

        har = {
            'entries': [{
                'request': {'url': 'https://api.com/connect', 'headers': []},
                'response': {'status': 101}
            }]
        }

        scanner = WebSocketScanner(har, config)
        endpoints = scanner.detect_endpoints()

        assert len(endpoints) == 1

    def test_http_to_ws_https(self, sample_har, config):
        from modules.websocket_scanner import WebSocketScanner

        scanner = WebSocketScanner(sample_har, config)

        assert scanner._http_to_ws('https://api.com/ws') == 'wss://api.com/ws'
        assert scanner._http_to_ws('http://api.com/ws') == 'ws://api.com/ws'
        assert scanner._http_to_ws('wss://api.com/ws') == 'wss://api.com/ws'

    @pytest.mark.asyncio
    async def test_test_authentication_success(self, sample_har, config):
        from modules.websocket_scanner import WebSocketScanner, WebSocketEndpoint

        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_ws.recv = AsyncMock(side_effect=asyncio.TimeoutError)
            mock_connect.return_value.__aenter__.return_value = mock_ws

            scanner = WebSocketScanner(sample_har, config)
            endpoint = WebSocketEndpoint(url='wss://api.com/ws')
            result = await scanner.test_authentication(endpoint)

            assert result['connection_successful'] is True
            assert result['requires_auth'] is False

    @pytest.mark.asyncio
    async def test_test_authentication_requires_auth(self, sample_har, config):
        from modules.websocket_scanner import WebSocketScanner, WebSocketEndpoint

        with patch('websockets.connect') as mock_connect:
            mock_connect.side_effect = Exception('401 Unauthorized')

            scanner = WebSocketScanner(sample_har, config)
            endpoint = WebSocketEndpoint(url='wss://api.com/ws')
            result = await scanner.test_authentication(endpoint)

            assert result['requires_auth'] is True
            assert endpoint.requires_auth is True

    @pytest.mark.asyncio
    async def test_test_origin_validation_vulnerable(self, sample_har, config):
        from modules.websocket_scanner import WebSocketScanner, WebSocketEndpoint

        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_connect.return_value.__aenter__.return_value = mock_ws

            scanner = WebSocketScanner(sample_har, config)
            endpoint = WebSocketEndpoint(url='wss://api.com/ws')
            result = await scanner.test_origin_validation(endpoint)

            assert result['vulnerable'] is True
            assert len(scanner.vulnerabilities) > 0

    @pytest.mark.asyncio
    async def test_test_origin_validation_secure(self, sample_har, config):
        from modules.websocket_scanner import WebSocketScanner, WebSocketEndpoint

        with patch('websockets.connect') as mock_connect:
            mock_connect.side_effect = Exception('403 Forbidden')

            scanner = WebSocketScanner(sample_har, config)
            endpoint = WebSocketEndpoint(url='wss://api.com/ws')
            result = await scanner.test_origin_validation(endpoint)

            assert result['vulnerable'] is False

    @pytest.mark.asyncio
    async def test_fuzz_messages(self, sample_har, config):
        from modules.websocket_scanner import WebSocketScanner, WebSocketEndpoint

        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            mock_ws.recv = AsyncMock(return_value='{"status": "ok"}')
            mock_connect.return_value.__aenter__.return_value = mock_ws

            scanner = WebSocketScanner(sample_har, config)
            endpoint = WebSocketEndpoint(url='wss://api.com/ws')
            results = await scanner.fuzz_messages(endpoint, ['payload1', 'payload2'])

            assert len(results) == 2
            assert mock_ws.send.call_count == 2

    @pytest.mark.asyncio
    async def test_fuzz_messages_timeout(self, sample_har, config):
        from modules.websocket_scanner import WebSocketScanner, WebSocketEndpoint

        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            mock_ws.recv = AsyncMock(side_effect=asyncio.TimeoutError)
            mock_connect.return_value.__aenter__.return_value = mock_ws

            scanner = WebSocketScanner(sample_har, config)
            endpoint = WebSocketEndpoint(url='wss://api.com/ws')
            results = await scanner.fuzz_messages(endpoint, ['payload1'])

            assert len(results) == 1
            assert results[0].get('timeout') is True

    @pytest.mark.asyncio
    async def test_fuzz_messages_interesting_response(self, sample_har, config):
        from modules.websocket_scanner import WebSocketScanner, WebSocketEndpoint

        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            mock_ws.recv = AsyncMock(return_value='SQL syntax error near')
            mock_connect.return_value.__aenter__.return_value = mock_ws

            scanner = WebSocketScanner(sample_har, config)
            endpoint = WebSocketEndpoint(url='wss://api.com/ws')
            results = await scanner.fuzz_messages(endpoint, ["' OR 1=1--"])

            assert len(results) == 1
            assert results[0]['interesting'] is True

    @pytest.mark.asyncio
    async def test_test_injection(self, sample_har, config):
        from modules.websocket_scanner import WebSocketScanner, WebSocketEndpoint

        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_ws.send = AsyncMock()
            mock_ws.recv = AsyncMock(return_value='ok')
            mock_connect.return_value.__aenter__.return_value = mock_ws

            scanner = WebSocketScanner(sample_har, config)
            endpoint = WebSocketEndpoint(url='wss://api.com/ws')
            results = await scanner.test_injection(endpoint)

            assert len(results) > 0

    @pytest.mark.asyncio
    async def test_scan_all(self, sample_har, config):
        from modules.websocket_scanner import WebSocketScanner

        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_ws.recv = AsyncMock(side_effect=asyncio.TimeoutError)
            mock_ws.send = AsyncMock()
            mock_connect.return_value.__aenter__.return_value = mock_ws

            scanner = WebSocketScanner(sample_har, config)
            scanner.detect_endpoints()

            if scanner.endpoints:
                results = await scanner.scan_all()

                assert 'endpoints' in results
                assert 'vulnerabilities' in results
                assert 'summary' in results

    def test_scan_all_sync(self, sample_har, config):
        from modules.websocket_scanner import WebSocketScanner

        with patch('websockets.connect') as mock_connect:
            mock_ws = AsyncMock()
            mock_ws.recv = AsyncMock(side_effect=asyncio.TimeoutError)
            mock_ws.send = AsyncMock()
            mock_connect.return_value.__aenter__.return_value = mock_ws

            scanner = WebSocketScanner(sample_har, config)
            scanner.endpoints = []  # Empty to skip actual tests

            # This should not raise
            results = scanner.scan_all_sync()

            assert 'summary' in results
