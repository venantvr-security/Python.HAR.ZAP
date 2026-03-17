"""Tests for ZAP HTTP client module"""
import pytest
from unittest.mock import Mock, patch, MagicMock

pytest.importorskip("zapv2")
from modules.zap_http_client import ZAPHttpClient, ZAPResponse


@pytest.fixture
def mock_zap():
    zap = Mock()
    zap.core = Mock()
    zap.core.send_request = Mock(return_value='HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>OK</html>')
    zap.alert = Mock()
    zap.alert.alerts = Mock(return_value=[])
    return zap


class TestZAPHttpClient:
    """Test ZAP HTTP client"""

    def test_init_with_existing_zap(self, mock_zap):
        client = ZAPHttpClient(zap=mock_zap, zap_url='http://localhost:8080')
        assert client.zap == mock_zap
        assert client.timeout == 30

    @patch('zapv2.ZAPv2')
    def test_init_without_zap(self, mock_zap_class):
        client = ZAPHttpClient(zap_url='http://localhost:9090', api_key='secret')
        assert client.zap_url == 'http://localhost:9090'
        assert client.api_key == 'secret'

    def test_build_zap_request_get(self, mock_zap):
        client = ZAPHttpClient(zap=mock_zap)
        request = client._build_zap_request(
            'GET',
            'https://example.com/api/users?page=1',
            headers={'Authorization': 'Bearer token'}
        )

        assert 'GET /api/users?page=1 HTTP/1.1' in request
        assert 'Host: example.com' in request
        assert 'Authorization: Bearer token' in request

    def test_build_zap_request_post_json(self, mock_zap):
        client = ZAPHttpClient(zap=mock_zap)
        request = client._build_zap_request(
            'POST',
            'https://example.com/api/users',
            data={'name': 'test'}
        )

        assert 'POST /api/users HTTP/1.1' in request
        assert 'Content-Type: application/json' in request
        assert 'Content-Length:' in request

    def test_build_zap_request_post_string(self, mock_zap):
        client = ZAPHttpClient(zap=mock_zap)
        request = client._build_zap_request(
            'POST',
            'https://example.com/api',
            data='raw body data'
        )

        assert 'Content-Length: 13' in request

    def test_build_zap_request_post_bytes(self, mock_zap):
        client = ZAPHttpClient(zap=mock_zap)
        request = client._build_zap_request(
            'POST',
            'https://example.com/api',
            data=b'binary data'
        )

        assert 'Content-Length:' in request

    def test_build_zap_request_default_path(self, mock_zap):
        client = ZAPHttpClient(zap=mock_zap)
        request = client._build_zap_request(
            'GET',
            'https://example.com'
        )

        assert 'GET / HTTP/1.1' in request


class TestZAPResponse:
    """Test ZAPResponse dataclass"""

    def test_create_response(self):
        response = ZAPResponse(
            status_code=200,
            headers={'Content-Type': 'text/html'},
            content=b'<html>test</html>',
            text='<html>test</html>',
            elapsed=0.5,
            url='https://example.com',
            method='GET'
        )

        assert response.status_code == 200
        assert response.elapsed == 0.5
        assert response.request_id is None

    def test_response_with_request_id(self):
        response = ZAPResponse(
            status_code=200,
            headers={},
            content=b'',
            text='',
            elapsed=0.1,
            url='https://example.com',
            method='GET',
            request_id=12345
        )

        assert response.request_id == 12345
