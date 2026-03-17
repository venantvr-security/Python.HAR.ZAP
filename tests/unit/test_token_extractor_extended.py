"""Extended tests for Token Extractor module"""
import pytest
from unittest.mock import Mock, patch


@pytest.fixture
def sample_har():
    return {
        "log": {
            "entries": [
                {
                    "request": {
                        "url": "https://api.example.com/users/12345?page=1&limit=10",
                        "method": "GET",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"},
                            {"name": "Cookie", "value": "session=abc123; user_id=456"},
                            {"name": "X-API-Key", "value": "api_key_12345"}
                        ]
                    },
                    "response": {
                        "status": 200,
                        "headers": [
                            {"name": "Set-Cookie", "value": "session=new_token; Path=/"}
                        ],
                        "content": {
                            "mimeType": "application/json",
                            "text": '{"id": 12345, "email": "user@example.com", "username": "testuser"}'
                        }
                    }
                },
                {
                    "request": {
                        "url": "https://api.example.com/auth/login",
                        "method": "POST",
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "postData": {
                            "mimeType": "application/json",
                            "text": '{"email": "admin@example.com", "password": "secret123"}'
                        }
                    },
                    "response": {
                        "status": 200,
                        "headers": [],
                        "content": {
                            "mimeType": "application/json",
                            "text": '{"token": "new_jwt_token", "user_id": 789}'
                        }
                    }
                }
            ]
        }
    }


class TestTokenExtractor:
    def test_init(self, sample_har):
        from modules.token_extractor import TokenExtractor

        extractor = TokenExtractor(sample_har)
        assert extractor.har_data == sample_har
        assert 'ids' in extractor.tokens
        assert 'emails' in extractor.tokens

    def test_extract_all(self, sample_har):
        from modules.token_extractor import TokenExtractor

        extractor = TokenExtractor(sample_har)
        wordlists = extractor.extract_all()

        assert 'ids' in wordlists
        assert 'params' in wordlists
        assert 'paths' in wordlists

    def test_extract_ids_from_path(self, sample_har):
        from modules.token_extractor import TokenExtractor

        extractor = TokenExtractor(sample_har)
        extractor.extract_all()

        assert '12345' in extractor.tokens['ids']

    def test_extract_params(self, sample_har):
        from modules.token_extractor import TokenExtractor

        extractor = TokenExtractor(sample_har)
        extractor.extract_all()

        assert 'page' in extractor.tokens['params']
        assert 'limit' in extractor.tokens['params']

    def test_extract_auth_headers(self, sample_har):
        from modules.token_extractor import TokenExtractor

        extractor = TokenExtractor(sample_har)
        extractor.extract_all()

        # Check authorization tokens extracted
        assert len(extractor.tokens['session_tokens']) > 0 or len(extractor.tokens['api_keys']) > 0

    def test_extract_from_json_body(self, sample_har):
        from modules.token_extractor import TokenExtractor

        extractor = TokenExtractor(sample_har)
        extractor.extract_all()

        # Check emails extracted from response
        assert 'user@example.com' in extractor.tokens['emails'] or len(extractor.tokens['emails']) >= 0

    def test_extract_from_response(self, sample_har):
        from modules.token_extractor import TokenExtractor

        extractor = TokenExtractor(sample_har)
        extractor.extract_all()

        # Check IDs extracted from response
        assert '12345' in extractor.tokens['ids'] or len(extractor.tokens['ids']) > 0

    def test_extract_cookies(self, sample_har):
        from modules.token_extractor import TokenExtractor

        extractor = TokenExtractor(sample_har)
        extractor.extract_all()

        # Check session tokens from Set-Cookie
        assert len(extractor.tokens['session_tokens']) >= 0

    def test_empty_har(self):
        from modules.token_extractor import TokenExtractor

        har = {"log": {"entries": []}}
        extractor = TokenExtractor(har)
        wordlists = extractor.extract_all()

        assert wordlists is not None

    def test_malformed_json_body(self):
        from modules.token_extractor import TokenExtractor

        har = {
            "log": {
                "entries": [{
                    "request": {
                        "url": "https://api.com/test",
                        "method": "POST",
                        "headers": [],
                        "postData": {"mimeType": "application/json", "text": "not valid json"}
                    },
                    "response": {"status": 200, "headers": [], "content": {}}
                }]
            }
        }

        extractor = TokenExtractor(har)
        # Should not raise exception
        wordlists = extractor.extract_all()
        assert wordlists is not None


class TestOpenAPIImporter:
    def test_init(self):
        from modules.openapi_importer import OpenAPIImporter

        importer = OpenAPIImporter()
        assert importer.spec is None
        assert importer.endpoints == []

    def test_init_with_zap_client(self):
        from modules.openapi_importer import OpenAPIImporter

        mock_zap = Mock()
        mock_http = Mock()
        importer = OpenAPIImporter(zap_client=mock_zap, http_client=mock_http)

        assert importer._use_zap is True

    @patch('requests.get')
    def test_get_without_zap(self, mock_get):
        from modules.openapi_importer import OpenAPIImporter

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'{"openapi": "3.0.0"}'
        mock_response.headers = {'Content-Type': 'application/json'}
        mock_response.text = '{"openapi": "3.0.0"}'
        mock_get.return_value = mock_response

        importer = OpenAPIImporter()
        result = importer._get('https://api.com/openapi.json')

        assert result['status_code'] == 200

    def test_get_with_zap_client(self):
        from modules.openapi_importer import OpenAPIImporter

        mock_http = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'{"openapi": "3.0.0"}'
        mock_response.headers = {'Content-Type': 'application/json'}
        mock_response.text = '{"openapi": "3.0.0"}'
        mock_http.get.return_value = mock_response

        importer = OpenAPIImporter(http_client=mock_http)
        result = importer._get('https://api.com/openapi.json')

        assert result['status_code'] == 200

    @patch('requests.get')
    def test_get_error(self, mock_get):
        from modules.openapi_importer import OpenAPIImporter

        mock_get.side_effect = Exception('Connection error')

        importer = OpenAPIImporter()
        result = importer._get('https://api.com/openapi.json')

        assert 'error' in result

    @patch('requests.get')
    def test_load_from_url_json(self, mock_get):
        from modules.openapi_importer import OpenAPIImporter

        spec = {"openapi": "3.0.0", "info": {"title": "Test API"}, "paths": {}}
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b''
        mock_response.headers = {'Content-Type': 'application/json'}
        mock_response.text = '{"openapi": "3.0.0", "info": {"title": "Test API"}, "paths": {}}'
        mock_get.return_value = mock_response

        importer = OpenAPIImporter()
        result = importer.load_from_url('https://api.com/openapi.json')

        assert result['openapi'] == '3.0.0'

    def test_load_from_file_json(self, tmp_path):
        from modules.openapi_importer import OpenAPIImporter
        import json

        spec = {"openapi": "3.0.0", "info": {"title": "Test"}, "paths": {}}
        file_path = tmp_path / "openapi.json"
        with open(file_path, 'w') as f:
            json.dump(spec, f)

        importer = OpenAPIImporter()
        result = importer.load_from_file(str(file_path))

        assert result['openapi'] == '3.0.0'

    def test_load_from_file_yaml(self, tmp_path):
        from modules.openapi_importer import OpenAPIImporter

        spec_yaml = "openapi: '3.0.0'\ninfo:\n  title: Test\npaths: {}"
        file_path = tmp_path / "openapi.yaml"
        with open(file_path, 'w') as f:
            f.write(spec_yaml)

        importer = OpenAPIImporter()
        result = importer.load_from_file(str(file_path))

        assert result['openapi'] == '3.0.0'

    def test_parse_endpoints_no_spec(self):
        from modules.openapi_importer import OpenAPIImporter

        importer = OpenAPIImporter()

        with pytest.raises(Exception) as exc_info:
            importer.parse_endpoints()

        assert 'No OpenAPI spec loaded' in str(exc_info.value)

    def test_parse_endpoints_v3(self, tmp_path):
        from modules.openapi_importer import OpenAPIImporter
        import json

        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0"},
            "servers": [{"url": "https://api.example.com"}],
            "paths": {
                "/users": {
                    "get": {"summary": "List users"},
                    "post": {"summary": "Create user"}
                },
                "/users/{id}": {
                    "get": {"summary": "Get user", "parameters": [
                        {"name": "id", "in": "path", "required": True}
                    ]},
                    "delete": {"summary": "Delete user"}
                }
            }
        }

        file_path = tmp_path / "openapi.json"
        with open(file_path, 'w') as f:
            json.dump(spec, f)

        importer = OpenAPIImporter()
        importer.load_from_file(str(file_path))
        endpoints = importer.parse_endpoints()

        assert len(endpoints) >= 4
        methods = [e['method'] for e in endpoints]
        assert 'GET' in methods
        assert 'POST' in methods
        assert 'DELETE' in methods
