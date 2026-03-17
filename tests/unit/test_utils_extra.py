"""Extra tests for utils module"""
import pytest
from unittest.mock import Mock, patch


class TestUtilsCore:
    """Test core utility functions"""

    def test_create_http_session(self):
        from modules.utils.core import create_http_session

        session = create_http_session()
        assert session is not None
        assert hasattr(session, 'get')
        assert hasattr(session, 'post')

    def test_hash_request(self):
        from modules.utils.core import hash_request

        result = hash_request('https://example.com', 'GET')
        assert isinstance(result, str)
        assert len(result) > 0

    def test_safe_get(self):
        from modules.utils.core import safe_get

        data = {'a': {'b': {'c': 'value'}}}
        result = safe_get(data, 'a', 'b', 'c')
        assert result == 'value'

        result2 = safe_get(data, 'x', 'y', default='default')
        assert result2 == 'default'

    def test_get_logger(self):
        from modules.utils.core import get_logger

        logger = get_logger('test')
        assert logger is not None


class TestUtilsMasking:
    """Test masking utility functions"""

    def test_mask_sensitive_data_string(self):
        from modules.utils.masking import mask_sensitive_data

        result = mask_sensitive_data('password=secret123')
        assert 'secret123' not in result or '[MASKED]' in result

    def test_mask_sensitive_data_dict(self):
        from modules.utils.masking import mask_sensitive_data

        data = {'password': 'secret', 'name': 'test'}
        result = mask_sensitive_data(data)
        assert isinstance(result, dict)

    def test_mask_string(self):
        from modules.utils.masking import mask_string

        result = mask_string('password=secret123')
        assert '[MASKED]' in result or 'secret123' not in result

    def test_mask_dict(self):
        from modules.utils.masking import mask_dict

        data = {'Authorization': 'Bearer token', 'other': 'value'}
        result = mask_dict(data)
        assert isinstance(result, dict)

    def test_mask_headers(self):
        from modules.utils.masking import mask_headers

        headers = {
            'Authorization': 'Bearer secret123',
            'Content-Type': 'application/json'
        }

        masked = mask_headers(headers)
        assert 'secret123' not in str(masked)
        assert masked['Content-Type'] == 'application/json'

    def test_mask_url(self):
        from modules.utils.masking import mask_url

        url = 'https://example.com?token=secret&id=123'
        masked = mask_url(url)
        assert isinstance(masked, str)


class TestHttpSmuggling:
    """Test HTTP smuggling module"""

    @pytest.fixture
    def sample_har(self):
        return {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "POST",
                            "url": "https://example.com/api",
                            "headers": [
                                {"name": "Content-Type", "value": "application/x-www-form-urlencoded"}
                            ]
                        },
                        "response": {"status": 200}
                    }
                ]
            }
        }

    def test_init(self, sample_har):
        from modules.http_smuggling import HTTPSmugglingTester

        tester = HTTPSmugglingTester(sample_har, {})
        assert tester.har_data == sample_har

    def test_smuggling_result_dataclass(self):
        from modules.http_smuggling import SmugglingResult

        result = SmugglingResult(
            url='https://example.com',
            variant='CL.TE',
            vulnerable=True,
            confidence=0.9,
            evidence={'headers': {}}
        )
        assert result.vulnerable is True
        assert result.variant == 'CL.TE'


class TestOpenAPIImporter:
    """Test OpenAPI importer module"""

    def test_init(self):
        from modules.openapi_importer import OpenAPIImporter

        importer = OpenAPIImporter()
        assert importer is not None

    def test_init_with_zap(self):
        from modules.openapi_importer import OpenAPIImporter

        mock_zap = Mock()
        importer = OpenAPIImporter(zap_client=mock_zap)
        assert importer.zap == mock_zap
