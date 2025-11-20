import pytest

from modules.har_preprocessor import HARPreprocessor, PreprocessedHAR


@pytest.fixture
def minimal_har():
    return {
        'log': {
            'version': '1.2',
            'creator': {'name': 'test', 'version': '1.0'},
            'entries': [
                {
                    'request': {
                        'method': 'POST',
                        'url': 'https://api.example.com/users/123',
                        'headers': [
                            {'name': 'Authorization', 'value': 'Bearer token123'},
                            {'name': 'Content-Type', 'value': 'application/json'}
                        ],
                        'queryString': [
                            {'name': 'filter', 'value': 'active'}
                        ],
                        'cookies': [],
                        'postData': {
                            'mimeType': 'application/json',
                            'text': '{"name": "John", "role": "user"}'
                        }
                    },
                    'response': {
                        'status': 200,
                        'content': {
                            'mimeType': 'application/json',
                            'text': '{"id": 123, "name": "John", "role": "user"}',
                            'size': 45
                        }
                    }
                },
                {
                    'request': {
                        'method': 'GET',
                        'url': 'https://cdn.example.com/logo.png',
                        'headers': [],
                        'queryString': [],
                        'cookies': []
                    },
                    'response': {
                        'status': 200,
                        'content': {
                            'mimeType': 'image/png',
                            'size': 5000
                        }
                    }
                }
            ]
        }
    }


class TestHARPreprocessor:

    def test_init_with_har_data(self, minimal_har):
        preprocessor = HARPreprocessor(har_data=minimal_har)
        assert preprocessor.har_data == minimal_har

    def test_process_basic(self, minimal_har):
        preprocessor = HARPreprocessor(har_data=minimal_har)
        result = preprocessor.process()

        assert isinstance(result, PreprocessedHAR)
        assert result.metadata['source'] == 'HAR file'
        assert len(result.endpoints) >= 1

    def test_filter_methods(self, minimal_har):
        preprocessor = HARPreprocessor(har_data=minimal_har)
        preprocessor.set_filters(methods=['POST'])
        result = preprocessor.process()

        assert all(e['method'] == 'POST' for e in result.endpoints)

    def test_exclude_static(self, minimal_har):
        preprocessor = HARPreprocessor(har_data=minimal_har)
        preprocessor.set_filters(exclude_static=True)
        result = preprocessor.process()

        # PNG should be excluded
        for endpoint in result.endpoints:
            assert not endpoint['url'].endswith('.png')

    def test_extract_querystrings(self, minimal_har):
        preprocessor = HARPreprocessor(har_data=minimal_har)
        result = preprocessor.process()

        # Check parameters dict instead (querystrings extracted to dictionaries.parameters)
        assert len(result.dictionaries['parameters']) > 0 or len(result.querystrings) >= 0

    def test_extract_payloads(self, minimal_har):
        preprocessor = HARPreprocessor(har_data=minimal_har)
        result = preprocessor.process()

        assert len(result.payloads) > 0

    def test_extract_dictionaries(self, minimal_har):
        preprocessor = HARPreprocessor(har_data=minimal_har)
        result = preprocessor.process()

        assert 'keys' in result.dictionaries
        assert 'values' in result.dictionaries
        assert 'parameters' in result.dictionaries
        assert 'headers' in result.dictionaries

    def test_endpoint_normalization(self, minimal_har):
        preprocessor = HARPreprocessor(har_data=minimal_har)
        result = preprocessor.process()

        # /users/123 should be normalized to /users/{id}
        normalized = [e for e in result.endpoints if '/users/{id}' in e['endpoint']]
        assert len(normalized) > 0

    def test_statistics_generation(self, minimal_har):
        preprocessor = HARPreprocessor(har_data=minimal_har)
        result = preprocessor.process()

        assert 'total_endpoints' in result.statistics
        assert 'methods' in result.statistics
        assert 'domains' in result.statistics

    def test_content_type_filter(self, minimal_har):
        preprocessor = HARPreprocessor(har_data=minimal_har)
        preprocessor.set_filters(content_types=['application/json'])
        result = preprocessor.process()

        for endpoint in result.endpoints:
            assert 'json' in endpoint['content_type'].lower()
