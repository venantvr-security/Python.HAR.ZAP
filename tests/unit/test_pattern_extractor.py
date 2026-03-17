"""Tests for pattern extractor module"""
import pytest

from modules.pattern_extractor import (
    PatternExtractor,
    PatternType,
    InjectionPoint,
    ExtractionResult,
    DEFAULT_PATTERNS,
)


@pytest.fixture
def sample_har_with_patterns():
    """HAR data with various pattern types"""
    return {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/users/12345?email=test@example.com",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123"},
                            {"name": "X-Request-ID", "value": "550e8400-e29b-41d4-a716-446655440000"}
                        ]
                    },
                    "response": {
                        "status": 200,
                        "content": {
                            "mimeType": "application/json",
                            "text": '{"user_id": 67890, "mongo_id": "507f1f77bcf86cd799439011"}'
                        }
                    }
                },
                {
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.com/files",
                        "headers": [
                            {"name": "Content-Type", "value": "application/json"}
                        ],
                        "postData": {
                            "mimeType": "application/json",
                            "text": '{"path": "../../../etc/passwd", "user_id": 999}'
                        }
                    },
                    "response": {
                        "status": 200,
                        "content": {"text": ""}
                    }
                },
                {
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.com/contact",
                        "headers": [],
                        "postData": {
                            "mimeType": "application/x-www-form-urlencoded",
                            "params": [
                                {"name": "email", "value": "admin@target.com"},
                                {"name": "id", "value": "42"}
                            ]
                        }
                    },
                    "response": {"status": 200}
                }
            ]
        }
    }


@pytest.fixture
def config_with_patterns():
    """Config with extraction patterns"""
    return {
        "extraction_patterns": {
            "numeric_id": r'\b\d{1,10}\b',
            "uuid": r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "jwt": r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
            "file_path": r'(?:\.\.\/)+|(?:\/[a-zA-Z0-9_-]+)+',
            "mongo_id": r'[0-9a-f]{24}',
        }
    }


class TestPatternExtractor:
    """Test pattern extraction from HAR"""

    def test_init_with_config(self, sample_har_with_patterns, config_with_patterns):
        extractor = PatternExtractor(sample_har_with_patterns, config_with_patterns)
        assert len(extractor.patterns) == 6

    def test_init_without_config(self, sample_har_with_patterns):
        extractor = PatternExtractor(sample_har_with_patterns)
        assert len(extractor.patterns) == len(DEFAULT_PATTERNS)

    def test_extract_numeric_ids(self, sample_har_with_patterns, config_with_patterns):
        extractor = PatternExtractor(sample_har_with_patterns, config_with_patterns)
        results = extractor.extract_from_har()

        numeric_result = results.get('numeric_id')
        assert numeric_result is not None
        assert '12345' in numeric_result.values
        assert '67890' in numeric_result.values
        assert '42' in numeric_result.values

    def test_extract_uuids(self, sample_har_with_patterns, config_with_patterns):
        extractor = PatternExtractor(sample_har_with_patterns, config_with_patterns)
        results = extractor.extract_from_har()

        uuid_result = results.get('uuid')
        assert uuid_result is not None
        assert '550e8400-e29b-41d4-a716-446655440000' in uuid_result.values

    def test_extract_emails(self, sample_har_with_patterns, config_with_patterns):
        extractor = PatternExtractor(sample_har_with_patterns, config_with_patterns)
        results = extractor.extract_from_har()

        email_result = results.get('email')
        assert email_result is not None
        assert 'test@example.com' in email_result.values
        assert 'admin@target.com' in email_result.values

    def test_extract_mongo_ids(self, sample_har_with_patterns, config_with_patterns):
        extractor = PatternExtractor(sample_har_with_patterns, config_with_patterns)
        results = extractor.extract_from_har()

        mongo_result = results.get('mongo_id')
        assert mongo_result is not None
        assert '507f1f77bcf86cd799439011' in mongo_result.values

    def test_identify_injection_points(self, sample_har_with_patterns, config_with_patterns):
        extractor = PatternExtractor(sample_har_with_patterns, config_with_patterns)
        extractor.extract_from_har()
        points = extractor.identify_injection_points()

        assert len(points) > 0
        assert all(isinstance(p, InjectionPoint) for p in points)

        # Check for query param injection point
        query_points = [p for p in points if p.location == 'query']
        assert len(query_points) > 0

    def test_injection_point_structure(self, sample_har_with_patterns, config_with_patterns):
        extractor = PatternExtractor(sample_har_with_patterns, config_with_patterns)
        extractor.extract_from_har()
        points = extractor.identify_injection_points()

        for point in points:
            assert hasattr(point, 'url')
            assert hasattr(point, 'method')
            assert hasattr(point, 'location')
            assert hasattr(point, 'param_name')
            assert hasattr(point, 'original_value')
            assert hasattr(point, 'pattern_type')

    def test_get_summary(self, sample_har_with_patterns, config_with_patterns):
        extractor = PatternExtractor(sample_har_with_patterns, config_with_patterns)
        extractor.extract_from_har()
        summary = extractor.get_summary()

        assert 'total_values' in summary
        assert 'total_injection_points' in summary
        assert 'patterns' in summary
        assert summary['total_values'] > 0

    def test_get_injection_points_by_pattern(self, sample_har_with_patterns, config_with_patterns):
        extractor = PatternExtractor(sample_har_with_patterns, config_with_patterns)
        extractor.extract_from_har()

        email_points = extractor.get_injection_points_by_pattern('email')
        assert all(p.pattern_type == PatternType.EMAIL for p in email_points)

    def test_get_values_by_pattern(self, sample_har_with_patterns, config_with_patterns):
        extractor = PatternExtractor(sample_har_with_patterns, config_with_patterns)
        extractor.extract_from_har()

        email_values = extractor.get_values_by_pattern('email')
        assert 'admin@target.com' in email_values
        assert 'test@example.com' in email_values

    def test_empty_har(self, config_with_patterns):
        """Test with empty HAR data"""
        empty_har = {"log": {"entries": []}}
        extractor = PatternExtractor(empty_har, config_with_patterns)
        results = extractor.extract_from_har()

        for result in results.values():
            assert len(result.values) == 0
            assert len(result.injection_points) == 0

    def test_missing_log_key(self, config_with_patterns):
        """Test with malformed HAR"""
        bad_har = {}
        extractor = PatternExtractor(bad_har, config_with_patterns)
        results = extractor.extract_from_har()
        assert isinstance(results, dict)

    def test_invalid_regex_in_config(self, sample_har_with_patterns):
        """Test handling of invalid regex patterns"""
        bad_config = {
            "extraction_patterns": {
                "bad_pattern": r'[invalid regex('
            }
        }
        extractor = PatternExtractor(sample_har_with_patterns, bad_config)
        # Should not crash, should use default
        assert 'bad_pattern' in extractor.patterns

    def test_form_data_extraction(self, config_with_patterns):
        """Test extraction from form POST data"""
        har = {
            "log": {
                "entries": [{
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.com/submit",
                        "headers": [],
                        "postData": {
                            "mimeType": "application/x-www-form-urlencoded",
                            "params": [
                                {"name": "user_id", "value": "12345"},
                                {"name": "email", "value": "user@test.com"}
                            ]
                        }
                    },
                    "response": {"status": 200}
                }]
            }
        }

        extractor = PatternExtractor(har, config_with_patterns)
        results = extractor.extract_from_har()

        assert '12345' in results['numeric_id'].values
        assert 'user@test.com' in results['email'].values

    def test_path_segment_extraction(self, config_with_patterns):
        """Test extraction from URL path segments"""
        har = {
            "log": {
                "entries": [{
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/users/99999/profile",
                        "headers": []
                    },
                    "response": {"status": 200}
                }]
            }
        }

        extractor = PatternExtractor(har, config_with_patterns)
        results = extractor.extract_from_har()

        assert '99999' in results['numeric_id'].values

    def test_header_extraction(self, config_with_patterns):
        """Test extraction from headers"""
        har = {
            "log": {
                "entries": [{
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/test",
                        "headers": [
                            {"name": "X-User-ID", "value": "77777"},
                            {"name": "X-Correlation-ID", "value": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}
                        ]
                    },
                    "response": {"status": 200}
                }]
            }
        }

        extractor = PatternExtractor(har, config_with_patterns)
        results = extractor.extract_from_har()

        assert '77777' in results['numeric_id'].values
        assert 'a1b2c3d4-e5f6-7890-abcd-ef1234567890' in results['uuid'].values

    def test_response_values_extraction(self, config_with_patterns):
        """Test values extracted from response body"""
        har = {
            "log": {
                "entries": [{
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/test",
                        "headers": []
                    },
                    "response": {
                        "status": 200,
                        "content": {
                            "mimeType": "application/json",
                            "text": '{"ids": [11111, 22222], "email": "response@test.com"}'
                        }
                    }
                }]
            }
        }

        extractor = PatternExtractor(har, config_with_patterns)
        results = extractor.extract_from_har()

        # Response values are extracted but no injection points
        assert 'response@test.com' in results['email'].values

    def test_nested_json_extraction(self, config_with_patterns):
        """Test extraction from nested JSON"""
        har = {
            "log": {
                "entries": [{
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.com/test",
                        "headers": [],
                        "postData": {
                            "mimeType": "application/json",
                            "text": '{"user": {"id": 88888, "profile": {"email": "nested@test.com"}}}'
                        }
                    },
                    "response": {"status": 200}
                }]
            }
        }

        extractor = PatternExtractor(har, config_with_patterns)
        results = extractor.extract_from_har()

        assert '88888' in results['numeric_id'].values
        assert 'nested@test.com' in results['email'].values

    def test_array_json_extraction(self, config_with_patterns):
        """Test extraction from JSON arrays"""
        har = {
            "log": {
                "entries": [{
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.com/test",
                        "headers": [],
                        "postData": {
                            "mimeType": "application/json",
                            "text": '{"ids": ["44444", "55555"]}'
                        }
                    },
                    "response": {"status": 200}
                }]
            }
        }

        extractor = PatternExtractor(har, config_with_patterns)
        results = extractor.extract_from_har()

        assert '44444' in results['numeric_id'].values
        assert '55555' in results['numeric_id'].values


class TestPatternType:
    """Test PatternType enum"""

    def test_pattern_types_exist(self):
        assert PatternType.NUMERIC_ID.value == "numeric_id"
        assert PatternType.UUID.value == "uuid"
        assert PatternType.EMAIL.value == "email"
        assert PatternType.JWT.value == "jwt"
        assert PatternType.FILE_PATH.value == "file_path"
        assert PatternType.MONGO_ID.value == "mongo_id"


class TestExtractionResult:
    """Test ExtractionResult dataclass"""

    def test_default_values(self):
        result = ExtractionResult(pattern_type=PatternType.NUMERIC_ID)
        assert result.values == set()
        assert result.injection_points == []

    def test_with_values(self):
        result = ExtractionResult(
            pattern_type=PatternType.EMAIL,
            values={'test@example.com'},
            injection_points=[]
        )
        assert 'test@example.com' in result.values


class TestInjectionPoint:
    """Test InjectionPoint dataclass"""

    def test_injection_point_creation(self):
        point = InjectionPoint(
            url="https://example.com/api",
            method="GET",
            location="query",
            param_name="id",
            original_value="123",
            pattern_type=PatternType.NUMERIC_ID
        )

        assert point.url == "https://example.com/api"
        assert point.method == "GET"
        assert point.location == "query"
        assert point.param_name == "id"
        assert point.original_value == "123"
        assert point.pattern_type == PatternType.NUMERIC_ID
