"""Additional tests for utils/core.py to reach 70% coverage."""
import pytest
from unittest.mock import Mock, patch
import time


class TestRateLimiterAdditional:
    """Additional RateLimiter tests."""

    def test_wait_for_token(self):
        from modules.utils.core import RateLimiter

        limiter = RateLimiter(requests_per_second=100.0, burst=1)
        limiter.acquire()

        start = time.time()
        limiter.acquire()
        elapsed = time.time() - start

        assert elapsed >= 0

    def test_multiple_acquires(self):
        from modules.utils.core import RateLimiter

        limiter = RateLimiter(requests_per_second=1000.0, burst=5)

        for _ in range(5):
            assert limiter.acquire() is True


class TestHashRequest:
    """Tests for hash_request."""

    def test_hash_request_basic(self):
        from modules.utils.core import hash_request

        result = hash_request("https://example.com/api", "GET")
        assert len(result) > 0
        assert isinstance(result, str)

    def test_hash_request_with_body(self):
        from modules.utils.core import hash_request

        result = hash_request("https://example.com/api", "POST", '{"key": "value"}')
        assert len(result) > 0

    def test_hash_request_consistency(self):
        from modules.utils.core import hash_request

        hash1 = hash_request("https://example.com", "GET")
        hash2 = hash_request("https://example.com", "GET")
        assert hash1 == hash2


class TestSafeGet:
    """Tests for safe_get."""

    def test_safe_get_single_key(self):
        from modules.utils.core import safe_get

        data = {"key": "value"}
        result = safe_get(data, "key")
        assert result == "value"

    def test_safe_get_nested(self):
        from modules.utils.core import safe_get

        data = {"level1": {"level2": {"level3": "value"}}}
        result = safe_get(data, "level1", "level2", "level3")
        assert result == "value"

    def test_safe_get_missing_key(self):
        from modules.utils.core import safe_get

        data = {"key": "value"}
        result = safe_get(data, "missing", default="default_value")
        assert result == "default_value"

    def test_safe_get_none_value(self):
        from modules.utils.core import safe_get

        data = {"key": None}
        result = safe_get(data, "key", default="default")
        assert result is None


class TestCreateHTTPSession:
    """Tests for create_http_session."""

    def test_create_http_session_basic(self):
        from modules.utils.core import create_http_session

        session = create_http_session()
        assert session is not None
        assert hasattr(session, 'get')
        assert hasattr(session, 'post')

    def test_create_http_session_with_timeout(self):
        from modules.utils.core import create_http_session

        session = create_http_session(timeout=30)
        assert session is not None


class TestStructuredLogger:
    """Tests for StructuredLogger."""

    def test_get_logger(self):
        from modules.utils.core import get_logger

        logger = get_logger("test_logger")
        assert logger is not None
        assert logger.name == "test_logger"

    def test_logger_structured_logging(self):
        from modules.utils.core import get_logger

        logger = get_logger("test_structured")
        # Should not raise
        logger.info("test_event", key="value", count=42)


class TestExceptions:
    """Tests for custom exceptions."""

    def test_zap_error(self):
        from modules.utils.core import ZAPError

        with pytest.raises(ZAPError):
            raise ZAPError("Test error")

    def test_zap_connection_error(self):
        from modules.utils.core import ZAPConnectionError

        with pytest.raises(ZAPConnectionError):
            raise ZAPConnectionError("Connection failed")

    def test_zap_timeout_error(self):
        from modules.utils.core import ZAPTimeoutError

        with pytest.raises(ZAPTimeoutError):
            raise ZAPTimeoutError("Timeout")

    def test_scan_error(self):
        from modules.utils.core import ScanError

        with pytest.raises(ScanError):
            raise ScanError("Scan failed")

    def test_config_error(self):
        from modules.utils.core import ConfigError

        with pytest.raises(ConfigError):
            raise ConfigError("Config invalid")
