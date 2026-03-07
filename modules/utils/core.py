"""
Core utilities: retry, rate limiting, logging, HTTP session pooling.
Infrastructure for professional-grade DAST automation.
"""
import os
import sys
import time
import json
import logging
import hashlib
from functools import wraps
from threading import Lock
from typing import Callable, Optional, Dict, Any, Tuple, Type
from datetime import datetime

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# =============================================================================
# EXCEPTIONS
# =============================================================================

class ZAPError(Exception):
    """Base exception for ZAP operations."""
    pass


class ZAPConnectionError(ZAPError):
    """ZAP connection failed."""
    pass


class ZAPTimeoutError(ZAPError):
    """ZAP operation timed out."""
    pass


class ScanError(ZAPError):
    """Scan execution error."""
    pass


class ConfigError(ZAPError):
    """Configuration error."""
    pass


# =============================================================================
# RETRY DECORATOR
# =============================================================================

def retry_zap_call(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    exponential: bool = True,
    retryable_exceptions: Tuple[Type[Exception], ...] = (
        ZAPConnectionError, ZAPTimeoutError, requests.exceptions.ConnectionError,
        requests.exceptions.Timeout, ConnectionRefusedError
    )
) -> Callable:
    """Decorator for retrying ZAP API calls with exponential backoff."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            logger = get_logger(__name__)

            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except retryable_exceptions as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        delay = min(
                            base_delay * (2 ** attempt if exponential else 1),
                            max_delay
                        )
                        logger.warning(
                            "retry_attempt",
                            func=func.__name__,
                            attempt=attempt + 1,
                            max_retries=max_retries,
                            delay=delay,
                            error=str(e)
                        )
                        time.sleep(delay)
                except Exception as e:
                    logger.error("non_retryable_error", func=func.__name__, error=str(e))
                    raise

            logger.error("max_retries_exceeded", func=func.__name__, error=str(last_exception))
            raise last_exception
        return wrapper
    return decorator


# =============================================================================
# RATE LIMITER (Token Bucket)
# =============================================================================

class RateLimiter:
    """Token bucket rate limiter. Thread-safe."""

    def __init__(self, requests_per_second: float = 10.0, burst: int = 20):
        self.rate = requests_per_second
        self.burst = burst
        self.tokens = float(burst)
        self.last_update = time.monotonic()
        self.lock = Lock()

    def acquire(self, timeout: Optional[float] = None) -> bool:
        """Acquire token. Blocks until available or timeout."""
        deadline = time.monotonic() + timeout if timeout else None

        while True:
            with self.lock:
                now = time.monotonic()
                elapsed = now - self.last_update
                self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
                self.last_update = now

                if self.tokens >= 1:
                    self.tokens -= 1
                    return True

                wait_time = (1 - self.tokens) / self.rate

            if deadline:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                wait_time = min(wait_time, remaining)

            time.sleep(wait_time)

    def try_acquire(self) -> bool:
        """Non-blocking acquire."""
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_update = now

            if self.tokens >= 1:
                self.tokens -= 1
                return True
            return False


# =============================================================================
# DUAL-MODE LOGGER (JSON + Console)
# =============================================================================

class DualFormatter(logging.Formatter):
    """JSON or colored console formatter based on environment."""

    COLORS = {
        'DEBUG': '\033[36m', 'INFO': '\033[32m', 'WARNING': '\033[33m',
        'ERROR': '\033[31m', 'CRITICAL': '\033[35m', 'RESET': '\033[0m'
    }

    def __init__(self, json_mode: bool = False):
        super().__init__()
        self.json_mode = json_mode

    def format(self, record: logging.LogRecord) -> str:
        if self.json_mode:
            return self._format_json(record)
        return self._format_console(record)

    def _format_json(self, record: logging.LogRecord) -> str:
        log_entry = {
            'ts': datetime.utcnow().isoformat() + 'Z',
            'lvl': record.levelname,
            'log': record.name,
            'msg': record.getMessage()
        }
        if hasattr(record, 'extra_fields'):
            log_entry.update(record.extra_fields)
        return json.dumps(log_entry, default=str)

    def _format_console(self, record: logging.LogRecord) -> str:
        c = self.COLORS.get(record.levelname, '')
        r = self.COLORS['RESET']
        prefix = f"{c}[{record.levelname:8}]{r} [{record.name}]"
        extras = ""
        if hasattr(record, 'extra_fields'):
            extras = " " + " ".join(f"{k}={v}" for k, v in record.extra_fields.items())
        return f"{prefix} {record.getMessage()}{extras}"


class StructuredLogger(logging.Logger):
    """Logger with structured field support."""

    def _log_with_fields(self, level: int, msg: str, **kwargs):
        record = self.makeRecord(self.name, level, "", 0, msg, (), None)
        record.extra_fields = kwargs
        self.handle(record)

    def debug(self, msg: str, **kwargs):
        self._log_with_fields(logging.DEBUG, msg, **kwargs)

    def info(self, msg: str, **kwargs):
        self._log_with_fields(logging.INFO, msg, **kwargs)

    def warning(self, msg: str, **kwargs):
        self._log_with_fields(logging.WARNING, msg, **kwargs)

    def error(self, msg: str, **kwargs):
        self._log_with_fields(logging.ERROR, msg, **kwargs)

    def critical(self, msg: str, **kwargs):
        self._log_with_fields(logging.CRITICAL, msg, **kwargs)


_loggers: Dict[str, StructuredLogger] = {}
_logger_lock = Lock()


def get_logger(name: str = "harzap") -> StructuredLogger:
    """Get structured logger. Auto-detects JSON vs console mode."""
    with _logger_lock:
        if name in _loggers:
            return _loggers[name]

        json_mode = (
            os.environ.get('CI', '').lower() == 'true' or
            os.environ.get('HARZAP_LOG_JSON', '').lower() == 'true' or
            not sys.stdout.isatty()
        )

        logging.setLoggerClass(StructuredLogger)
        logger = logging.getLogger(name)
        logger.__class__ = StructuredLogger

        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(DualFormatter(json_mode=json_mode))
            logger.addHandler(handler)
            level = os.environ.get('HARZAP_LOG_LEVEL', 'INFO').upper()
            logger.setLevel(getattr(logging, level, logging.INFO))

        _loggers[name] = logger
        return logger


# =============================================================================
# HTTP SESSION WITH CONNECTION POOLING
# =============================================================================

def create_http_session(
    pool_connections: int = 10,
    pool_maxsize: int = 20,
    max_retries: int = 3,
    backoff_factor: float = 0.3,
    timeout: Tuple[float, float] = (10.0, 30.0)
) -> requests.Session:
    """Create HTTP session with connection pooling and retry."""
    session = requests.Session()

    retry_strategy = Retry(
        total=max_retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "PATCH"]
    )

    adapter = HTTPAdapter(
        pool_connections=pool_connections,
        pool_maxsize=pool_maxsize,
        max_retries=retry_strategy
    )

    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.timeout = timeout

    return session


# =============================================================================
# UTILITIES
# =============================================================================

def hash_request(url: str, method: str, body: Optional[str] = None) -> str:
    """Generate unique hash for request (incremental scanning)."""
    content = f"{method}:{url}:{body or ''}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def safe_get(data: Dict, *keys, default: Any = None) -> Any:
    """Safely get nested dictionary value."""
    for key in keys:
        if isinstance(data, dict):
            data = data.get(key, default)
        else:
            return default
    return data
