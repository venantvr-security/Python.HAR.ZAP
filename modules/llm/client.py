"""
LLM Client - Anthropic Claude API wrapper with rate limiting and retry.
"""
import os
import time
from dataclasses import dataclass
from typing import Dict, Optional

from modules.utils import get_logger, RateLimiter, create_http_session

logger = get_logger("llm.client")


@dataclass
class LLMConfig:
    """LLM configuration."""
    provider: str = "anthropic"
    model: str = "claude-sonnet-4-20250514"
    api_key: str = ""
    max_tokens: int = 4000
    temperature: float = 0.1
    timeout: int = 60
    max_retries: int = 3
    requests_per_minute: float = 10.0


@dataclass
class LLMResponse:
    """Structured LLM response."""
    content: str
    model: str
    usage: Dict[str, int]
    latency_ms: float
    cached: bool = False


class LLMClient:
    """
    LLM client wrapper for Anthropic Claude API.
    Thread-safe, rate-limited, with retry logic.
    """

    ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"

    def __init__(self, config: LLMConfig):
        self.config = config
        self.session = create_http_session(max_retries=config.max_retries)
        self.rate_limiter = RateLimiter(
            requests_per_second=config.requests_per_minute / 60.0,
            burst=3
        )
        self._validate_config()

    def _validate_config(self):
        """Validate API key presence."""
        if not self.config.api_key:
            raise ValueError(
                "LLM API key required. Set HARZAP_LLM_API_KEY environment variable."
            )

    def complete(self, prompt: str, system: Optional[str] = None) -> LLMResponse:
        """
        Send completion request to LLM.

        Args:
            prompt: User prompt
            system: Optional system prompt

        Returns:
            LLMResponse with content and metadata
        """
        self.rate_limiter.acquire()
        start_time = time.monotonic()

        headers = {
            "x-api-key": self.config.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json"
        }

        payload = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "messages": [{"role": "user", "content": prompt}]
        }

        if system:
            payload["system"] = system

        try:
            response = self.session.post(
                self.ANTHROPIC_API_URL,
                headers=headers,
                json=payload,
                timeout=self.config.timeout
            )
            response.raise_for_status()

            data = response.json()
            latency = (time.monotonic() - start_time) * 1000

            logger.info(
                "llm_complete",
                model=self.config.model,
                input_tokens=data.get("usage", {}).get("input_tokens", 0),
                output_tokens=data.get("usage", {}).get("output_tokens", 0),
                latency_ms=round(latency, 2)
            )

            return LLMResponse(
                content=data["content"][0]["text"],
                model=data["model"],
                usage=data.get("usage", {}),
                latency_ms=latency
            )

        except Exception as e:
            logger.error("llm_error", error=str(e))
            raise

    @staticmethod
    def from_config(config: Dict) -> 'LLMClient':
        """Factory from config dict."""
        llm_config = config.get('llm', {})
        return LLMClient(LLMConfig(
            provider=llm_config.get('provider', 'anthropic'),
            model=llm_config.get('model', 'claude-sonnet-4-20250514'),
            api_key=os.environ.get('HARZAP_LLM_API_KEY', llm_config.get('api_key', '')),
            max_tokens=llm_config.get('max_tokens', 4000),
            temperature=llm_config.get('temperature', 0.1),
            timeout=llm_config.get('timeout', 60),
            max_retries=llm_config.get('max_retries', 3),
            requests_per_minute=llm_config.get('requests_per_minute', 10.0)
        ))
