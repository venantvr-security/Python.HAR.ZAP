"""
LLM Client - Multi-provider wrapper with rate limiting and retry.
Supports: Anthropic Claude, Google Gemini (with batch mode via GCS).
"""
import os
import time
import uuid
from dataclasses import dataclass
from typing import Dict, Optional

from modules.utils import get_logger, RateLimiter, create_http_session

logger = get_logger("llm.client")


@dataclass
class LLMConfig:
    """LLM configuration."""
    provider: str = "anthropic"  # "anthropic" | "gemini"
    model: str = "claude-sonnet-4-20250514"
    api_key: str = ""
    gemini_api_key: str = ""
    max_tokens: int = 4000
    temperature: float = 0.1
    timeout: int = 60
    max_retries: int = 3
    requests_per_minute: float = 10.0
    # Gemini batch settings (inline, no GCS required)
    batch_enabled: bool = False
    batch_poll_interval: float = 5.0
    batch_max_wait: int = 3600


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
    Multi-provider LLM client.
    Supports Anthropic Claude and Google Gemini (batch via GCS).
    Thread-safe, rate-limited, with retry logic.
    """

    ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
    GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta"

    def __init__(self, config: LLMConfig):
        self.config = config
        self.session = create_http_session(max_retries=config.max_retries)
        self.rate_limiter = RateLimiter(
            requests_per_second=config.requests_per_minute / 60.0,
            burst=3
        )
        self._validate_config()

    def _validate_config(self):
        """Validate API key presence based on provider."""
        if self.config.provider == "anthropic":
            if not self.config.api_key:
                raise ValueError(
                    "Anthropic API key required. Set HARZAP_LLM_API_KEY."
                )
        elif self.config.provider == "gemini":
            if not self.config.gemini_api_key:
                raise ValueError(
                    "Gemini API key required. Set HARZAP_GEMINI_API_KEY."
                )
        else:
            raise ValueError(f"Unknown provider: {self.config.provider}")

    def complete(self, prompt: str, system: Optional[str] = None) -> LLMResponse:
        """
        Send completion request to LLM.
        Dispatches to appropriate provider.
        """
        if self.config.provider == "anthropic":
            return self._complete_anthropic(prompt, system)
        elif self.config.provider == "gemini":
            if self.config.batch_enabled:
                return self._complete_gemini_batch(prompt, system)
            return self._complete_gemini(prompt, system)
        else:
            raise ValueError(f"Unknown provider: {self.config.provider}")

    def _complete_anthropic(self, prompt: str, system: Optional[str] = None) -> LLMResponse:
        """Anthropic Claude API call."""
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
                provider="anthropic",
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
            logger.error("llm_error", provider="anthropic", error=str(e))
            raise

    # --- Gemini Methods ---

    def _complete_gemini(self, prompt: str, system: Optional[str] = None) -> LLMResponse:
        """Gemini API call (synchronous, blocks until response)."""
        self.rate_limiter.acquire()
        start_time = time.monotonic()

        # Build contents with system as first user message
        contents = []
        if system:
            contents.append({"role": "user", "parts": [{"text": system}]})
            contents.append({"role": "model", "parts": [{"text": "Understood."}]})
        contents.append({"role": "user", "parts": [{"text": prompt}]})

        url = f"{self.GEMINI_API_URL}/models/{self.config.model}:generateContent"
        payload = {
            "contents": contents,
            "generationConfig": {
                "maxOutputTokens": self.config.max_tokens,
                "temperature": self.config.temperature
            }
        }

        try:
            response = self.session.post(
                url,
                params={"key": self.config.gemini_api_key},
                json=payload,
                timeout=self.config.timeout
            )
            response.raise_for_status()
            data = response.json()

            # Extract text from response
            text = ""
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    text = parts[0].get("text", "")

            latency = (time.monotonic() - start_time) * 1000
            usage = data.get("usageMetadata", {})

            logger.info(
                "llm_complete",
                provider="gemini",
                model=self.config.model,
                input_tokens=usage.get("promptTokenCount", 0),
                output_tokens=usage.get("candidatesTokenCount", 0),
                latency_ms=round(latency, 2)
            )

            return LLMResponse(
                content=text,
                model=self.config.model,
                usage=usage,
                latency_ms=latency
            )

        except Exception as e:
            logger.error("llm_error", provider="gemini", error=str(e))
            raise

    # --- Gemini Batch Methods (inline, no GCS) ---

    def _complete_gemini_batch(self, prompt: str, system: Optional[str] = None) -> LLMResponse:
        """Gemini batch completion with inline requests. BLOCKING until done."""
        self.rate_limiter.acquire()
        start_time = time.monotonic()

        try:
            # Build contents
            contents = []
            if system:
                contents.append({"role": "user", "parts": [{"text": system}]})
                contents.append({"role": "model", "parts": [{"text": "Understood."}]})
            contents.append({"role": "user", "parts": [{"text": prompt}]})

            # Create batch job with inline request
            batch_url = f"{self.GEMINI_API_URL}/models/{self.config.model}:batchGenerateContent"
            payload = {
                "batch": {
                    "display_name": f"harzap-{uuid.uuid4().hex[:8]}",
                    "input_config": {
                        "requests": {
                            "requests": [{
                                "request": {
                                    "contents": contents,
                                    "generationConfig": {
                                        "maxOutputTokens": self.config.max_tokens,
                                        "temperature": self.config.temperature
                                    }
                                },
                                "metadata": {"key": "req-0"}
                            }]
                        }
                    }
                }
            }

            response = self.session.post(
                batch_url,
                params={"key": self.config.gemini_api_key},
                json=payload,
                timeout=self.config.timeout
            )
            response.raise_for_status()
            job_data = response.json()
            job_name = job_data.get("name", "")
            logger.info("gemini_batch_created", job=job_name)

            # Poll until done (BLOCKING)
            content = self._poll_gemini_batch(job_name)

            latency = (time.monotonic() - start_time) * 1000
            logger.info("llm_complete", provider="gemini_batch", model=self.config.model, latency_ms=round(latency, 2))

            return LLMResponse(content=content, model=self.config.model, usage={}, latency_ms=latency)

        except Exception as e:
            logger.error("llm_error", provider="gemini_batch", error=str(e))
            raise

    def _poll_gemini_batch(self, job_name: str) -> str:
        """Poll batch job until complete, return content. BLOCKING."""
        url = f"{self.GEMINI_API_URL}/{job_name}"
        deadline = time.monotonic() + self.config.batch_max_wait

        while time.monotonic() < deadline:
            response = self.session.get(
                url,
                params={"key": self.config.gemini_api_key},
                timeout=self.config.timeout
            )
            response.raise_for_status()
            data = response.json()

            state = data.get("state", "")
            if state == "JOB_STATE_SUCCEEDED":
                logger.info("gemini_batch_done", job=job_name)
                # Extract from inline responses
                responses = data.get("dest", {}).get("inlinedResponses", [])
                if responses and responses[0].get("response"):
                    resp = responses[0]["response"]
                    candidates = resp.get("candidates", [])
                    if candidates:
                        parts = candidates[0].get("content", {}).get("parts", [])
                        if parts:
                            return parts[0].get("text", "")
                return ""

            if state in ("JOB_STATE_FAILED", "JOB_STATE_CANCELLED"):
                raise RuntimeError(f"Gemini batch failed: {state}")

            logger.debug("gemini_batch_polling", job=job_name, state=state)
            time.sleep(self.config.batch_poll_interval)

        raise TimeoutError(f"Gemini batch timeout after {self.config.batch_max_wait}s")

    @staticmethod
    def from_config(config: Dict) -> 'LLMClient':
        """Factory from config dict."""
        llm_config = config.get('llm', {})
        provider = llm_config.get('provider', 'anthropic')

        # Provider-specific model defaults
        if provider == 'gemini':
            default_model = 'gemini-1.5-pro'
        else:
            default_model = 'claude-sonnet-4-20250514'

        batch_enabled_env = os.environ.get('HARZAP_LLM_BATCH_ENABLED', '').lower()
        batch_enabled = batch_enabled_env in ('true', '1', 'yes') if batch_enabled_env else llm_config.get('batch_enabled', False)

        return LLMClient(LLMConfig(
            provider=provider,
            model=llm_config.get('model', default_model),
            api_key=os.environ.get('HARZAP_LLM_API_KEY', llm_config.get('api_key', '')),
            gemini_api_key=os.environ.get('HARZAP_GEMINI_API_KEY', llm_config.get('gemini_api_key', '')),
            max_tokens=llm_config.get('max_tokens', 4000),
            temperature=llm_config.get('temperature', 0.1),
            timeout=llm_config.get('timeout', 60),
            max_retries=llm_config.get('max_retries', 3),
            requests_per_minute=llm_config.get('requests_per_minute', 10.0),
            batch_enabled=batch_enabled,
            batch_poll_interval=llm_config.get('batch_poll_interval', 5.0),
            batch_max_wait=llm_config.get('batch_max_wait', 3600)
        ))
