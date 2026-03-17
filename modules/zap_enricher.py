"""
ZAP Payload Enricher - Combine HAR patterns with ZAP fuzzer payloads.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from pathlib import Path

from .utils import get_logger, RateLimiter

logger = get_logger("zap.enricher")

# Known ZAP fuzzdb categories
KNOWN_ZAP_CATEGORIES = [
    "jbrofuzz/Integer Overflow",
    "jbrofuzz/XSS",
    "jbrofuzz/SQLi",
    "jbrofuzz/Path Traversal",
    "jbrofuzz/LDAP Injection",
    "jbrofuzz/XML Injection",
    "fuzzdb/attack/path-traversal",
    "fuzzdb/attack/sql-injection",
    "fuzzdb/attack/xss",
    "fuzzdb/attack/os-cmd-execution",
    "fuzzdb/attack/file-upload",
    "dirbuster/directory-list-2.3-small",
    "dirbuster/directory-list-2.3-medium",
]


@dataclass
class EnrichedPayloadSet:
    pattern_type: str
    zap_payloads: List[str] = field(default_factory=list)
    custom_payloads: List[str] = field(default_factory=list)
    combined: List[str] = field(default_factory=list)
    source_files: List[str] = field(default_factory=list)


class ZAPPayloadEnricher:
    """Enrich payloads with ZAP fuzzer lists."""

    def __init__(self, zap=None, config: Dict = None):
        self.zap = zap
        self.config = config or {}
        self.payload_mapping = self.config.get('payload_mapping', {})
        self.rate_limiter = RateLimiter(
            requests_per_second=self.config.get('rate_limit', 10.0)
        )

    def get_available_lists(self) -> List[str]:
        """List available ZAP payload categories."""
        if not self.zap:
            return KNOWN_ZAP_CATEGORIES

        try:
            # Try ZAP API if available
            self.rate_limiter.acquire()
            # Note: ZAP fuzzer API varies by version
            # Fallback to known categories
            return KNOWN_ZAP_CATEGORIES
        except Exception as e:
            logger.warning("zap_list_error", error=str(e))
            return KNOWN_ZAP_CATEGORIES

    def load_payloads_from_zap(self, category: str) -> List[str]:
        """Load payloads from ZAP fuzzer category."""
        if not self.zap:
            logger.debug("zap_not_available", category=category)
            return []

        try:
            self.rate_limiter.acquire()
            # ZAP stores fuzzers in fuzz/ directory
            # Try to access via script or direct file
            # This is version-dependent, return empty for now
            return []
        except Exception as e:
            logger.warning("zap_payload_load_error", category=category, error=str(e))
            return []

    def get_custom_payloads(self, pattern_type: str) -> List[str]:
        """Get custom payloads for pattern type from config."""
        mapping = self.payload_mapping.get(pattern_type, {})
        return mapping.get('custom', [])

    def get_zap_categories_for_pattern(self, pattern_type: str) -> List[str]:
        """Get ZAP categories mapped to pattern type."""
        mapping = self.payload_mapping.get(pattern_type, {})
        return mapping.get('zap_categories', [])

    def load_payloads_for_pattern(self, pattern_type: str) -> EnrichedPayloadSet:
        """Load all payloads (ZAP + custom) for a pattern type."""
        result = EnrichedPayloadSet(pattern_type=pattern_type)

        # Custom payloads from config
        result.custom_payloads = self.get_custom_payloads(pattern_type)

        # ZAP payloads
        zap_categories = self.get_zap_categories_for_pattern(pattern_type)
        for category in zap_categories:
            payloads = self.load_payloads_from_zap(category)
            result.zap_payloads.extend(payloads)
            if payloads:
                result.source_files.append(category)

        # Combine and dedupe
        result.combined = list(dict.fromkeys(
            result.custom_payloads + result.zap_payloads
        ))

        logger.info(
            "payloads_loaded",
            pattern=pattern_type,
            custom=len(result.custom_payloads),
            zap=len(result.zap_payloads),
            total=len(result.combined)
        )

        return result

    def enrich_payloads(
        self,
        base_payloads: List[str],
        pattern_type: str,
        include_zap: bool = True,
        include_custom: bool = True
    ) -> EnrichedPayloadSet:
        """Enrich base payloads with ZAP and custom lists."""
        result = EnrichedPayloadSet(pattern_type=pattern_type)

        # Start with base payloads
        all_payloads = list(base_payloads)

        # Add custom payloads
        if include_custom:
            custom = self.get_custom_payloads(pattern_type)
            result.custom_payloads = custom
            all_payloads.extend(custom)

        # Add ZAP payloads
        if include_zap:
            zap_categories = self.get_zap_categories_for_pattern(pattern_type)
            for category in zap_categories:
                payloads = self.load_payloads_from_zap(category)
                result.zap_payloads.extend(payloads)
                if payloads:
                    result.source_files.append(category)
            all_payloads.extend(result.zap_payloads)

        # Dedupe while preserving order
        result.combined = list(dict.fromkeys(all_payloads))

        return result

    def load_payloads_from_file(self, file_path: str) -> List[str]:
        """Load payloads from a local file."""
        path = Path(file_path)
        if not path.exists():
            logger.warning("payload_file_not_found", path=file_path)
            return []

        try:
            with open(path) as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            logger.debug("payloads_from_file", path=file_path, count=len(payloads))
            return payloads
        except Exception as e:
            logger.error("payload_file_error", path=file_path, error=str(e))
            return []

    def get_all_pattern_payloads(self) -> Dict[str, EnrichedPayloadSet]:
        """Load payloads for all configured patterns."""
        all_payloads = {}
        for pattern_type in self.payload_mapping:
            all_payloads[pattern_type] = self.load_payloads_for_pattern(pattern_type)
        return all_payloads

    def preview_payloads(
        self,
        pattern_type: str,
        limit: int = 100,
        include_zap: bool = True,
        include_custom: bool = True
    ) -> Dict:
        """Preview payloads for UI/API response."""
        payload_set = self.load_payloads_for_pattern(pattern_type)

        combined = []
        if include_custom:
            combined.extend(payload_set.custom_payloads)
        if include_zap:
            combined.extend(payload_set.zap_payloads)

        combined = list(dict.fromkeys(combined))

        return {
            'pattern_type': pattern_type,
            'total_count': len(combined),
            'custom_count': len(payload_set.custom_payloads) if include_custom else 0,
            'zap_count': len(payload_set.zap_payloads) if include_zap else 0,
            'sources': payload_set.source_files,
            'payloads': combined[:limit],
            'truncated': len(combined) > limit
        }
