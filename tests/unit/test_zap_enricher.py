"""Tests for ZAP payload enricher module"""
import pytest
from unittest.mock import Mock, patch, MagicMock

from modules.zap_enricher import (
    ZAPPayloadEnricher,
    EnrichedPayloadSet,
    KNOWN_ZAP_CATEGORIES,
)


@pytest.fixture
def config_with_mapping():
    """Config with payload mapping"""
    return {
        "payload_mapping": {
            "numeric_id": {
                "zap_categories": ["jbrofuzz/Integer Overflow"],
                "custom": ["0", "-1", "999999", "2147483647"]
            },
            "uuid": {
                "zap_categories": [],
                "custom": ["00000000-0000-0000-0000-000000000000"]
            },
            "file_path": {
                "zap_categories": ["fuzzdb/attack/path-traversal"],
                "custom": ["../../../etc/passwd"]
            },
            "email": {
                "zap_categories": [],
                "custom": ["admin@target.com", "test'--@x.com"]
            }
        }
    }


@pytest.fixture
def mock_zap():
    """Mock ZAP instance"""
    return Mock()


class TestZAPPayloadEnricher:
    """Test ZAP payload enrichment"""

    def test_init_without_zap(self, config_with_mapping):
        enricher = ZAPPayloadEnricher(zap=None, config=config_with_mapping)
        assert enricher.zap is None
        assert enricher.payload_mapping == config_with_mapping['payload_mapping']

    def test_init_with_zap(self, mock_zap, config_with_mapping):
        enricher = ZAPPayloadEnricher(zap=mock_zap, config=config_with_mapping)
        assert enricher.zap == mock_zap

    def test_init_without_config(self):
        enricher = ZAPPayloadEnricher(zap=None, config=None)
        assert enricher.payload_mapping == {}

    def test_get_available_lists_without_zap(self, config_with_mapping):
        enricher = ZAPPayloadEnricher(zap=None, config=config_with_mapping)
        lists = enricher.get_available_lists()

        assert lists == KNOWN_ZAP_CATEGORIES
        assert "jbrofuzz/Integer Overflow" in lists
        assert "fuzzdb/attack/path-traversal" in lists

    def test_get_available_lists_with_zap(self, mock_zap, config_with_mapping):
        enricher = ZAPPayloadEnricher(zap=mock_zap, config=config_with_mapping)
        lists = enricher.get_available_lists()

        # Should return known categories as fallback
        assert len(lists) > 0

    def test_get_custom_payloads(self, config_with_mapping):
        enricher = ZAPPayloadEnricher(zap=None, config=config_with_mapping)

        numeric_payloads = enricher.get_custom_payloads('numeric_id')
        assert '0' in numeric_payloads
        assert '-1' in numeric_payloads
        assert '999999' in numeric_payloads

    def test_get_custom_payloads_unknown_pattern(self, config_with_mapping):
        enricher = ZAPPayloadEnricher(zap=None, config=config_with_mapping)

        payloads = enricher.get_custom_payloads('unknown_pattern')
        assert payloads == []

    def test_get_zap_categories_for_pattern(self, config_with_mapping):
        enricher = ZAPPayloadEnricher(zap=None, config=config_with_mapping)

        categories = enricher.get_zap_categories_for_pattern('numeric_id')
        assert 'jbrofuzz/Integer Overflow' in categories

        categories = enricher.get_zap_categories_for_pattern('uuid')
        assert categories == []

    def test_load_payloads_for_pattern(self, config_with_mapping):
        enricher = ZAPPayloadEnricher(zap=None, config=config_with_mapping)

        payload_set = enricher.load_payloads_for_pattern('numeric_id')

        assert isinstance(payload_set, EnrichedPayloadSet)
        assert payload_set.pattern_type == 'numeric_id'
        assert '0' in payload_set.custom_payloads
        assert '-1' in payload_set.custom_payloads
        assert len(payload_set.combined) > 0

    def test_load_payloads_for_pattern_email(self, config_with_mapping):
        enricher = ZAPPayloadEnricher(zap=None, config=config_with_mapping)

        payload_set = enricher.load_payloads_for_pattern('email')

        assert 'admin@target.com' in payload_set.custom_payloads
        assert "test'--@x.com" in payload_set.custom_payloads

    def test_enrich_payloads(self, config_with_mapping):
        enricher = ZAPPayloadEnricher(zap=None, config=config_with_mapping)

        base_payloads = ['100', '200']
        result = enricher.enrich_payloads(base_payloads, 'numeric_id')

        assert '100' in result.combined
        assert '200' in result.combined
        assert '0' in result.combined
        assert '-1' in result.combined

    def test_enrich_payloads_without_custom(self, config_with_mapping):
        enricher = ZAPPayloadEnricher(zap=None, config=config_with_mapping)

        base_payloads = ['100']
        result = enricher.enrich_payloads(
            base_payloads, 'numeric_id',
            include_custom=False
        )

        assert '100' in result.combined
        assert result.custom_payloads == []

    def test_enrich_payloads_without_zap(self, config_with_mapping):
        enricher = ZAPPayloadEnricher(zap=None, config=config_with_mapping)

        base_payloads = ['100']
        result = enricher.enrich_payloads(
            base_payloads, 'numeric_id',
            include_zap=False
        )

        assert '100' in result.combined
        assert '0' in result.combined  # custom still included

    def test_enrich_deduplication(self, config_with_mapping):
        enricher = ZAPPayloadEnricher(zap=None, config=config_with_mapping)

        # Include a payload that's also in custom
        base_payloads = ['0', '100', '0']
        result = enricher.enrich_payloads(base_payloads, 'numeric_id')

        # Should not have duplicates
        assert result.combined.count('0') == 1

    def test_preview_payloads(self, config_with_mapping):
        enricher = ZAPPayloadEnricher(zap=None, config=config_with_mapping)

        preview = enricher.preview_payloads('numeric_id', limit=10)

        assert 'pattern_type' in preview
        assert 'total_count' in preview
        assert 'custom_count' in preview
        assert 'zap_count' in preview
        assert 'payloads' in preview
        assert preview['pattern_type'] == 'numeric_id'

    def test_preview_payloads_limit(self, config_with_mapping):
        enricher = ZAPPayloadEnricher(zap=None, config=config_with_mapping)

        preview = enricher.preview_payloads('numeric_id', limit=2)

        assert len(preview['payloads']) <= 2

    def test_preview_payloads_truncated_flag(self, config_with_mapping):
        enricher = ZAPPayloadEnricher(zap=None, config=config_with_mapping)

        preview = enricher.preview_payloads('numeric_id', limit=1)

        # With 4 custom payloads and limit=1, should be truncated
        assert preview['truncated'] == True

    def test_get_all_pattern_payloads(self, config_with_mapping):
        enricher = ZAPPayloadEnricher(zap=None, config=config_with_mapping)

        all_payloads = enricher.get_all_pattern_payloads()

        assert 'numeric_id' in all_payloads
        assert 'uuid' in all_payloads
        assert 'file_path' in all_payloads
        assert 'email' in all_payloads

    def test_load_payloads_from_file(self, config_with_mapping, tmp_path):
        enricher = ZAPPayloadEnricher(zap=None, config=config_with_mapping)

        # Create temp payload file
        payload_file = tmp_path / "test_payloads.txt"
        payload_file.write_text("payload1\npayload2\n# comment\npayload3")

        payloads = enricher.load_payloads_from_file(str(payload_file))

        assert 'payload1' in payloads
        assert 'payload2' in payloads
        assert 'payload3' in payloads
        assert '# comment' not in payloads

    def test_load_payloads_from_nonexistent_file(self, config_with_mapping):
        enricher = ZAPPayloadEnricher(zap=None, config=config_with_mapping)

        payloads = enricher.load_payloads_from_file('/nonexistent/path.txt')
        assert payloads == []

    def test_load_payloads_from_zap_without_zap(self, config_with_mapping):
        enricher = ZAPPayloadEnricher(zap=None, config=config_with_mapping)

        payloads = enricher.load_payloads_from_zap('jbrofuzz/XSS')
        assert payloads == []


class TestEnrichedPayloadSet:
    """Test EnrichedPayloadSet dataclass"""

    def test_default_values(self):
        payload_set = EnrichedPayloadSet(pattern_type='test')

        assert payload_set.pattern_type == 'test'
        assert payload_set.zap_payloads == []
        assert payload_set.custom_payloads == []
        assert payload_set.combined == []
        assert payload_set.source_files == []

    def test_with_values(self):
        payload_set = EnrichedPayloadSet(
            pattern_type='numeric_id',
            zap_payloads=['zap1', 'zap2'],
            custom_payloads=['custom1'],
            combined=['zap1', 'zap2', 'custom1'],
            source_files=['jbrofuzz/test']
        )

        assert payload_set.pattern_type == 'numeric_id'
        assert len(payload_set.zap_payloads) == 2
        assert len(payload_set.custom_payloads) == 1
        assert len(payload_set.combined) == 3
        assert 'jbrofuzz/test' in payload_set.source_files


class TestKnownCategories:
    """Test known ZAP categories constant"""

    def test_known_categories_not_empty(self):
        assert len(KNOWN_ZAP_CATEGORIES) > 0

    def test_known_categories_contains_expected(self):
        assert "jbrofuzz/Integer Overflow" in KNOWN_ZAP_CATEGORIES
        assert "jbrofuzz/XSS" in KNOWN_ZAP_CATEGORIES
        assert "fuzzdb/attack/path-traversal" in KNOWN_ZAP_CATEGORIES
        assert "fuzzdb/attack/sql-injection" in KNOWN_ZAP_CATEGORIES


class TestRateLimiting:
    """Test rate limiting behavior"""

    def test_rate_limiter_initialized(self, config_with_mapping):
        config_with_mapping['rate_limit'] = 5.0
        enricher = ZAPPayloadEnricher(zap=None, config=config_with_mapping)

        assert enricher.rate_limiter is not None

    def test_rate_limiter_default(self):
        enricher = ZAPPayloadEnricher(zap=None, config={})
        assert enricher.rate_limiter is not None
