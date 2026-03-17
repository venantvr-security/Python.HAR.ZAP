"""
Fuzzer Vocabulary Strategy - Domain-specific fuzzing vocabulary.
"""
from typing import Dict, List

from .base import BaseAttackStrategy


class FuzzerVocabularyStrategy(BaseAttackStrategy):
    """Fuzzer strategy with LLM-generated domain vocabulary."""

    ATTACK_TYPE = "fuzzer"

    def get_enriched_payloads(self) -> List[Dict]:
        """Get domain-specific fuzzing vocabulary."""
        if not self.strategy:
            return []

        vocab = []
        for p in self.strategy.payloads:
            if isinstance(p, dict):
                vocab.append({
                    'key': p.get('key', p.get('name', '')),
                    'values': p.get('values', p.get('test_values', [])),
                    'category': p.get('category', 'custom')
                })
        return vocab

    def get_targets(self) -> List[Dict]:
        """Get endpoints to fuzz."""
        if not self.strategy:
            return []
        return self.strategy.targets

    def get_vocabulary_by_category(self, category: str) -> List[Dict]:
        """Get vocabulary filtered by category."""
        return [
            v for v in self.get_enriched_payloads()
            if v.get('category') == category
        ]

    def get_all_keys(self) -> List[str]:
        """Get all parameter keys to fuzz."""
        return [v['key'] for v in self.get_enriched_payloads() if v.get('key')]

    def get_values_for_key(self, key: str) -> List[str]:
        """Get fuzzing values for a specific key."""
        for v in self.get_enriched_payloads():
            if v.get('key') == key:
                return v.get('values', [])
        return []

    def to_wordlist(self) -> Dict[str, List[str]]:
        """Convert to wordlist format for ZAP fuzzer."""
        wordlist = {}
        for v in self.get_enriched_payloads():
            key = v.get('key')
            if key:
                wordlist[key] = v.get('values', [])
        return wordlist
