"""Tests de l'adjudicateur de faux positifs (offline + LLM) et de la passe passive."""
import pytest
from modules.llm.fp_adjudicator import FalsePositiveAdjudicator, FPVerdict
from modules.passive_analysis import SecurityIssue, PassiveAnalysisOrchestrator


def issue(sev, match, category='Data Leakage', title='x'):
    return SecurityIssue(sev, category, title, '', {'match': match}, '')


class _Resp:
    def __init__(self, c): self.content = c


class TestOffline:
    def test_placeholder_is_false_positive(self):
        v = FalsePositiveAdjudicator().adjudicate(issue('HIGH', 'jane.doe@example.com'))
        assert not v.is_true_positive and v.source == 'offline'

    def test_repeated_value_is_false_positive(self):
        v = FalsePositiveAdjudicator().adjudicate(issue('MEDIUM', '0000000'))
        assert not v.is_true_positive

    def test_real_secret_kept(self):
        v = FalsePositiveAdjudicator().adjudicate(issue('HIGH', 'AKIA9REAL2KEY7XZ'))
        assert v.is_true_positive and v.confidence >= 0.8

    def test_accepts_dict_issue(self):
        v = FalsePositiveAdjudicator().adjudicate(
            {'severity': 'LOW', 'evidence': {'match': 'test@test.com'}})
        assert not v.is_true_positive


class TestLLM:
    def test_llm_verdict(self):
        class Client:
            def complete(self, prompt, system=None):
                return _Resp('{"is_true_positive": false, "confidence": 0.9, "reason": "sample"}')
        v = FalsePositiveAdjudicator(Client()).adjudicate(issue('HIGH', 'AKIAREALKEY'))
        assert not v.is_true_positive and v.source == 'llm'

    def test_llm_failure_falls_back(self):
        class Client:
            def complete(self, prompt, system=None):
                raise RuntimeError("down")
        v = FalsePositiveAdjudicator(Client()).adjudicate(issue('HIGH', 'AKIAREALKEY'))
        assert v.source == 'offline'


class TestPartition:
    def test_partition_filters_only_confident_fps(self):
        adj = FalsePositiveAdjudicator()
        kept, filtered = adj.partition([
            issue('HIGH', 'user@example.com'),   # FP
            issue('HIGH', 'AKIAREALSECRET99'),   # TP
        ])
        assert len(filtered) == 1 and len(kept) == 1


class TestPassiveIntegration:
    def test_orchestrator_pass_annotates_and_filters(self):
        orch = PassiveAnalysisOrchestrator.__new__(PassiveAnalysisOrchestrator)
        orch.results = {'data_leaks': [
            issue('HIGH', 'john.doe@example.com'),
            issue('HIGH', 'AKIAREALSECRET99'),
        ]}
        stats = orch.adjudicate_false_positives(FalsePositiveAdjudicator())
        assert stats['reviewed'] == 2 and stats['filtered_false_positives'] == 1
        assert len(orch.results['data_leaks']) == 1
        assert 'fp_verdict' in orch.results['data_leaks'][0].evidence
