"""Tests du vocabulaire d'investigation commun + unification des moteurs."""
from modules.llm.investigation import (
    Verdict, Evidence, CONFIRMED, SUSPECTED, REFUTED, run_confirmations, summarize)


class TestVerdict:
    def test_confirmed_and_actionable(self):
        assert Verdict(CONFIRMED).confirmed
        assert Verdict(CONFIRMED).actionable and Verdict(SUSPECTED).actionable
        assert not Verdict(REFUTED).actionable
        assert not Verdict(SUSPECTED).confirmed

    def test_summarize_counts(self):
        vs = [Verdict(CONFIRMED), Verdict(SUSPECTED), Verdict(SUSPECTED), Verdict(REFUTED)]
        assert summarize(vs) == {CONFIRMED: 1, SUSPECTED: 2, REFUTED: 1}

    def test_run_confirmations_pairs(self):
        pairs = run_confirmations([1, 2, 3], lambda h: Verdict(
            CONFIRMED if h % 2 else REFUTED))
        assert [p[1].status for p in pairs] == [CONFIRMED, REFUTED, CONFIRMED]

    def test_evidence_serialization(self):
        v = Verdict(CONFIRMED, "r", 0.9, "deterministic", Evidence("req", "resp", "n"))
        d = v.to_dict()
        assert d['status'] == CONFIRMED and d['evidence']['request'] == "req"


class TestEngineUnification:
    """Les moteurs existants parlent le vocabulaire commun."""

    def test_mass_assignment_verdicts(self):
        from modules.llm.adaptive_mass_assignment import MAFinding
        f = MAFinding("u", accepted_fields=[{'field': 'admin', 'value': True, 'reason': 'r'}],
                      suspected_fields=[{'field': 'role', 'value': 'x', 'reason': 'r'}])
        statuses = {v.status for v in f.verdicts()}
        assert CONFIRMED in statuses and SUSPECTED in statuses

    def test_bola_verdict(self):
        from modules.llm.bola_investigator import BolaFinding
        v = BolaFinding("u", "name1", "admin", 200, True, "r", "deterministic").verdict
        assert v.status == CONFIRMED
        v2 = BolaFinding("u", "name1", None, 200, False, "r", "suspected").verdict
        assert v2.status == SUSPECTED

    def test_probe_verdict(self):
        from modules.active_probes import ProbeFinding
        assert ProbeFinding("API7", "Critical", "t", "u").verdict.status == CONFIRMED
        assert ProbeFinding("API7", "High", "t", "u", source="llm").verdict.status == SUSPECTED


class TestMixAdjudicate:
    """Décision mixte : déterministe souverain, IA seulement sur SUSPECTED."""

    class _AI:
        def __init__(self, decision): self.decision = decision

        class _R:
            def __init__(self, c): self.content = c

        def complete(self, prompt, system=None):
            import json as _j
            return self._R(_j.dumps({"decision": self.decision, "reason": "x"}))

    def test_confirmed_untouched_by_ai(self):
        from modules.llm.investigation import mix_adjudicate
        v = mix_adjudicate(Verdict(CONFIRMED, "proof"), {}, self._AI("false_positive"))
        assert v.status == CONFIRMED and v.source == "deterministic"

    def test_refuted_untouched_by_ai(self):
        from modules.llm.investigation import mix_adjudicate
        v = mix_adjudicate(Verdict(REFUTED, "disproof"), {}, self._AI("real"))
        assert v.status == REFUTED

    def test_suspected_promoted_or_dropped(self):
        from modules.llm.investigation import mix_adjudicate
        assert mix_adjudicate(Verdict(SUSPECTED), {}, self._AI("real")).status == CONFIRMED
        assert mix_adjudicate(Verdict(SUSPECTED), {}, self._AI("false_positive")).status == REFUTED
        assert mix_adjudicate(Verdict(SUSPECTED), {}, self._AI("uncertain")).status == SUSPECTED

    def test_offline_keeps_suspected(self):
        from modules.llm.investigation import mix_adjudicate
        assert mix_adjudicate(Verdict(SUSPECTED), {}, None).status == SUSPECTED
