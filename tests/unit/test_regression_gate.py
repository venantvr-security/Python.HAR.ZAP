"""Tests de la gate de régression sécurité."""
import json
import pytest
from modules.regression_gate import (
    RegressionGate, GateResult, endpoint_template, finding_signature,
    normalize_diag_findings, normalize_adaptive,
)


class TestTemplate:
    def test_collapses_numeric_and_uuid(self):
        assert endpoint_template("https://x/v1/users/42/orders/7") == "/v1/users/{id}/orders/{id}"
        u = "a3f1c2d4-1111-4222-8333-444455556666"
        assert endpoint_template(f"https://x/o/{u}") == "/o/{id}"

    def test_keeps_words(self):
        assert endpoint_template("https://x/v1/dashboard") == "/v1/dashboard"

    def test_signature_stable_across_ids(self):
        a = finding_signature({'type': 'idor(API1)', 'endpoint': 'https://x/users/42'})
        b = finding_signature({'type': 'idor(API1)', 'endpoint': 'https://x/users/99'})
        assert a == b


class TestNormalizeAdaptive:
    def test_extracts_high_value_findings(self):
        class IDOR:
            target_url = 'https://x/users/42'; vulnerable = True
        class MA:
            target_url = 'https://x/users/42'
            accepted_fields = [{'field': 'role'}]
        class HP:
            target_url = 'https://x/dash'
            active_params = [{'name': 'debug'}]
        class Res:
            idor = [IDOR()]; mass_assignment = [MA()]; hidden_params = [HP()]
        out = normalize_adaptive(Res())
        types = sorted(f['type'] for f in out)
        assert types == ['hidden_params(API5)', 'idor(API1)', 'mass_assignment(API3)']

    def test_none_result(self):
        assert normalize_adaptive(None) == []


class TestGate:
    def _findings(self, extra=None):
        base = [
            {'source': 'idor(API1)', 'url': 'https://x/v1/users/42', 'name': 'BOLA', 'risk': 'High'},
            {'source': 'passive', 'url': 'https://x/', 'name': 'Missing HSTS', 'risk': 'Low'},
        ]
        return normalize_diag_findings(base + (extra or []))

    def test_establish_baseline(self, tmp_path):
        bp = tmp_path / 'b.json'
        r = RegressionGate(str(bp)).evaluate(self._findings(), update=True)
        assert r.passed and r.baseline_updated and bp.exists()
        assert 'signatures' in json.loads(bp.read_text())

    def test_same_bug_different_id_is_not_new(self, tmp_path):
        bp = tmp_path / 'b.json'
        g = RegressionGate(str(bp))
        g.evaluate(self._findings(), update=True)
        # même BOLA, id différent
        later = normalize_diag_findings([
            {'source': 'idor(API1)', 'url': 'https://x/v1/users/777', 'name': 'BOLA', 'risk': 'High'},
            {'source': 'passive', 'url': 'https://x/', 'name': 'Missing HSTS', 'risk': 'Low'},
        ])
        r = g.evaluate(later)
        assert r.passed and len(r.new) == 0 and len(r.unchanged) == 2

    def test_new_finding_fails_gate(self, tmp_path):
        bp = tmp_path / 'b.json'
        g = RegressionGate(str(bp))
        g.evaluate(self._findings(), update=True)
        r = g.evaluate(self._findings(extra=[
            {'source': 'mass_assignment(API3)', 'url': 'https://x/v1/users/1', 'name': 'role', 'risk': 'High'}]))
        assert not r.passed and len(r.new) == 1
        assert r.new[0]['signature'].startswith('mass_assignment(api3)')

    def test_fixed_finding_reported(self, tmp_path):
        bp = tmp_path / 'b.json'
        g = RegressionGate(str(bp))
        g.evaluate(self._findings(extra=[
            {'source': 'jwt', 'url': 'https://x/login', 'name': 'alg=none', 'risk': 'High'}]), update=True)
        r = g.evaluate(self._findings())  # jwt disparu
        assert r.passed and any('jwt' in s for s in r.fixed)

    def test_missing_baseline_treats_all_as_new(self, tmp_path):
        r = RegressionGate(str(tmp_path / 'nope.json')).evaluate(self._findings())
        assert not r.passed and len(r.new) == 2


class TestStatusAwareGate:
    """La gate porte le statut : n'échoue que sur du nouveau CONFIRMÉ ; le
    suspecté est remonté sans casser le build (sauf strict)."""

    def _sig(self, status):
        return [{'type': 'bola', 'endpoint': 'https://x/o/1', 'detail': 'd', 'status': status}]

    def test_new_suspected_does_not_fail(self, tmp_path):
        g = RegressionGate(str(tmp_path / 'b.json'))
        g.evaluate([], update=True)                       # baseline vide
        r = g.evaluate(self._sig('suspected'))
        assert r.passed and r.summary()['new_suspected'] == 1 and r.summary()['new_confirmed'] == 0

    def test_new_confirmed_fails(self, tmp_path):
        g = RegressionGate(str(tmp_path / 'b.json'))
        g.evaluate([], update=True)
        r = g.evaluate(self._sig('confirmed'))
        assert not r.passed and r.summary()['new_confirmed'] == 1

    def test_strict_fails_on_suspected(self, tmp_path):
        g = RegressionGate(str(tmp_path / 'b.json'))
        g.evaluate([], update=True)
        r = g.evaluate(self._sig('suspected'), strict=True)
        assert not r.passed

    def test_status_not_in_signature(self, tmp_path):
        # suspecté -> confirmé : même signature (pas un fixed + new).
        g = RegressionGate(str(tmp_path / 'b.json'))
        g.evaluate(self._sig('suspected'), update=True)
        r = g.evaluate(self._sig('confirmed'))
        assert r.new == [] and len(r.unchanged) == 1

    def test_normalize_carries_status(self):
        from modules.regression_gate import normalize_diag_findings
        out = normalize_diag_findings([
            {'source': 'shadow_endpoint', 'url': '/x', 'name': 'n', 'risk': 'Medium',
             'status': 'confirmed'},
            {'source': 'bola', 'url': '/y', 'name': 'm', 'risk': 'High', 'status': 'suspected'}])
        assert {o['status'] for o in out} == {'confirmed', 'suspected'}
