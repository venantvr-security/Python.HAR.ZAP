"""Tests de la sortie findings-first (unification, tri, preuve curl, HTML)."""
import pytest
from modules.findings import build_findings, render_cli, render_html, curl_for, Finding


class _IDOR:
    class _O: url = 'https://api.x/v1/users/43'
    observation = _O(); target_url = 'https://api.x/v1/users/42'; vulnerable = True
    class _V: confidence = 0.96
    verdict = _V()


class _MA:
    target_url = 'https://api.x/v1/users/42'
    accepted_fields = [{'field': 'role', 'value': 'admin'}]


class _HP:
    target_url = 'https://api.x/dash'
    active_params = [{'name': 'debug', 'value': 'true'}]


class _Res:
    idor = [_IDOR()]; mass_assignment = [_MA()]; hidden_params = [_HP()]


FLAT = [
    {'source': 'passive', 'risk': 'Low', 'name': 'Missing HSTS', 'url': 'https://api.x/'},
    {'source': 'jwt', 'risk': 'High', 'name': 'alg=none', 'url': 'https://api.x/login'},
]


class TestCurl:
    def test_get_with_auth(self):
        c = curl_for('GET', 'https://x/a')
        assert c.startswith('curl -i -s') and 'Authorization' in c and "'https://x/a'" in c

    def test_write_has_method_and_body(self):
        c = curl_for('PATCH', 'https://x/a', {'role': 'admin'})
        assert '-X PATCH' in c and '"role": "admin"' in c and 'Content-Type' in c

    def test_no_auth(self):
        assert 'Authorization' not in curl_for('GET', 'https://x/a', auth=False)


class TestBuild:
    def test_unifies_adaptive_and_flat(self):
        fs = build_findings(FLAT, _Res())
        vectors = sorted({f.vector for f in fs})
        assert 'idor' in vectors and 'mass_assignment' in vectors and 'hidden_params' in vectors
        assert 'jwt' in vectors and 'passive' in vectors

    def test_sorted_by_severity(self):
        fs = build_findings(FLAT, _Res())
        ranks = ['Critical', 'High', 'Medium', 'Low', 'Info']
        idx = [ranks.index(f.severity) for f in fs]
        assert idx == sorted(idx)

    def test_idor_has_proof_and_owasp(self):
        fs = build_findings([], _Res())
        idor = next(f for f in fs if f.vector == 'idor')
        assert 'API1' in idor.owasp and idor.proof.startswith('curl') and '/users/43' in idor.proof

    def test_mass_assignment_proof_is_write(self):
        fs = build_findings([], _Res())
        ma = next(f for f in fs if f.vector == 'mass_assignment')
        assert ma.method == 'PATCH' and 'role' in ma.proof

    def test_skips_non_vulnerable_idor(self):
        class NV(_IDOR):
            vulnerable = False
        class R:
            idor = [NV()]; mass_assignment = []; hidden_params = []
        assert not any(f.vector == 'idor' for f in build_findings([], R()))

    def test_no_adaptive_still_works(self):
        fs = build_findings(FLAT, None)
        assert len(fs) == 2


class TestRender:
    def test_cli_lists_findings(self):
        out = render_cli(build_findings(FLAT, _Res()))
        assert 'FINDINGS (5)' in out and 'proof' in out and 'BOLA' in out

    def test_cli_empty(self):
        assert 'none' in render_cli([]).lower()

    def test_html_structure(self):
        h = render_html(build_findings(FLAT, _Res()), {'target': 'https://api.x'})
        assert '<title>' in h and 'API1:2023' in h and 'curl -i -s' in h
        assert 'BOLA' in h and 'PATCH' in h
