"""Vérifie que la campagne adaptative de diagnose passe par le proxy ZAP quand un
client ZAP est fourni (et non par requests direct)."""
import re
import pytest
import cli


class _ZResp:
    def __init__(self, status, body):
        self.status_code = status
        self.content = body.encode()
        self.text = body


class _FakeZap:
    def __init__(self):
        self.calls = []

    def request(self, method, url, headers=None, json_data=None, follow_redirects=True):
        self.calls.append(('write' if json_data is not None else 'get', method, url))
        cid = (re.search(r'/users/(\d+)', url) or [None, ''])[1]
        if json_data is not None:
            f = list(json_data)[0]
            return _ZResp(200 if f in ('role', 'is_admin') else 400, 'ok')
        if '/users/' in url:
            if cid == '42':
                return _ZResp(200, 'own' * 200)
            if cid in ('43', '44'):
                return _ZResp(200, 'leak' * 120)
            return _ZResp(403, 'no')
        return _ZResp(200, 'page')


class _Args:
    target = 'https://api.demo.com'


HAR = {"log": {"entries": [
    {"request": {"method": "GET", "url": "https://api.demo.com/v1/users/42"}},
    {"request": {"method": "POST", "url": "https://api.demo.com/v1/users/42"}},
]}}


def test_adaptive_routes_through_zap(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # isole ./patterns
    zap = _FakeZap()
    result = cli._run_adaptive_campaign(HAR, {}, _Args(), zap_client=zap)
    summary = result.summary()
    # Tout le trafic est passé par le client ZAP.
    assert len(zap.calls) > 0
    assert any(c[0] == 'write' for c in zap.calls)  # mass assignment via ZAP
    assert any(c[0] == 'get' for c in zap.calls)    # IDOR via ZAP
    assert summary['idor_vulnerable'] >= 1
    assert summary['mass_assignment_vulnerable'] == 1
    # Les wordlists ZAP sont bien produites.
    assert 'idor' in summary['zap_exported'] and 'mass_assignment' in summary['zap_exported']
    assert (tmp_path / 'patterns' / 'zap_export' / 'fuzzers' / 'llm_idor.txt').exists()
