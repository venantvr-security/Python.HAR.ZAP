"""Tests du coordinateur de campagne adaptative + extraction de cibles."""
import re
import pytest
from modules.llm.adaptive_campaign import (
    AdaptiveCampaign, id_targets, mutation_targets, get_targets,
)
from modules.llm.pattern_enricher import PatternEnricher

HAR = {"log": {"entries": [
    {"request": {"method": "GET", "url": "https://api.demo.com/v1/users/42"}},
    {"request": {"method": "GET", "url": "https://api.demo.com/v1/orders?order_id=7"}},
    {"request": {"method": "GET", "url": "https://api.demo.com/v1/dashboard"}},
    {"request": {"method": "POST", "url": "https://api.demo.com/v1/users/42"}},
]}}


class TestTargetExtraction:
    def test_id_targets_read_only(self):
        t = id_targets(HAR)
        urls = [x['url'] for x in t]
        # /users/42 (GET) et orders?order_id=7 -> oui ; POST /users/42 -> exclu
        assert any('users/42' in u for u in urls)
        assert any('order_id' in u for u in urls)
        assert all(x['method'].upper() in ('GET', 'HEAD') for x in t)

    def test_mutation_targets_write_only(self):
        t = mutation_targets(HAR)
        assert len(t) == 1 and t[0]['method'] == 'POST'

    def test_get_targets(self):
        t = get_targets(HAR)
        assert any('dashboard' in x['url'] for x in t)


def http_get(url, method='GET'):
    m = re.search(r'/users/(\d+)', url)
    cid = m.group(1) if m else ''
    if '/users/' in url:
        if cid == '42':
            return {'status': 200, 'content_length': 500, 'body': 'own'}
        if cid in ('43', '44'):
            return {'status': 200, 'content_length': 480, 'body': f'user {cid}'}
        return {'status': 403, 'content_length': 20, 'body': 'no'}
    if 'order_id=' in url:
        return {'status': 200, 'content_length': 400, 'body': 'order'}
    if 'debug=true' in url:
        return {'status': 200, 'content_length': 3000, 'body': 'Traceback: boom'}
    return {'status': 200, 'content_length': 300, 'body': 'page'}


def http_write(url, method, payload):
    f = list(payload)[0]
    return {'status': 200, 'body': 'ok'} if f in ('role', 'is_admin', 'is_superuser') \
        else {'status': 400, 'body': 'invalid'}


class TestCampaign:
    def test_end_to_end_enriches_and_exports(self, tmp_path):
        enr = PatternEnricher.for_run(domain='demo.com', base_path=str(tmp_path))
        res = AdaptiveCampaign(enricher=enr, max_targets=10).run(HAR, http_get, http_write)
        s = res.summary()
        assert s['idor_vulnerable'] >= 1
        assert s['mass_assignment_vulnerable'] == 1
        assert s['hidden_params_vulnerable'] >= 1
        # Wordlists ZAP écrites pour les trois vecteurs
        fuzz = tmp_path / 'zap_export' / 'fuzzers'
        assert (fuzz / 'llm_idor.txt').exists()
        assert (fuzz / 'llm_mass_assignment.txt').exists()
        assert (fuzz / 'llm_hidden_params.txt').exists()
        assert 'role=admin' in (fuzz / 'llm_mass_assignment.txt').read_text()

    def test_runs_without_enricher(self):
        res = AdaptiveCampaign(enricher=None).run(HAR, http_get, http_write)
        assert res.summary()['idor_vulnerable'] >= 1
        assert res.exported == {}
