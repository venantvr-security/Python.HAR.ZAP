"""Tests du moteur actif d'abus de flux métier (API6)."""
import pytest
from modules.business_flow import (
    extract_flows, BusinessFlowScanner, Flow, Step, _accepted)


def _entry(m, u, body=None):
    r = {"request": {"method": m, "url": u,
                     "headers": [{"name": "Authorization", "value": "Bearer U"}]}}
    if body is not None:
        r["request"]["postData"] = {"text": body}
    return r


HAR = {"log": {"entries": [
    _entry("POST", "https://api.x/v1/orders/cart", '{"item":"A","quantity":1}'),
    _entry("POST", "https://api.x/v1/orders/pay", '{"amount":100}'),
    _entry("POST", "https://api.x/v1/orders/confirm", '{"order":1}'),
    _entry("POST", "https://api.x/v1/coupon/redeem", '{"code":"SAVE"}'),
    _entry("GET", "https://api.x/v1/orders/42"),  # ignoré (lecture)
]}}


class TestExtract:
    def test_groups_write_flows(self):
        flows = {f.name: f for f in extract_flows(HAR)}
        assert 'orders' in flows and 'coupon' in flows
        assert [s.path for s in flows['orders'].steps] == \
            ['/v1/orders/cart', '/v1/orders/pay', '/v1/orders/confirm']

    def test_parses_json_body(self):
        flows = {f.name: f for f in extract_flows(HAR)}
        assert flows['orders'].steps[0].body == {'item': 'A', 'quantity': 1}

    def test_ignores_reads(self):
        assert all(s.method in ('POST', 'PUT', 'PATCH')
                   for f in extract_flows(HAR) for s in f.steps)


def _vuln_server(method, url, headers, body):
    if "/confirm" in url:
        return {"status": 200, "body": "order confirmed"}       # saut d'état accepté
    if "/pay" in url and body and body.get("amount", 0) < 0:
        return {"status": 200, "body": "paid"}                   # négatif accepté
    if "/redeem" in url:
        return {"status": 200, "body": "applied"}                # rejeu accepté
    return {"status": 200, "body": "ok"}


def _strict_server(method, url, headers, body):
    if "/confirm" in url:
        return {"status": 403, "body": "payment required"}       # ordre appliqué
    if body and any(isinstance(v, (int, float)) and not (0 < v <= 1000000) for v in body.values()):
        return {"status": 400, "body": "validation error: out of range"}
    if "/redeem" in url:
        return {"status": 409, "body": "coupon already used"}    # usage unique appliqué
    return {"status": 200, "body": "ok"}


class TestScanner:
    def test_detects_all_three_abuses(self):
        findings = BusinessFlowScanner(_vuln_server).run(extract_flows(HAR))
        kinds = {f.kind for f in findings}
        assert {'state_skip', 'value_manipulation', 'replay'} <= kinds

    def test_strict_server_clean(self):
        assert BusinessFlowScanner(_strict_server).run(extract_flows(HAR)) == []

    def test_state_skip_needs_guard(self):
        # flux sans étape gardienne -> pas de saut d'état signalé
        flow = Flow('x', [Step('POST', 'https://api.x/a'), Step('POST', 'https://api.x/b')])
        assert not any(f.kind == 'state_skip'
                       for f in BusinessFlowScanner(_vuln_server).run([flow]))

    def test_error_marker_blocks_acceptance(self):
        assert not _accepted({'status': 200, 'body': 'validation error'})
        assert _accepted({'status': 200, 'body': 'ok'})
        assert not _accepted({'status': 403, 'body': 'ok'})

    def test_findings_flat(self):
        f = BusinessFlowScanner(_vuln_server).run(extract_flows(HAR))[0].flat()
        assert f['source'] == 'business_flow' and 'risk' in f
        assert 'status' in f and 'adjudication' in f


class TestFlowKey:
    def test_groups_action_under_resource_without_version(self):
        # /articles/1/publish doit rejoindre /articles, pas être classé sous '1'
        har = {"log": {"entries": [
            _entry("POST", "https://x/articles", '{"title":"t"}'),
            _entry("POST", "https://x/articles/1/publish"),
        ]}}
        flows = {f.name: f for f in extract_flows(har)}
        assert 'articles' in flows and len(flows['articles'].steps) == 2


class TestWorkflowTransition:
    HAR = {"log": {"entries": [
        _entry("POST", "https://x/articles", '{"title":"t"}'),
        _entry("POST", "https://x/articles/2/publish"),
    ]}}

    def test_transition_suspected_without_readback(self):
        srv = lambda m, u, h, b: {"status": 200, "body": "ok"}
        fs = BusinessFlowScanner(srv).run(extract_flows(self.HAR))
        wt = [f for f in fs if f.kind == 'workflow_transition']
        assert wt and wt[0].status == 'suspected' and "publish" in wt[0].title

    def test_transition_confirmed_with_readback(self):
        def srv(m, u, h, b):
            return {"status": 200, "body": "ok"}
        def read(url):
            # l'objet parent revient à l'état promu -> preuve
            return {"status": 200, "body": '{"id":2,"status":"published"}'}
        fs = BusinessFlowScanner(srv, read_fn=read).run(extract_flows(self.HAR))
        wt = [f for f in fs if f.kind == 'workflow_transition']
        assert wt and wt[0].status == 'confirmed' and wt[0].severity == 'High'

    def test_transition_denied_not_flagged(self):
        srv = lambda m, u, h, b: {"status": 403, "body": "forbidden"}
        fs = BusinessFlowScanner(srv).run(extract_flows(self.HAR))
        assert not any(f.kind == 'workflow_transition' for f in fs)
