"""Tests du planificateur adaptatif (articulation par IA — prototype)."""
import json

from modules.llm.orchestrator import (
    scan_context, deterministic_plan, ai_plan, next_plan, ENGINES, Plan)


def _har(entries):
    return {'log': {'entries': entries}}


def _get(url):
    return {'request': {'method': 'GET', 'url': url, 'headers': []}}


def _post(url, body='{}', auth=False):
    h = [{'name': 'Authorization', 'value': 'Bearer x'}] if auth else []
    return {'request': {'method': 'POST', 'url': url, 'headers': h,
                        'postData': {'text': body}}}


class TestContext:
    def test_detects_shapes(self):
        ctx = scan_context(_har([
            _get('https://x/media?url=http://a'),
            _post('https://x/articles', auth=True),
        ]))
        assert ctx['has_auth'] and ctx['has_writes'] and ctx['has_urlish_params']
        assert ctx['endpoints'] == 2

    def test_graphql_detected(self):
        ctx = scan_context(_har([_post('https://x/graphql', '{"query":"{ me }"}')]))
        assert ctx['is_graphql']


class TestDeterministicPlan:
    def test_urlish_selects_injection_and_web(self):
        ctx = scan_context(_har([_get('https://x/s?q=1&url=http://a')]))
        engines = deterministic_plan(ctx).engines()
        assert {'investigate', 'probes', 'web', 'injection'} <= set(engines)

    def test_writes_select_business_and_adaptive(self):
        ctx = scan_context(_har([_post('https://x/articles', auth=True)]))
        engines = deterministic_plan(ctx).engines()
        assert {'adaptive', 'business_flow', 'matrix_bola'} <= set(engines)

    def test_reactive_auth_bypass_prioritizes_authz(self):
        ctx = scan_context(_har([_get('https://x/me')]),
                           findings=[{'name': 'JWT bypass via alg=none accepted',
                                      'source': 'auth_confirmer'}])
        plan = deterministic_plan(ctx)
        top = plan.ordered()[0]
        assert top.engine == 'matrix_bola' and top.priority == 1

    def test_reactive_ssrf_prioritizes_internal_extrapolation(self):
        ctx = scan_context(_har([_get('https://x/media?url=x')]),
                           findings=[{'name': 'SSRF via body url', 'source': 'probe_api7'}])
        assert deterministic_plan(ctx).ordered()[0].engine == 'investigate'


class _Client:
    def __init__(self, content):
        self._c = content
    def complete(self, user, system=None):
        class R: content = None
        R.content = self._c
        return R()


class TestAiPlan:
    def test_ai_proposal_used_and_validated(self):
        client = _Client(json.dumps({'steps': [
            {'engine': 'injection', 'rationale': 'sql-ish params', 'priority': 1},
            {'engine': 'web', 'rationale': 'xss', 'priority': 2},
        ]}))
        plan = ai_plan(client, scan_context(_har([_get('https://x/s?q=1')])))
        assert plan and plan.source == 'llm'
        assert plan.engines()[0] == 'injection'

    def test_invalid_engines_dropped(self):
        client = _Client(json.dumps({'steps': [
            {'engine': 'rm_-rf', 'rationale': 'evil'},          # inventé -> écarté
            {'engine': 'web', 'rationale': 'ok'},
        ]}))
        plan = ai_plan(client, scan_context(_har([_get('https://x/s?q=1')])))
        assert plan.engines() == ['web']                        # seule l'action valide survit

    def test_all_invalid_returns_none(self):
        client = _Client(json.dumps({'steps': [{'engine': 'nope'}]}))
        assert ai_plan(client, scan_context(_har([_get('https://x/a')]))) is None

    def test_garbage_returns_none(self):
        assert ai_plan(_Client('not json'), scan_context(_har([]))) is None


class TestNextPlan:
    def test_falls_back_to_deterministic_without_client(self):
        plan = next_plan(_har([_get('https://x/s?q=1')]))
        assert plan.source == 'deterministic' and plan.steps

    def test_uses_ai_when_valid(self):
        client = _Client(json.dumps({'steps': [{'engine': 'graphql', 'priority': 1}]}))
        plan = next_plan(_har([_get('https://x/graphql')]), client=client)
        assert plan.source == 'llm'

    def test_never_empty(self):
        assert next_plan(_har([])).steps        # au moins investigate
