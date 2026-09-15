"""Tests du planificateur adaptatif (articulation par IA — prototype)."""
import json

from modules.llm.orchestrator import (
    scan_context, deterministic_plan, ai_plan, next_plan, ENGINES, Plan,
    interpret_goal, filter_har, ScopeConstraints, Step, DESTRUCTIVE_ENGINES)


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


class TestGoalScoping:
    def _full_plan(self):
        return Plan(steps=[Step(e, '', 3) for e in
                           ('investigate', 'probes', 'web', 'injection',
                            'business_flow', 'adaptive')])

    def test_deterministic_authz_only(self):
        c = interpret_goal("authz only")
        assert c.source == 'deterministic'
        engines = c.apply(self._full_plan()).engines()
        assert 'injection' not in engines and 'web' not in engines
        assert 'investigate' in engines and 'business_flow' in engines

    def test_non_destructive_drops_writes(self):
        c = interpret_goal("full scan but non destructive")
        assert c.non_destructive
        engines = c.apply(self._full_plan()).engines()
        assert not (DESTRUCTIVE_ENGINES & set(engines))     # business_flow/adaptive exclus
        assert 'injection' in engines                       # lecture -> gardé

    def test_authz_and_non_destructive_combo(self):
        c = interpret_goal("authz only, read-only")
        engines = c.apply(self._full_plan()).engines()
        assert engines and 'business_flow' not in engines and 'adaptive' not in engines
        assert 'investigate' in engines

    def test_injection_goal_selects_injection(self):
        c = interpret_goal("focus on sql injection")
        assert c.apply(self._full_plan()).engines() == ['injection']

    def test_path_include_extracted(self):
        c = interpret_goal("only /billing and /invoices")
        assert '/billing' in c.path_include and '/invoices' in c.path_include

    def test_no_goal_returns_none(self):
        assert interpret_goal(None) is None
        assert interpret_goal("") is None

    def test_ai_goal_validated_against_whitelist(self):
        client = _Client(json.dumps({'allow_engines': ['web', 'rm_rf'],
                                     'non_destructive': True, 'path_include': ['/api']}))
        c = interpret_goal("scan the web stuff safely on /api", client=client)
        assert c.source == 'llm'
        assert c.allow_engines == frozenset({'web'})        # 'rm_rf' écarté
        assert c.non_destructive and c.path_include == ['/api']

    def test_ai_garbage_falls_back_to_deterministic(self):
        c = interpret_goal("authz only", client=_Client('not json'))
        assert c.source == 'deterministic' and 'investigate' in (c.allow_engines or set())


class TestFilterHar:
    def test_include_restricts_endpoints(self):
        har = _har([_get('https://x/billing/pay'), _get('https://x/blog/post')])
        out = filter_har(har, include=['/billing'])
        paths = [e['request']['url'] for e in out['log']['entries']]
        assert paths == ['https://x/billing/pay']

    def test_exclude_removes_endpoints(self):
        har = _har([_get('https://x/billing/pay'), _get('https://x/admin/x')])
        out = filter_har(har, exclude=['/admin'])
        assert len(out['log']['entries']) == 1

    def test_no_filter_returns_same(self):
        har = _har([_get('https://x/a')])
        assert filter_har(har) is har
