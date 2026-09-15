"""Phase 2 — la boucle --auto planifie, lance un moteur, replanifie, et respecte
le périmètre (skip des moteurs multi-session)."""
import cli


def _har():
    return {'log': {'entries': [
        {'request': {'method': 'GET', 'url': 'http://x/s?q=1&url=http://a',
                     'headers': [{'name': 'Authorization', 'value': 'Bearer t'}]}},
        {'request': {'method': 'POST', 'url': 'http://x/articles',
                     'headers': [{'name': 'Authorization', 'value': 'Bearer t'}],
                     'postData': {'text': '{"title":"t"}'}}},
    ]}}


class _Args:
    ai = False
    auto_budget = None
    target = 'http://x'


class _AdaptiveResult:
    def summary(self):
        return {'idor_vulnerable': 0, 'mass_assignment_vulnerable': 1}


def test_auto_runs_planned_engines_and_skips_out_of_scope(monkeypatch):
    calls = []

    def rec(name, ret=None):
        def _fn(har, config, args, zap_client):
            calls.append(name)
            return ret or [{'name': f'{name}-finding', 'source': name}]
        return _fn

    monkeypatch.setattr(cli, '_run_investigations', rec('investigate'))
    monkeypatch.setattr(cli, '_run_active_probes', rec('probes'))
    monkeypatch.setattr(cli, '_run_web_probes', rec('web'))
    monkeypatch.setattr(cli, '_run_injection_probes', rec('injection'))
    monkeypatch.setattr(cli, '_run_business_flow', rec('business_flow'))

    def _adaptive(har, config, args, zap_client=None):
        calls.append('adaptive')
        return _AdaptiveResult()
    monkeypatch.setattr(cli, '_run_adaptive_campaign', _adaptive)

    all_findings, report = [], {}
    adaptive_result = cli._run_auto(_har(), {}, _Args(), None, all_findings, report)

    # tous les moteurs mono-session planifiés ont tourné, exactement une fois
    assert set(calls) == {'investigate', 'probes', 'web', 'injection',
                          'business_flow', 'adaptive'}
    assert len(calls) == len(set(calls))              # aucun double-run
    assert calls[0] == 'investigate'                  # priorité au socle
    # matrix_bola planifié (réactif) mais hors périmètre -> jamais exécuté
    assert 'matrix_bola' not in calls
    assert 'matrix_bola' in report['auto']['engines_run']   # marqué comme traité (ignoré)
    assert adaptive_result is not None
    assert any('investigate-finding' == f.get('name') for f in all_findings)


def test_auto_budget_caps_iterations(monkeypatch):
    calls = []
    for n, fn in (('investigate', '_run_investigations'), ('probes', '_run_active_probes'),
                  ('web', '_run_web_probes'), ('injection', '_run_injection_probes'),
                  ('business_flow', '_run_business_flow')):
        monkeypatch.setattr(cli, fn,
                            (lambda _n: (lambda h, c, a, z: (calls.append(_n) or [])))(n))
    monkeypatch.setattr(cli, '_run_adaptive_campaign',
                        lambda h, c, a, z=None: (calls.append('adaptive') or _AdaptiveResult()))

    class _A(_Args):
        auto_budget = 2
    cli._run_auto(_har(), {}, _A(), None, [], {})
    assert len(calls) <= 2                             # budget respecté
