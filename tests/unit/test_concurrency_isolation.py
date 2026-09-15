"""Concurrence : « 1 HAR-ZAP par user » — prouver l'ISOLATION, et prouver que le
test DÉTECTE bien une interaction (sinon il ne vaut rien)."""
import os
import threading

from modules.run_context import RunContext, isolation_report
from modules.llm.pattern_enricher import PatternEnricher
from modules.auth_dsl import AuthRecipeStore


def _barrier_run(fn, n=2):
    """Lance n workers en parallèle, synchronisés sur une barrière pour maximiser
    l'entrelacement (révèle les courses)."""
    barrier = threading.Barrier(n)
    errors = []

    def wrap(i):
        try:
            barrier.wait()
            fn(i)
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=wrap, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors


class TestIsolatedRuns:
    def test_distinct_contexts_do_not_interact(self, tmp_path):
        """Chaque user a son RunContext -> patterns + DSL séparés, zéro diaphonie."""
        users = {0: ('alice', 'AK-alice'), 1: ('bob', 'AK-bob')}
        ctxs = {i: RunContext.for_run(name, str(tmp_path), index=i)
                for i, (name, _) in users.items()}

        def work(i):
            name, key = users[i]
            enr = PatternEnricher.for_run(domain=name, base_path=ctxs[i].patterns_dir)
            enr.record_payloads('ssrf', [f'http://internal/{name}'])
            enr.flush()
            store = AuthRecipeStore(ctxs[i].auth_dsl_path)
            store.record_slot(name, 'session', {'strategy': 'cookie', 'names': [f'sid_{name}']})

        _barrier_run(work, 2)

        # Les artefacts de bob ne doivent JAMAIS apparaître chez alice, et vice-versa.
        alice_ssrf = os.path.join(ctxs[0].patterns_dir, 'zap_export', 'fuzzers', 'llm_ssrf.txt')
        bob_ssrf = os.path.join(ctxs[1].patterns_dir, 'zap_export', 'fuzzers', 'llm_ssrf.txt')
        assert 'alice' in open(alice_ssrf).read() and 'bob' not in open(alice_ssrf).read()
        assert 'bob' in open(bob_ssrf).read() and 'alice' not in open(bob_ssrf).read()
        assert 'sid_alice' in open(ctxs[0].auth_dsl_path).read()
        assert 'sid_alice' not in open(ctxs[1].auth_dsl_path).read()

    def test_shared_path_DOES_collide(self, tmp_path):
        """Sanity : SANS isolation (même dossier patterns), les deux users se
        marchent dessus -> le test sait détecter une interaction."""
        shared = str(tmp_path / 'shared_patterns')

        def work(i):
            name = 'alice' if i == 0 else 'bob'
            enr = PatternEnricher.for_run(domain='shared', base_path=shared)
            enr.record_payloads('ssrf', [f'http://internal/{name}'])
            enr.flush()

        _barrier_run(work, 2)
        # L'export ZAP est un chemin FIXE (llm_ssrf.txt) : la dernière écriture
        # gagne -> on ne retrouve qu'UN seul des deux users (perte de données).
        exported = os.path.join(shared, 'zap_export', 'fuzzers', 'llm_ssrf.txt')
        content = open(exported).read()
        assert ('alice' in content) ^ ('bob' in content), \
            "collision attendue : un seul user survit sur le chemin partagé"


class TestProcessGlobalEnvLeak:
    def test_env_authorization_is_process_global(self):
        """Vecteur de diaphonie n°2 : os.environ est partagé entre threads. Un
        thread qui atteste l'autorisation la rend visible à l'autre."""
        from modules.llm.client import ai_authorized
        seen = {}
        os.environ.pop('HARZAP_AI_AUTHORIZED', None)

        def user_a():
            os.environ['HARZAP_AI_AUTHORIZED'] = '1'      # A atteste

        def user_b():
            seen['b'] = ai_authorized({})                 # B lit (sans rien attester)

        a = threading.Thread(target=user_a)
        a.start(); a.join()
        b = threading.Thread(target=user_b)
        b.start(); b.join()
        try:
            assert seen['b'] is True                       # FUITE démontrée
        finally:
            os.environ.pop('HARZAP_AI_AUTHORIZED', None)

    def test_per_config_authorization_does_not_leak(self):
        """Remède : passer l'autorisation par CONFIG (RunContext.config_overlay)
        n'affecte QUE ce run, même sans toucher l'env."""
        from modules.llm.client import ai_authorized
        os.environ.pop('HARZAP_AI_AUTHORIZED', None)
        ctx_auth = RunContext('alice', '/tmp/x', zap_port=8090, authorized=True)
        ctx_noauth = RunContext('bob', '/tmp/y', zap_port=8091, authorized=False)
        assert ai_authorized(ctx_auth.config_overlay()) is True
        assert ai_authorized(ctx_noauth.config_overlay()) is False   # pas de contamination


class TestContextPaths:
    def test_distinct_ports_and_paths(self, tmp_path):
        a = RunContext.for_run('alice', str(tmp_path), index=0)
        b = RunContext.for_run('bob', str(tmp_path), index=1)
        assert a.zap_port != b.zap_port
        assert a.patterns_dir != b.patterns_dir
        assert a.auth_dsl_path != b.auth_dsl_path

    def test_subprocess_env_isolates_auth(self):
        a = RunContext('alice', '/tmp/a', zap_port=8090, authorized=True)
        b = RunContext('bob', '/tmp/b', zap_port=8091, authorized=False)
        assert a.env_for_subprocess({})['HARZAP_AI_AUTHORIZED'] == '1'
        assert 'HARZAP_AI_AUTHORIZED' not in b.env_for_subprocess({})

    def test_isolation_report_lists_vectors(self):
        rep = isolation_report()
        assert {'zap_session', 'process_env', 'shared_files'} <= set(rep)
