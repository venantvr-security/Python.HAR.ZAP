"""Tests des sondes d'injection SQL/NoSQL (A03) : marqueurs déterministes,
différentiel time-based, booléen SUSPECTED, et NON-régression (zéro FP)."""
import json
import time
from urllib.parse import unquote

from modules.injection_probes import (
    probe_sqli, probe_nosqli, run_injection_probes)


def _q(url, method='GET'):
    return {'url': url, 'method': method}


def _b(url, body, method='POST'):
    return {'url': url, 'method': method, 'body': body}


class TestSqliErrorBased:
    def test_db_error_signature_confirms(self):
        def srv(url, method, body=None):
            if "'" in unquote(url):
                return {'status': 500, 'body': "You have an error in your SQL syntax near ''"}
            return {'status': 200, 'body': 'ok'}
        fs = probe_sqli(srv, [_q('https://x/item?id=1')])
        assert fs and fs[0].category == 'SQLI' and fs[0].flat()['status'] == 'confirmed'
        assert 'error-based' in fs[0].title

    def test_clean_endpoint_no_finding(self):
        srv = lambda u, m, b=None: {'status': 200, 'body': 'normal page content here'}
        assert probe_sqli(srv, [_q('https://x/item?id=1')]) == []


class TestSqliTimeBased:
    def test_sleep_delay_confirms(self):
        def srv(url, method, body=None):
            u = unquote(url)
            if 'SLEEP(5)' in u or 'pg_sleep(5)' in u or "0:0:5" in u:
                time.sleep(0.2)                       # simulate delay (échelle réduite)
                return {'status': 200, 'body': 'ok'}
            return {'status': 200, 'body': 'ok'}       # contrôle rapide
        # seuils abaissés pour le test
        import modules.injection_probes as ip
        old_t, old_c = ip._TIME_THRESHOLD, ip._TIME_CTRL_MAX
        ip._TIME_THRESHOLD, ip._TIME_CTRL_MAX = 0.1, 0.1
        try:
            fs = probe_sqli(srv, [_q('https://x/item?id=1')])
        finally:
            ip._TIME_THRESHOLD, ip._TIME_CTRL_MAX = old_t, old_c
        assert fs and 'time-based' in fs[0].title and fs[0].flat()['status'] == 'confirmed'

    def test_uniformly_slow_target_not_flagged(self):
        def srv(url, method, body=None):
            time.sleep(0.2)                            # lent pour TOUT (contrôle inclus)
            return {'status': 200, 'body': 'ok'}
        import modules.injection_probes as ip
        old_c = ip._TIME_CTRL_MAX
        ip._TIME_CTRL_MAX = 0.1                        # contrôle jugé « lent » -> ignoré
        try:
            fs = probe_sqli(srv, [_q('https://x/item?id=1')])
        finally:
            ip._TIME_CTRL_MAX = old_c
        assert all('time-based' not in f.title for f in fs)


class TestSqliBoolean:
    def test_true_false_divergence_is_suspected(self):
        def srv(url, method, body=None):
            from urllib.parse import urlparse, parse_qs
            v = parse_qs(urlparse(url).query).get('id', [''])[0]
            if "OR '1'='1" in v or 'OR 1=1' in v:
                return {'status': 200, 'body': 'ROWS: alice bob carol dave'}
            if "AND '1'='2" in v or 'AND 1=2' in v:
                return {'status': 200, 'body': 'ROWS:'}      # vide
            return {'status': 200, 'body': 'ROWS: alice bob carol dave'}  # baseline
        fs = probe_sqli(srv, [_q('https://x/users?id=1')])
        assert fs and 'boolean-based' in fs[0].title
        assert fs[0].flat()['status'] == 'suspected'   # sans IA -> SUSPECTED


class TestNoSqli:
    def test_operator_injection_changes_result(self):
        def srv(url, method, body=None):
            # $ne:null élargit l'accès -> réponse différente du baseline bénin
            if body and '$ne' in json.dumps(body):
                return {'status': 200, 'body': 'ALL USERS DUMP ' * 20}
            return {'status': 200, 'body': 'no match'}
        fs = probe_nosqli(srv, [_b('https://x/login', {'username': 'a', 'password': 'b'})])
        assert fs and fs[0].category == 'NOSQLI' and 'operator' in fs[0].title

    def test_mongo_error_signature(self):
        def srv(url, method, body=None):
            return {'status': 500, 'body': 'MongoError: unknown operator: $foo'}
        fs = probe_nosqli(srv, [_b('https://x/find', {'q': 'x'})])
        assert fs and 'error-based' in fs[0].title and fs[0].flat()['status'] == 'confirmed'

    def test_clean_nosql_no_finding(self):
        srv = lambda u, m, b=None: {'status': 200, 'body': 'stable response'}
        assert probe_nosqli(srv, [_b('https://x/find', {'q': 'x'})]) == []


class TestOrchestrator:
    def test_flat_and_owasp(self):
        def srv(url, method, body=None):
            return {'status': 500, 'body': 'ORA-00933: SQL command not properly ended'} if "'" in unquote(url) \
                else {'status': 200, 'body': 'ok'}
        out = run_injection_probes(srv, {'log': {'entries': []}},
                                   targets=[_q('https://x/i?id=1')])
        assert out and out[0]['owasp'] == 'API8:2023' and out[0]['name']
