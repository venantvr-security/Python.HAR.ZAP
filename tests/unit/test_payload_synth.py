"""Phase 3b — synthèse de payloads : empreinte, validation non-destructive,
persistance (propose une fois), et injection des extras dans la sonde SQLi."""
import json

from modules.llm.payload_synth import (
    fingerprint, synthesize, SynthStore, _sanitize)
from modules.injection_probes import probe_sqli


def _resp_har(headers):
    return {'log': {'entries': [{'request': {'method': 'GET', 'url': 'https://app.x/a'},
            'response': {'headers': [{'name': k, 'value': v} for k, v in headers.items()]}}]}}


class _Client:
    def __init__(self, content):
        self._c = content
        self.calls = 0
    def complete(self, user, system=None):
        self.calls += 1
        class R: content = None
        R.content = self._c
        return R()


class TestFingerprint:
    def test_node_express_cookie(self):
        fp = fingerprint(_resp_har({'Set-Cookie': 'connect.sid=abc; Path=/',
                                    'X-Powered-By': 'Express'}))
        assert 'node' in fp['stack'] and 'mongo' in fp['db_guess']

    def test_php(self):
        fp = fingerprint(_resp_har({'Set-Cookie': 'PHPSESSID=x', 'Server': 'Apache'}))
        assert fp['stack'] == 'php' and 'mysql' in fp['db_guess']


class TestSanitize:
    def test_drops_destructive_and_caps(self):
        payloads = _sanitize(["' OR SLEEP(5)-- -", "'; DROP TABLE users-- -",
                              "1' AND '1'='1", "rm -rf /", "x" * 500])
        assert "' OR SLEEP(5)-- -" in payloads
        assert all('drop table' not in p.lower() and 'rm -rf' not in p for p in payloads)
        assert all(len(p) <= 200 for p in payloads)

    def test_dedup(self):
        assert _sanitize(["a", "a", "b"]) == ["a", "b"]


class TestSynthesizeCache:
    def test_ai_proposes_then_cache_reuses(self, tmp_path):
        client = _Client(json.dumps(["' OR 1=1-- -", "'; DROP TABLE t-- -"]))
        store = SynthStore(str(tmp_path))
        fp = {'db_guess': 'mysql'}
        p1 = synthesize('sqli', fp, client, store, domain='app.x')
        assert "' OR 1=1-- -" in p1 and all('drop' not in x.lower() for x in p1)  # destructif filtré
        assert client.calls == 1
        # 2e appel -> cache disque, pas de nouvel appel modèle
        store2 = SynthStore(str(tmp_path))
        p2 = synthesize('sqli', fp, client, store2, domain='app.x')
        assert p2 == p1 and client.calls == 1

    def test_no_client_returns_empty(self):
        assert synthesize('sqli', {}, client=None) == []


class TestExtrasReachProbe:
    def test_synthesized_payload_triggers_error_finding(self):
        magic = "'INJECT_MAGIC"

        def srv(url, method, body=None):
            from urllib.parse import unquote
            if 'INJECT_MAGIC' in unquote(url):
                return {'status': 500, 'body': 'You have an error in your SQL syntax'}
            return {'status': 200, 'body': 'ok'}
        # sans l'extra : rien ; avec l'extra synthétisé : confirmé
        assert probe_sqli(srv, [{'url': 'https://x/i?id=1', 'method': 'GET'}]) == []
        fs = probe_sqli(srv, [{'url': 'https://x/i?id=1', 'method': 'GET'}], extra=[magic])
        assert fs and fs[0].category == 'SQLI' and fs[0].payload == magic


class TestDestructiveHardening:
    def test_obfuscated_and_dangerous_blocked(self):
        evil = ["'; DROP/**/TABLE users-- -", "' UNION SELECT 1 INTO OUTFILE '/x/s.php'-- -",
                "' OR BENCHMARK(9999999,MD5(1))-- -", "' OR SLEEP(9999)-- -",
                "'; COPY t TO PROGRAM 'sh'-- -", "' AND LOAD_FILE('/etc/shadow')-- -",
                "'; DELETE  FROM t-- -", "'; exec('x')"]
        assert _sanitize(evil) == []                      # tout bloqué, y compris obfusqué

    def test_legit_detection_payloads_kept(self):
        legit = ["' OR '1'='1", "' OR SLEEP(5)-- -", "' UNION SELECT NULL-- -",
                 "1' AND '1'='1", "' OR pg_sleep(3)-- -"]
        assert _sanitize(legit) == legit                  # détection non altérée
