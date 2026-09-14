"""Tests des sondes « angles morts » (path traversal, SSTI, XSS, open redirect,
reset prédictible, CSV)."""
import hashlib
import json

from modules.web_probes import (
    injectable_targets, probe_path_traversal, probe_ssti, probe_reflected_xss,
    probe_stored_xss, probe_open_redirect, probe_predictable_reset,
    probe_csv_injection, run_web_probes)


def _html(body, status=200):
    return {'status': status, 'body': body, 'content_type': 'text/html'}


def _json(body, status=200):
    return {'status': status, 'body': body, 'content_type': 'application/json'}


class TestTargets:
    def test_query_and_body(self):
        har = {"log": {"entries": [
            {"request": {"method": "GET", "url": "https://x/media/raw?path=a"}},
            {"request": {"method": "POST", "url": "https://x/preview",
                         "postData": {"text": json.dumps({"template": "t"})}}},
        ]}}
        ts = injectable_targets(har)
        assert len(ts) == 2


class TestPathTraversal:
    def test_marker_hit(self):
        def srv(url, method, body=None):
            leak = 'passwd' in url or (body and 'passwd' in json.dumps(body))
            return {'status': 200, 'body': 'root:x:0:0:root:/root', 'content_type': 'text/plain'} if leak \
                else {'status': 200, 'body': 'ok'}
        fs = probe_path_traversal(srv, [{'url': 'https://x/media/raw?path=logo', 'method': 'GET'}])
        assert fs and fs[0].category == 'LFI' and fs[0].severity == 'Critical'

    def test_non_file_param_skipped(self):
        srv = lambda u, m, b=None: {'status': 200, 'body': 'root:x:0:0'}
        # clé 'name' est file-ish -> testé ; ici on prend une clé non file-ish
        fs = probe_path_traversal(srv, [{'url': 'https://x/a?color=red', 'method': 'GET'}])
        assert fs == []

    def test_finding_carries_winning_payload(self):
        """La charge gagnante est structurée (flat['payload']) pour l'enrichissement ZAP."""
        def srv(url, method, body=None):
            return {'status': 200, 'body': 'root:x:0:0:root', 'content_type': 'text/plain'}
        f = probe_path_traversal(srv, [{'url': 'https://x/media/raw?path=a', 'method': 'GET'}])[0]
        assert f.payload and f.flat()['payload'] == f.payload


class TestSSTI:
    def test_arithmetic_eval(self):
        def srv(url, method, body=None):
            val = (body or {}).get('tpl', '') if body else ''
            # moteur qui évalue 7*7
            return _json(json.dumps({'r': val.replace('{{7*7}}', '49')}))
        fs = probe_ssti(srv, [{'url': 'https://x/r', 'method': 'POST', 'body': {'tpl': 'x'}}])
        assert fs and fs[0].category == 'SSTI'

    def test_context_leak(self):
        def srv(url, method, body=None):
            v = (body or {}).get('template', '')
            out = 'secret_key=abc123' if v == '{config}' else v
            return _json(json.dumps({'rendered': out}))
        fs = probe_ssti(srv, [{'url': 'https://x/preview', 'method': 'POST', 'body': {'template': 'x'}}])
        assert fs and 'leaked' in fs[0].title


class TestReflectedXSS:
    def test_html_reflection_flagged(self):
        def srv(url, method, body=None):
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(url).query).get('q', [''])[0]
            return _html(f"<h1>{q}</h1>")
        fs = probe_reflected_xss(srv, [{'url': 'https://x/search?q=hi', 'method': 'GET'}])
        assert fs and fs[0].category == 'XSS'

    def test_json_reflection_not_flagged(self):
        """Réflexion dans du JSON = pas une XSS (contexte non HTML)."""
        def srv(url, method, body=None):
            from urllib.parse import urlparse, parse_qs
            q = parse_qs(urlparse(url).query).get('q', [''])[0]
            return _json(json.dumps({'echo': q}))
        assert probe_reflected_xss(srv, [{'url': 'https://x/api?q=hi', 'method': 'GET'}]) == []


class TestStoredXSS:
    def test_persisted_then_rendered(self):
        store = {}

        def srv(url, method, body=None):
            if method == 'POST':
                store['c'] = (body or {}).get('body', '')
                return _json('{"ok":1}', 201)
            return _html(f"<article>{store.get('c','')}</article>")
        har = {"log": {"entries": [
            {"request": {"method": "POST", "url": "https://x/articles/1/comments",
                         "postData": {"text": json.dumps({"body": "hi"})}}},
            {"request": {"method": "GET", "url": "https://x/articles/1/render"}},
        ]}}
        fs = probe_stored_xss(srv, har)
        assert fs and fs[0].category == 'XSS' and 'Stored' in fs[0].title


class TestOpenRedirect:
    def test_location_to_attacker(self):
        def srv(url, method, body=None):
            return {'status': 302, 'body': '', 'location': 'https://harzap-oob.example/',
                    'content_type': ''}
        fs = probe_open_redirect(srv, [{'url': 'https://x/go?to=/', 'method': 'GET'}])
        assert fs and fs[0].category == 'OPEN_REDIRECT'

    def test_same_site_not_flagged(self):
        def srv(url, method, body=None):
            return {'status': 302, 'body': '', 'location': 'https://x/home', 'content_type': ''}
        assert probe_open_redirect(srv, [{'url': 'https://x/go?to=/', 'method': 'GET'}]) == []


class TestPredictableReset:
    def test_md5_username_token(self):
        token = hashlib.md5(b'admin').hexdigest()[:8]

        def srv(url, method, body=None):
            return _json(json.dumps({'reset_token': token}))
        har = {"log": {"entries": [
            {"request": {"method": "POST", "url": "https://x/auth/reset-request",
                         "postData": {"text": json.dumps({"username": "admin"})}}},
        ]}}
        fs = probe_predictable_reset(srv, har)
        assert fs and fs[0].category == 'WEAK_RESET'

    def test_random_token_not_flagged(self):
        def srv(url, method, body=None):
            return _json(json.dumps({'reset_token': 'Zx9-unrelated-random-Qa'}))
        har = {"log": {"entries": [
            {"request": {"method": "POST", "url": "https://x/forgot",
                         "postData": {"text": json.dumps({"email": "a@b.c"})}}},
        ]}}
        assert probe_predictable_reset(srv, har) == []


class TestCSVInjection:
    def test_formula_cell(self):
        har = {"log": {"entries": [
            {"request": {"method": "GET", "url": "https://x/export.csv"},
             "response": {"headers": [{"name": "Content-Type", "value": "text/csv"}],
                          "content": {"text": "id,name\n1,=HYPERLINK(evil)"}}},
        ]}}
        fs = probe_csv_injection(har)
        assert fs and fs[0].category == 'CSV_INJECTION'

    def test_clean_csv(self):
        har = {"log": {"entries": [
            {"request": {"method": "GET", "url": "https://x/export.csv"},
             "response": {"headers": [{"name": "Content-Type", "value": "text/csv"}],
                          "content": {"text": "id,name\n1,alice"}}},
        ]}}
        assert probe_csv_injection(har) == []


class _Adjud:
    """Adjudicateur IA simulé : disponible et qui valide tout near-miss."""
    available = True
    def classify_owasp(self, alert, categories):
        return {'reason': 'LLM says plausible'}


class _AdjudNo:
    available = True
    def classify_owasp(self, alert, categories):
        return None


class TestSuspectedTier:
    def test_lfi_near_miss_needs_adjudicator(self):
        # réponse « fs-like » (pas le marqueur strict root:x:...:0:0)
        def srv(url, method, body=None):
            return {'status': 200, 'body': 'daemon:x:1:1:daemon', 'content_type': 'text/plain'}
        tgt = [{'url': 'https://x/media/raw?path=a', 'method': 'GET'}]
        # sans IA : rien (pas de FP)
        assert probe_path_traversal(srv, tgt) == []
        # avec IA : un SUSPECTED
        fs = probe_path_traversal(srv, tgt, adjudicator=_Adjud())
        assert fs and fs[0].source == 'llm' and 'suspected' in fs[0].title.lower()
        assert fs[0].flat()['status'] == 'suspected'

    def test_adjudicator_can_reject(self):
        def srv(url, method, body=None):
            return {'status': 200, 'body': 'daemon:x:1:1', 'content_type': 'text/plain'}
        tgt = [{'url': 'https://x/media/raw?path=a', 'method': 'GET'}]
        assert probe_path_traversal(srv, tgt, adjudicator=_AdjudNo()) == []

    def test_ssti_near_miss(self):
        def srv(url, method, body=None):
            return _json('{"rendered":"jinja2.exceptions.TemplateSyntaxError"}')
        tgt = [{'url': 'https://x/preview', 'method': 'POST', 'body': {'template': 'x'}}]
        assert probe_ssti(srv, tgt) == []
        fs = probe_ssti(srv, tgt, adjudicator=_Adjud())
        assert fs and fs[0].flat()['status'] == 'suspected'

    def test_reset_near_miss_numeric_token(self):
        def srv(url, method, body=None):
            return _json(json.dumps({'reset_token': '100042'}))  # numérique, non-hash
        har = {"log": {"entries": [
            {"request": {"method": "POST", "url": "https://x/forgot",
                         "postData": {"text": json.dumps({"email": "a@b.c"})}}}]}}
        assert probe_predictable_reset(srv, har) == []
        fs = probe_predictable_reset(srv, har, adjudicator=_Adjud())
        assert fs and fs[0].flat()['status'] == 'suspected'


class TestOrchestrator:
    def test_flat_shape(self):
        def srv(url, method, body=None):
            return _html('<h1>root:x:0:0</h1>')
        out = run_web_probes(srv, {"log": {"entries": []}}, targets=[])
        assert isinstance(out, list)
