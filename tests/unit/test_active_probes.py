"""Tests des sondes actives API4 / API7 / API2."""
from modules.active_probes import probe_rate_limit, probe_ssrf, probe_auth, _decode_jwt
import base64, json


def _jwt(header, payload):
    def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip('=')
    return f"{b64(header)}.{b64(payload)}.sig"


class TestRateLimit:
    def test_no_throttle_flags(self):
        f = probe_rate_limit(lambda u, m: {'status': 200}, 'https://x/a', burst=10)
        assert f and f.category == 'API4'

    def test_throttle_no_finding(self):
        seq = iter([200]*5 + [429]*5)
        assert probe_rate_limit(lambda u, m: {'status': next(seq)}, 'https://x/a', burst=10) is None


class TestSSRF:
    def test_marker_hit(self):
        def srv(url, method):
            return {'status': 200, 'body': 'ami-id: ami-123'} if '169.254' in url else {'status': 200, 'body': 'ok'}
        fs = probe_ssrf(srv, [{'url': 'https://x/fetch?url=http://a', 'method': 'GET'}])
        assert fs and fs[0].category == 'API7' and fs[0].severity == 'Critical'

    def test_no_urlish_param_no_probe(self):
        fs = probe_ssrf(lambda u, m: {'status': 200, 'body': 'x'},
                        [{'url': 'https://x/a?name=bob', 'method': 'GET'}])
        assert fs == []


class TestAuth:
    def test_token_in_url(self):
        har = {"log": {"entries": [{"request": {"url": "https://x/a?access_token=abc", "headers": []}}]}}
        fs = probe_auth(har)
        assert any('Credential in URL' in f.title for f in fs)

    def test_jwt_alg_none(self):
        tok = _jwt({'alg': 'none'}, {'sub': '1', 'exp': 9999999999})
        har = {"log": {"entries": [{"request": {"url": "https://x/a",
               "headers": [{"name": "Authorization", "value": f"Bearer {tok}"}]}}]}}
        assert any('alg=none' in f.title for f in probe_auth(har))

    def test_jwt_no_exp(self):
        tok = _jwt({'alg': 'HS256'}, {'sub': '1'})
        har = {"log": {"entries": [{"request": {"url": "https://x/a",
               "headers": [{"name": "Authorization", "value": f"Bearer {tok}"}]}}]}}
        assert any('without expiration' in f.title for f in probe_auth(har))
