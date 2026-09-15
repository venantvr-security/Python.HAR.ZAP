"""Câblage reauth dans les exécuteurs de diagnose : _DiagTransport doit établir
une session vivante (reauth) OU injecter l'auth statique du HAR."""
import cli


class _Resp:
    def __init__(self, status, text='', headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self.content = text.encode()


class _FakeZap:
    """Mime une app : POST /auth/login rend un jeton JSON ; les endpoints
    protégés exigent `Authorization: Bearer <tok>`."""
    def __init__(self):
        self.logins = 0

    def request(self, method, url, headers=None, json_data=None, follow_redirects=False):
        headers = headers or {}
        if url.endswith('/auth/login') and method == 'POST':
            self.logins += 1
            return _Resp(200, '{"token":"tok123"}', {'Content-Type': 'application/json'})
        if headers.get('Authorization') == 'Bearer tok123':
            return _Resp(200, 'ok')
        if headers.get('Authorization') == 'Bearer static':
            return _Resp(200, 'ok-static')
        return _Resp(401, 'no auth')


def _reauth_cfg(authorized=True):
    return {'llm': {'authorized': authorized},
            'reauth': {'base_url': 'http://app',
                       'login': {'url': '/auth/login',
                                 'credentials': {'username': 'a', 'password': 'b'}},
                       'session': {'strategy': 'json', 'path': 'token',
                                   'header': 'Authorization', 'scheme': 'Bearer '},
                       'rotation': {'strategy': 'none'},
                       'expiry': {'strategies': [{'strategy': 'redirect',
                                                  'login_path': '/auth/login'}]}}}


class TestReauthWiring:
    def test_live_session_established_and_injected(self):
        zap = _FakeZap()
        T = cli._DiagTransport(zap, _reauth_cfg(authorized=True), {'log': {'entries': []}})
        assert T.active
        assert zap.logins == 1                       # login initial une fois
        r = T.send('GET', 'http://app/me', None, None)
        assert r['status'] == 200                    # session injectée -> autorisé
        assert 'Bearer tok123' in T.auth_headers().get('Authorization', '')

    def test_reauth_config_but_not_attested_stays_static(self):
        zap = _FakeZap()
        T = cli._DiagTransport(zap, _reauth_cfg(authorized=False), {'log': {'entries': []}})
        assert not T.active                          # pas d'attestation -> pas de login
        assert zap.logins == 0

    def test_base_is_tokenless_for_forge_baseline(self):
        zap = _FakeZap()
        T = cli._DiagTransport(zap, _reauth_cfg(authorized=True), {'log': {'entries': []}})
        # base() ne doit PAS injecter la session -> baseline non authentifiée (401)
        assert T.base('GET', 'http://app/me', None, None)['status'] == 401


class TestStaticAuthFallback:
    def _har(self):
        return {'log': {'entries': [{'request': {'method': 'GET', 'url': 'http://app/me',
                'headers': [{'name': 'Authorization', 'value': 'Bearer static'}]}}]}}

    def test_static_auth_injected_without_reauth(self):
        zap = _FakeZap()
        T = cli._DiagTransport(zap, {}, self._har())     # pas de bloc reauth
        assert not T.active
        r = T.send('GET', 'http://app/me', None, None)
        assert r['status'] == 200 and r['body'] == 'ok-static'

    def test_base_exposes_location_and_content_type(self):
        class _ZL:
            def request(self, method, url, headers=None, json_data=None, follow_redirects=False):
                return _Resp(302, '', {'Location': 'http://evil/', 'Content-Type': 'text/html'})
        T = cli._DiagTransport(_ZL(), {}, {'log': {'entries': []}})
        r = T.base('GET', 'http://app/go', None, None)
        assert r['location'] == 'http://evil/' and 'html' in r['content_type']
