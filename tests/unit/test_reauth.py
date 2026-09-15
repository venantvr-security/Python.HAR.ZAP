"""Tests de la ré-authentification enfichable (nonce, rotation, expiration, IA)."""
import time

from modules.reauth import (
    ReAuthenticator, SessionStore, RegexNonce, JsonNonce, CookieNonce,
    CookieSession, JsonSession, RotatingCookie, RotatingHeader,
    RedirectExpiry, CookieTtlExpiry, AiExpiry, CompositeExpiry, LoginRecipe,
    AiNonce, AiSession, _resp_cookies, _cookie_ttl, _jwt_exp)


# --- Serveur factice : nonce à usage unique, cookie de session ROTATIF -------
class FakeApp:
    def __init__(self, rotate=True, ttl=None):
        self.valid_nonce = None
        self.session = None
        self.counter = 0
        self.rotate = rotate
        self.ttl = ttl
        self.login_calls = 0

    def send(self, method, url, headers=None, body=None):
        headers = headers or {}
        if url.endswith('/login') and method == 'GET':
            self.valid_nonce = f'nonce{self.counter}'
            self.counter += 1
            return {'status': 200,
                    'body': f'<input name="csrf" value="{self.valid_nonce}">'}
        if url.endswith('/login') and method == 'POST':
            self.login_calls += 1
            if (body or {}).get('csrf') != self.valid_nonce:
                return {'status': 403, 'body': 'bad nonce'}
            self.valid_nonce = None                      # usage unique
            self.session = f'sess{self.counter}'
            self.counter += 1
            sc = f'sid={self.session}; Path=/'
            if self.ttl is not None:
                sc += f'; Max-Age={self.ttl}'
            return {'status': 200, 'body': '{"ok":1}', 'set_cookie': [sc]}
        # endpoint protégé : exige le cookie de session courant
        cookie = headers.get('Cookie', '')
        if f'sid={self.session}' not in cookie or self.session is None:
            return {'status': 302, 'location': '/login', 'body': ''}
        resp = {'status': 200, 'body': 'data'}
        if self.rotate:                                  # jeton renouvelé à chaque réponse
            self.session = f'sess{self.counter}'
            self.counter += 1
            resp['set_cookie'] = [f'sid={self.session}; Path=/']
        return resp


def _recipe():
    return LoginRecipe(
        login_url='/login', method='POST',
        credentials={'user': 'alice', 'password': 'x'}, nonce_field='csrf',
        nonce=RegexNonce('/login', r'name="csrf" value="([^"]+)"'),
        session=CookieSession(names=['sid']))


class TestLoginNonce:
    def test_login_fetches_fresh_nonce(self):
        app = FakeApp(rotate=False)
        ra = ReAuthenticator(_recipe(), RotatingCookie(), RedirectExpiry())
        assert ra.login(app.send) is True
        assert ra.store.cookies.get('sid') is not None

    def test_stale_nonce_would_fail(self):
        app = FakeApp(rotate=False)
        # simuler un rejeu : récupérer un nonce puis en générer un autre
        app.send('GET', '/login'); app.send('GET', '/login')
        ra = ReAuthenticator(_recipe(), RotatingCookie(), RedirectExpiry())
        # login refait un GET -> nonce frais -> OK malgré le rejeu ci-dessus
        assert ra.login(app.send) is True


class TestRotation:
    def test_session_tracked_across_rotation(self):
        app = FakeApp(rotate=True)
        ra = ReAuthenticator(_recipe(), RotatingCookie(), RedirectExpiry())
        send = ra.wrap(app.send)
        # plusieurs requêtes : chaque réponse tourne le cookie, jamais de 302
        for _ in range(5):
            r = send('GET', 'http://app/data')
            assert r['status'] == 200
        assert app.login_calls == 1                      # un seul login malgré la rotation


class TestReactiveExpiry:
    def test_reauth_on_redirect_to_login(self):
        app = FakeApp(rotate=False)
        ra = ReAuthenticator(_recipe(), RotatingCookie(), RedirectExpiry())
        send = ra.wrap(app.send)
        assert send('GET', 'http://app/data')['status'] == 200
        app.session = None                               # la session « meurt »
        r = send('GET', 'http://app/data')               # -> 302 -> re-login -> 200
        assert r['status'] == 200
        assert app.login_calls == 2


class TestProactiveExpiry:
    def test_cookie_ttl_triggers_early_reauth(self):
        app = FakeApp(rotate=False, ttl=1)               # cookie qui expire vite
        ra = ReAuthenticator(_recipe(), RotatingCookie(),
                             CookieTtlExpiry(skew=0.0))
        send = ra.wrap(app.send)
        send('GET', 'http://app/data')
        assert app.login_calls == 1
        ra.store.expires_at = time.time() - 1            # forcer l'expiration
        send('GET', 'http://app/data')                   # proactif -> re-login
        assert app.login_calls == 2


class TestHelpers:
    def test_resp_cookies_and_ttl(self):
        resp = {'set_cookie': ['sid=abc; Path=/; Max-Age=100']}
        assert _resp_cookies(resp)['sid'] == 'abc'
        assert _cookie_ttl(resp) > time.time() + 90

    def test_jwt_exp(self):
        import base64, json
        p = base64.urlsafe_b64encode(json.dumps({'exp': 9999999999}).encode()).rstrip(b'=').decode()
        assert _jwt_exp(f'h.{p}.s') == 9999999999.0

    def test_json_session_reads_jwt_exp(self):
        import base64, json
        p = base64.urlsafe_b64encode(json.dumps({'exp': 9999999999}).encode()).rstrip(b'=').decode()
        store = SessionStore()
        JsonSession('token').capture({'body': json.dumps({'token': f'h.{p}.s'})}, store)
        assert store.headers['Authorization'].startswith('Bearer ')
        assert store.expires_at == 9999999999.0


# --- Stratégies IA : le client propose une spec, le code l'exécute -----------
class _FakeClient:
    def __init__(self, content):
        self._c = content
    def complete(self, user, system=None):
        class R: content = None
        R.content = self._c
        return R()


class TestAiStrategies:
    def test_ai_nonce_derives_regex_spec(self):
        app = FakeApp(rotate=False)
        client = _FakeClient('{"strategy":"regex","url":"/login","pattern":"value=\\"([^\\"]+)\\""}')
        n = AiNonce('/login', source='render_template(csrf=...)', client=client)
        val = n.fetch(app.send, 'http://app')
        assert val and val.startswith('nonce')

    def test_ai_nonce_inert_without_client(self):
        app = FakeApp(rotate=False)
        assert AiNonce('/login', client=None).fetch(app.send, 'http://app') is None

    def test_ai_session_derives_cookie_spec(self):
        client = _FakeClient('{"strategy":"cookie","names":["sid"]}')
        store = SessionStore()
        AiSession(source='set_cookie sid', client=client).capture(
            {'set_cookie': ['sid=xyz; Path=/']}, store)
        assert store.cookies.get('sid') == 'xyz'

    def test_ai_expiry_negotiates(self):
        client = _FakeClient('{"expired": true}')
        assert AiExpiry(client).expired({'status': 200, 'body': 'session gone'}, SessionStore())
        assert not AiExpiry(None).expired({'status': 200, 'body': 'x'}, SessionStore())


class TestCompositeAndConfig:
    def test_composite_or(self):
        exp = CompositeExpiry([CookieTtlExpiry(), RedirectExpiry('/login')])
        s = SessionStore()
        assert exp.expired({'status': 401}, s) is True
        assert exp.expired({'status': 200}, s) is False

    def test_from_config_ai_wiring(self):
        client = _FakeClient('{"strategy":"cookie","names":["sid"]}')
        cfg = {'reauth': {'base_url': 'http://app',
               'login': {'url': '/login', 'credentials': {'u': 'a'}, 'nonce_field': 'csrf'},
               'nonce': {'strategy': 'ai', 'url': '/login'},
               'session': {'strategy': 'ai'},
               'rotation': {'strategy': 'cookie'},
               'expiry': {'strategies': [{'strategy': 'cookie_ttl'}, {'strategy': 'ai'}]},
               'source': 'def login(): ...'}}
        ra = ReAuthenticator.from_config(cfg, client=client)
        assert ra is not None and ra.base_url == 'http://app'

    def test_from_config_absent(self):
        assert ReAuthenticator.from_config({}) is None
