"""Tests du DSL de recettes d'auth + persistance (mémoire de la ré-auth)."""
from modules.auth_dsl import parse, serialize, AuthRecipeStore


SAMPLE = '''
# découvert par l'IA
auth "app.example" {
  login POST /login
  nonce-field csrf
  nonce   regex url=/login pattern="name=\\"csrf\\" value=\\"([^\\"]+)\\""
  session cookie names=sid,jwt
  rotate  cookie
  expire  cookie_ttl skew=30
  expire  redirect login_path=/login
}
'''


class TestParse:
    def test_parses_all_slots(self):
        rec = parse(SAMPLE)['app.example']
        assert rec['login'] == {'method': 'POST', 'url': '/login', 'nonce_field': 'csrf'}
        assert rec['nonce']['strategy'] == 'regex'
        assert rec['nonce']['url'] == '/login'
        assert 'csrf' in rec['nonce']['pattern']
        assert rec['session'] == {'strategy': 'cookie', 'names': ['sid', 'jwt']}
        assert rec['rotation'] == {'strategy': 'cookie'}
        assert rec['expiry']['strategies'][0] == {'strategy': 'cookie_ttl', 'skew': 30}
        assert rec['expiry']['strategies'][1] == {'strategy': 'redirect', 'login_path': '/login'}

    def test_ignores_comments_and_blanks(self):
        assert parse("\n\n# just a comment\n") == {}


class TestRoundTrip:
    def test_serialize_then_parse_is_stable(self):
        rec = parse(SAMPLE)['app.example']
        text = serialize('app.example', rec)
        rec2 = parse(text)['app.example']
        assert rec2 == rec

    def test_serialize_never_writes_credentials(self):
        rec = {'login': {'method': 'POST', 'url': '/login',
                         'credentials': {'password': 'SECRET'}},
               'session': {'strategy': 'cookie'}}
        text = serialize('h', rec)
        assert 'SECRET' not in text and 'credentials' not in text


class TestStore:
    def test_record_and_reload(self, tmp_path):
        p = str(tmp_path / 'auth.dsl')
        store = AuthRecipeStore(p)
        assert store.get('app') is None
        assert not store.has_slot('app', 'nonce')
        store.record_slot('app', 'nonce', {'strategy': 'regex', 'url': '/login', 'pattern': 'x=(.+)'})
        # rechargé depuis le disque -> le slot est mémorisé (plus besoin d'IA)
        store2 = AuthRecipeStore(p)
        assert store2.has_slot('app', 'nonce')
        assert store2.get('app')['nonce']['strategy'] == 'regex'

    def test_ai_strategy_not_counted_as_resolved(self, tmp_path):
        p = str(tmp_path / 'auth.dsl')
        store = AuthRecipeStore(p)
        store.put('app', {'login': {}, 'nonce': {'strategy': 'ai', 'url': '/login'},
                          'expiry': {'strategies': []}})
        assert not store.has_slot('app', 'nonce')     # 'ai' n'est pas une résolution concrète
