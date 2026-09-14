"""Tests de l'orchestrateur d'investigations (shadow + auth-forge)."""
import base64
import json

from modules.investigations import run_investigations, run_shadow, run_auth_forge
from modules.semantic.api_model import APIModel


def _jwt(alg="HS256", sub="bob"):
    b = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b'=').decode()  # noqa
    return f"{b({'alg': alg, 'typ': 'JWT'})}.{b({'sub': sub, 'exp': 9999999999})}.sig"


TOKEN = _jwt()
BASE = "https://api.x"


def _har():
    e = lambda m, u, s=200, txt="{}", h=None: {  # noqa
        "request": {"method": m, "url": u, "headers": h or []},
        "response": {"status": s, "content": {"text": txt}}}
    return {"log": {"entries": [
        e("GET", f"{BASE}/users/v1", txt=json.dumps({"users": []})),
        e("GET", f"{BASE}/users/v1/bob", 200, json.dumps({"username": "bob", "email": "b@x"}),
          [{"name": "Authorization", "value": f"Bearer {TOKEN}"}]),
        # item protégé (401 sans jeton) -> cible du forge auth
        e("GET", f"{BASE}/books/v1/42", 401),
    ]}}


class Server:
    """VAmPI-like : /_debug caché, /users/v1/<id> item, /books/v1/<id> protégé et
    VULNÉRABLE à alg=none."""

    def __call__(self, method, url, headers=None, json_body=None):
        auth = (headers or {}).get("Authorization", "")
        last = url.rstrip('/').split('/')[-1]
        if url.endswith("/users/v1/_debug"):
            return {"status": 200, "body": json.dumps({"users": [{"username": "bob", "admin": True}]})}
        if "/users/v1/" in url:            # item users : {username,email}
            if last in ("bob", "admin"):
                return {"status": 200, "body": json.dumps({"username": last, "email": "x"})}
            return {"status": 404, "body": "{}"}
        if "/books/v1/" in url:            # protégé, accepte alg=none
            if not auth:
                return {"status": 401, "body": "{}"}
            tok = auth.split(" ", 1)[-1]
            hdr = json.loads(base64.urlsafe_b64decode(tok.split('.')[0] + '=='))
            return {"status": 200, "body": "{}"} if hdr.get("alg") == "none" else {"status": 401, "body": "{}"}
        return {"status": 404, "body": "{}"}


class TestShadow:
    def test_finds_hidden_skips_existing_id(self):
        model = APIModel.from_har(_har())
        out = run_shadow(model, Server(), BASE)
        names = " ".join(f['name'] for f in out)
        assert "_debug" in names               # endpoint caché trouvé
        assert "/users/v1/admin" not in names  # id existant écarté (schéma d'item)


class TestAuthForge:
    def test_confirms_alg_none(self):
        model = APIModel.from_har(_har())
        out = run_auth_forge(model, TOKEN, Server())
        assert any(f['status'] == 'confirmed' and f['risk'] == 'Critical' for f in out)


class TestOrchestrator:
    def test_end_to_end(self):
        findings = run_investigations(
            _har(), Server(), BASE,
            headers={"Authorization": f"Bearer {TOKEN}"})
        sources = {f['source'] for f in findings}
        assert 'shadow_endpoint' in sources and 'auth_confirmer' in sources
