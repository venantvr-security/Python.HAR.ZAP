"""Tests du confirmateur d'auth (forge + rejeu, verdict prouvé)."""
import base64
import json

from modules.llm.auth_confirmer import (
    AuthConfirmer, forge_alg_none, forge_unsigned)
from modules.llm.investigation import CONFIRMED, REFUTED


def _token(alg="HS256", sub="name1"):
    h = base64.urlsafe_b64encode(json.dumps({"alg": alg, "typ": "JWT"}).encode()).rstrip(b'=').decode()
    p = base64.urlsafe_b64encode(json.dumps({"sub": sub, "exp": 9999999999}).encode()).rstrip(b'=').decode()
    return f"{h}.{p}.signature"


URL = "https://api.x/books/v1/42"
GOOD = _token()


class TestForge:
    def test_alg_none_header(self):
        forged = forge_alg_none(GOOD)
        hdr = json.loads(base64.urlsafe_b64decode(forged.split('.')[0] + '=='))
        assert hdr["alg"] == "none" and forged.endswith(".")

    def test_unsigned_empties_signature(self):
        assert forge_unsigned(GOOD).endswith(".")
        assert forge_unsigned("a.b") is None   # pas 3 parties -> None


class TestConfirm:
    def _vulnerable(self, method, url, headers=None):
        # Accepte N'IMPORTE quel jeton présent (validation cassée) ; refuse sans.
        return {"status": 200} if (headers or {}).get("Authorization") else {"status": 401}

    def _secure(self, method, url, headers=None):
        # N'accepte que le jeton d'origine exact ; forgés (signature vide) rejetés.
        auth = (headers or {}).get("Authorization", "")
        return {"status": 200} if auth == f"Bearer {GOOD}" else {"status": 401}

    def _open(self, method, url, headers=None):
        return {"status": 200}  # ouvert même sans jeton

    def test_vulnerable_is_confirmed(self):
        f = AuthConfirmer(self._vulnerable).confirm(URL, GOOD)
        assert any(x.verdict.status == CONFIRMED for x in f)
        assert any(x.technique == "alg=none" for x in f)

    def test_secure_is_refuted(self):
        f = AuthConfirmer(self._secure).confirm(URL, GOOD)
        assert f and all(x.verdict.status == REFUTED for x in f)

    def test_open_endpoint_not_a_jwt_bypass(self):
        f = AuthConfirmer(self._open).confirm(URL, GOOD)
        assert f and all(x.verdict.status == REFUTED for x in f)
        assert "without any token" in f[0].verdict.reason


class TestModelIntegration:
    def test_protected_urls_from_model(self):
        from modules.semantic.api_model import APIModel
        har = {"log": {"entries": [
            {"request": {"method": "GET", "url": URL, "headers": []},
             "response": {"status": 401, "content": {"text": "{}"}}},
            {"request": {"method": "GET", "url": "https://api.x/books/v1", "headers": []},
             "response": {"status": 200, "content": {"text": "{}"}}},
        ]}}
        model = APIModel.from_har(har)
        urls = AuthConfirmer(lambda *a, **k: {}, api_model=model).protected_urls()
        assert URL in urls and "https://api.x/books/v1" not in urls


class TestExpiredTokenNotMasking:
    """Régression : un jeton capturé EXPIRÉ ne doit pas masquer un vrai bypass
    alg=none (les claims temporels du jeton forgé sont rafraîchis)."""

    def test_alg_none_confirmed_despite_expired_capture(self):
        import time as _t
        expired = _token()  # exp=9999999999 lointain ; on force l'expiration :
        parts = expired.split('.')
        p = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
        p['exp'] = int(_t.time()) - 10
        parts[1] = base64.urlsafe_b64encode(json.dumps(p).encode()).rstrip(b'=').decode()
        expired = '.'.join(parts)

        def server(method, url, headers=None):
            auth = (headers or {}).get("Authorization", "")
            if not auth:
                return {"status": 401}
            tok = auth.split(" ", 1)[-1]
            hdr = json.loads(base64.urlsafe_b64decode(tok.split('.')[0] + '=='))
            pl = json.loads(base64.urlsafe_b64decode(tok.split('.')[1] + '=='))
            if pl.get("exp", 0) < _t.time():
                return {"status": 401}          # vérifie l'expiration
            return {"status": 200} if hdr.get("alg") == "none" else {"status": 401}

        f = AuthConfirmer(server).confirm("https://api/x", expired)
        assert any(x.technique == "alg=none" and x.verdict.status == CONFIRMED for x in f)
