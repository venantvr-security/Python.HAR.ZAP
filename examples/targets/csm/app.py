"""
CSM — Customer Success Management API (DÉLIBÉRÉMENT VULNÉRABLE).

⚠️  Cible d'entraînement pour HAR-ZAP. À NE LANCER QU'EN LOCAL, jamais exposée.
    Chaque faille est intentionnelle et commentée : le but est pédagogique
    (comprendre le « pourquoi » de l'attaque) et de servir de mode adversarial
    au scanner (BOLA, mass assignment, SSRF, JWT alg=none, business-flow, chaînes).

Domaine métier : plateforme SaaS de « Customer Success » — comptes clients
(accounts), leurs utilisateurs (users), tickets, factures (invoices), webhooks.

100 % bibliothèque standard (aucune dépendance) → image minuscule, buildable
partout sans réseau, redémarrage = état neuf. Auth JWT faite main pour maîtriser
exactement la faille alg=none.
"""
import base64
import hashlib
import hmac
import json
import re
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET = "csm_dev_secret_2024"                 # faible ET exposé par /debug/config
ADMIN_SERVICE_TOKEN = "svc-internal-9d41c0a7"  # ne fuit QUE via l'endpoint interne (SSRF)

DB = {}


def seed():
    global DB
    DB = {
        "users": {
            1: {"id": 1, "username": "alice", "password": "alice123", "role": "user",
                "account_id": 1, "api_key": "AK-alice-001", "email": "alice@acme.io"},
            2: {"id": 2, "username": "bob", "password": "bob123", "role": "user",
                "account_id": 2, "api_key": "AK-bob-002", "email": "bob@globex.io"},
            3: {"id": 3, "username": "carol", "password": "carol123", "role": "manager",
                "account_id": 1, "api_key": "AK-carol-003", "email": "carol@acme.io"},
            4: {"id": 4, "username": "admin", "password": "admin123", "role": "admin",
                "account_id": 0, "api_key": "AK-admin-999", "email": "admin@csm.internal"},
        },
        "accounts": {
            1: {"id": 1, "name": "Acme Corp", "owner_id": 1, "plan": "pro", "mrr": 999},
            2: {"id": 2, "name": "Globex", "owner_id": 2, "plan": "free", "mrr": 0},
        },
        "tickets": {
            1: {"id": 1, "account_id": 1, "author_id": 1, "subject": "Login issue",
                "private_note": "alice SSN 111-22-3333 (internal only)"},
            2: {"id": 2, "account_id": 2, "author_id": 2, "subject": "Billing",
                "private_note": "bob card 4242-4242-4242-4242"},
        },
        "invoices": {
            1: {"id": 1, "account_id": 1, "amount": 100, "status": "paid",
                "payment_ref": "pi_acme_0001", "refunded": 0},
            2: {"id": 2, "account_id": 2, "amount": 50, "status": "paid",
                "payment_ref": "pi_globex_0001", "refunded": 0},
        },
    }


seed()


# --- JWT fait main : la faille alg=none est dans jwt_verify -----------------
def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _unb64(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def jwt_sign(payload: dict) -> str:
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64(json.dumps(payload).encode())
    sig = hmac.new(SECRET.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{_b64(sig)}"


def jwt_verify(token: str):
    """VULN (JWT) : accepte alg=none (aucune signature) et ignore l'expiration."""
    try:
        h, b, s = token.split(".")
        header = json.loads(_unb64(h))
        payload = json.loads(_unb64(b))
    except Exception:
        return None
    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        return payload                          # ⚠️ bypass total de signature
    if alg == "hs256":
        expected = _b64(hmac.new(SECRET.encode(), f"{h}.{b}".encode(),
                                 hashlib.sha256).digest())
        if hmac.compare_digest(expected, s):
            return payload
    return None


# --- Routeur minimal --------------------------------------------------------
ROUTES = []


def route(method, pattern):
    rx = re.compile("^" + re.sub(r"<int:(\w+)>", r"(?P<\1>\\d+)", pattern) + "$")

    def deco(fn):
        ROUTES.append((method, rx, fn))
        return fn
    return deco


class Ctx:
    """Contexte de requête passé aux handlers."""
    def __init__(self, handler, body):
        self.h = handler
        self.body = body

    def header(self, name, default=""):
        return self.h.headers.get(name, default)

    def remote_addr(self):
        return self.h.client_address[0]

    # --- résolution de l'appelant (3 voies d'auth, toutes exploitables) ---
    def user(self):
        auth = self.header("Authorization")
        if auth.startswith("Bearer "):
            payload = jwt_verify(auth[7:])
            if payload:
                for u in DB["users"].values():
                    if u["username"] == payload.get("sub"):
                        return u
                if payload.get("role") == "admin":       # jeton forgé role=admin
                    return {"id": 0, "username": payload.get("sub", "?"),
                            "role": "admin", "account_id": 0}
        apikey = self.header("X-API-Key")
        if apikey:                                       # fuite via BOLA -> takeover
            for u in DB["users"].values():
                if u["api_key"] == apikey:
                    return u
        return None

    def is_admin(self, u):
        """VULN (BFLA) : jeton de service OU rôle 'manager' passent pour admin."""
        if self.header("X-Service-Token") == ADMIN_SERVICE_TOKEN:
            return True
        return bool(u and u.get("role") in ("admin", "manager"))


# --- Handlers ---------------------------------------------------------------
@route("GET", "/")
def root(c):
    return 200, {"name": "CSM — Customer Success Management", "vulnerable": 1,
                 "hint": "POST /createdb then POST /auth/login"}


@route("POST", "/createdb")
def createdb(c):
    seed()
    return 200, {"message": "Database seeded."}


@route("POST", "/auth/login")
def login(c):
    for u in DB["users"].values():
        if u["username"] == c.body.get("username") and u["password"] == c.body.get("password"):
            tok = jwt_sign({"sub": u["username"], "role": u["role"],
                            "iat": int(time.time()), "exp": int(time.time()) + 3600})
            return 200, {"token": tok, "token_type": "Bearer"}
    return 401, {"detail": "invalid credentials"}


@route("GET", "/me")
def me(c):
    u = c.user()
    return (200, u) if u else (401, {"detail": "authentication required"})


@route("PATCH", "/me")
def patch_me(c):
    """VULN (mass assignment) : fusion du corps SANS liste blanche → role=admin,
    changement d'account_id (prise de contrôle d'un autre compte)."""
    u = c.user()
    if not u:
        return 401, {"detail": "authentication required"}
    u.update(c.body)                             # ⚠️ aucune allowlist
    return 200, u


@route("GET", "/users")
def users_list(c):
    if not c.user():
        return 401, {"detail": "authentication required"}
    return 200, {"users": [{"id": x["id"], "username": x["username"], "role": x["role"]}
                           for x in DB["users"].values()]}


@route("GET", "/users/<int:uid>")
def user_get(c, uid):
    """VULN (BOLA) : tout authentifié lit n'importe quel profil, clé API comprise."""
    if not c.user():
        return 401, {"detail": "authentication required"}
    t = DB["users"].get(int(uid))
    return (200, t) if t else (404, {"detail": "not found"})


@route("GET", "/accounts/<int:aid>")
def account_get(c, aid):
    """VULN (BOLA) : accès transverse aux comptes (MRR, plan…)."""
    if not c.user():
        return 401, {"detail": "authentication required"}
    a = DB["accounts"].get(int(aid))
    return (200, a) if a else (404, {"detail": "not found"})


@route("GET", "/tickets/<int:tid>")
def ticket_get(c, tid):
    """VULN (BOLA) : la note privée (PII) d'un ticket d'autrui fuit."""
    if not c.user():
        return 401, {"detail": "authentication required"}
    t = DB["tickets"].get(int(tid))
    return (200, t) if t else (404, {"detail": "not found"})


@route("GET", "/invoices/<int:iid>")
def invoice_get(c, iid):
    """VULN (BOLA) : référence de paiement d'autrui exposée."""
    if not c.user():
        return 401, {"detail": "authentication required"}
    inv = DB["invoices"].get(int(iid))
    return (200, inv) if inv else (404, {"detail": "not found"})


@route("POST", "/invoices/<int:iid>/refund")
def invoice_refund(c, iid):
    """VULN (flux métier/API6) : aucun plafond, aucune idempotence, aucun contrôle
    de propriété → fraude au remboursement (montant > payé, rejouable)."""
    if not c.user():
        return 401, {"detail": "authentication required"}
    inv = DB["invoices"].get(int(iid))
    if not inv:
        return 404, {"detail": "not found"}
    amount = float(c.body.get("amount", 0))
    inv["refunded"] += amount                    # ⚠️ pas de cap ni d'idempotence
    return 200, {"invoice_id": int(iid), "refunded_now": amount,
                 "total_refunded": inv["refunded"], "paid": inv["amount"]}


@route("POST", "/webhooks/test")
def webhook_test(c):
    """VULN (SSRF/API7) : le serveur requête une URL fournie par l'utilisateur sans
    filtrer les cibles internes → atteint /internal/metadata (pivot) et 169.254.169.254."""
    if not c.user():
        return 401, {"detail": "authentication required"}
    url = c.body.get("url", "")
    try:
        with urllib.request.urlopen(url, timeout=4) as r:   # ⚠️ SSRF
            return 200, {"fetched": url, "status": r.status,
                         "body": r.read(2000).decode("utf-8", "ignore")}
    except Exception as e:
        return 502, {"fetched": url, "error": str(e)}


@route("GET", "/internal/metadata")
def internal_metadata(c):
    """« Interne » : contrôle par IP source (127.0.0.1) — exactement ce que
    satisfait une SSRF (le serveur se requête lui-même). De l'extérieur → 403."""
    if c.remote_addr() not in ("127.0.0.1", "::1"):
        return 403, {"detail": "internal endpoint"}
    return 200, {"service_token": ADMIN_SERVICE_TOKEN, "note": "use as X-Service-Token"}


@route("GET", "/admin/users")
def admin_users(c):
    """VULN (BFLA/API5) : dump complet (mots de passe, clés) via le jeton de service
    (fin de chaîne SSRF), OU par un 'manager' (contrôle trop permissif), OU par un
    jeton alg=none forgé role=admin."""
    u = c.user()
    if not c.is_admin(u):
        return 403, {"detail": "admin required"}
    return 200, {"users": list(DB["users"].values())}


@route("GET", "/debug/config")
def debug_config(c):
    """VULN (API9/exposition) : endpoint oublié qui divulgue le secret de signature
    et le jeton de service — non référencé, découvert par extrapolation."""
    return 200, {"secret_key": SECRET, "admin_service_token": ADMIN_SERVICE_TOKEN,
                 "users": len(DB["users"]), "env": "production"}


# --- Serveur HTTP -----------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _dispatch(self, method):
        path = self.path.split("?", 1)[0]
        body = {}
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            raw = self.rfile.read(length)
            try:
                body = json.loads(raw or b"{}")
            except Exception:
                body = {}
        for m, rx, fn in ROUTES:
            if m != method:
                continue
            mt = rx.match(path)
            if mt:
                try:
                    status, payload = fn(Ctx(self, body), **mt.groupdict())
                except Exception as e:               # pas de 500 opaque en démo
                    status, payload = 500, {"error": str(e)}
                return self._send(status, payload)
        self._send(404, {"detail": "not found"})

    def _send(self, status, payload):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PATCH(self):
        self._dispatch("PATCH")

    def log_message(self, *a):
        pass                                          # silencieux


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 5000), Handler).serve_forever()
