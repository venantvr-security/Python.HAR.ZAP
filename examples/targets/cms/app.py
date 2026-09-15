"""
CMS — fausse application de gestion de contenu (DÉLIBÉRÉMENT VULNÉRABLE).

⚠️  Cible d'entraînement pour HAR-ZAP. À NE LANCER QU'EN LOCAL, jamais exposée.
    Chaque faille est intentionnelle et commentée : le but est pédagogique
    (comprendre le « pourquoi » de l'attaque) et de servir de mode adversarial
    au scanner.

Domaine métier : un mini « Content Management System » — articles (brouillon /
publié), pages, médias, commentaires, et des rôles éditoriaux
(subscriber < author < editor < admin) avec un workflow de publication.

Deux familles de vulnérabilités cohabitent volontairement :

  1. Celles que HAR-ZAP sait déjà investiguer (pour vérifier qu'il confirme) :
     BOLA, mass assignment, BFLA, SSRF (+ rebond interne), JWT alg=none,
     flux métier (publication sans revue), endpoint « shadow ».

  2. Celles qu'il ne gère PAS a priori (pour montrer ses angles morts et servir
     de banc d'essai à de futurs moteurs) : path traversal / LFI, SSTI (format
     string), open redirect, XSS réfléchi et stocké, jeton de reset prédictible,
     CORS permissif (Origin reflété + credentials), injection de formule CSV.

100 % bibliothèque standard (aucune dépendance) → image minuscule, buildable
partout sans réseau, redémarrage = état neuf. Auth JWT faite main pour maîtriser
exactement la faille alg=none.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET = "cms_dev_secret_2024"                 # faible ET exposé (SSTI, /debug/config)
ADMIN_SERVICE_TOKEN = "svc-internal-9d41c0a7"  # ne fuit QUE via l'endpoint interne (SSRF)

# Objet de configuration : il sert de « bombe » à l'injection de template (SSTI).
# En reflétant un format string contrôlé par l'utilisateur, on peut lire ses champs.
CONFIG = {
    "secret_key": SECRET,
    "service_token": ADMIN_SERVICE_TOKEN,
    "env": "production",
    "version": "cms-1.4.2",
    "media_dir": "/app/media",
}

MEDIA_DIR = CONFIG["media_dir"]

DB = {}


def seed():
    global DB
    DB = {
        "users": {
            1: {"id": 1, "username": "alice", "password": "alice123", "role": "author",
                "account_id": 1, "api_key": "AK-alice-001", "email": "alice@blog.io"},
            2: {"id": 2, "username": "bob", "password": "bob123", "role": "author",
                "account_id": 2, "api_key": "AK-bob-002", "email": "bob@blog.io"},
            3: {"id": 3, "username": "carol", "password": "carol123", "role": "editor",
                "account_id": 1, "api_key": "AK-carol-003", "email": "carol@blog.io"},
            4: {"id": 4, "username": "admin", "password": "admin123", "role": "admin",
                "account_id": 0, "api_key": "AK-admin-999", "email": "admin@cms.internal"},
        },
        # status : draft | published. Les brouillons portent des notes confidentielles.
        "articles": {
            1: {"id": 1, "author_id": 1, "status": "published", "title": "Bienvenue sur le blog",
                "body": "Premier article public.", "secret_notes": ""},
            2: {"id": 2, "author_id": 1, "status": "draft", "title": "Roadmap Q3 (privé)",
                "body": "Contenu non publié.",
                "secret_notes": "embargo presse jusqu'au 30/09 — ne pas divulguer"},
            3: {"id": 3, "author_id": 2, "status": "draft", "title": "Refonte tarifs (privé)",
                "body": "Brouillon de Bob.",
                "secret_notes": "nouveaux prix +20% — confidentiel direction"},
            4: {"id": 4, "author_id": 2, "status": "published", "title": "Notes de version",
                "body": "Changelog public.", "secret_notes": ""},
        },
        "pages": {
            1: {"id": 1, "slug": "about", "title": "À propos", "body": "Un blog de démo."},
            2: {"id": 2, "slug": "contact", "title": "Contact", "body": "hello@blog.io"},
        },
        # Commentaires stockés SANS échappement -> XSS stocké au rendu HTML.
        "comments": {
            1: {"id": 1, "article_id": 1, "author": "lecteur", "body": "Super article !"},
        },
        "media": {
            1: {"id": 1, "owner_id": 1, "filename": "logo.txt", "source_url": ""},
        },
    }


def _seed_media_files():
    """Prépare un dossier média : le fichier légitime sert de base au path traversal."""
    try:
        os.makedirs(MEDIA_DIR, exist_ok=True)
        with open(os.path.join(MEDIA_DIR, "logo.txt"), "w") as f:
            f.write("CMS demo media asset\n")
    except Exception:
        pass


seed()
_seed_media_files()


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


def reset_token(username: str) -> str:
    """VULN (auth) : jeton de reset PRÉDICTIBLE — dépend seulement du nom, sans
    secret ni aléa. Un attaquant le recalcule hors ligne pour n'importe qui."""
    return hashlib.md5(username.encode()).hexdigest()[:8]


# --- Routeur minimal --------------------------------------------------------
ROUTES = []


def route(method, pattern):
    rx = re.compile("^" + re.sub(r"<int:(\w+)>", r"(?P<\1>\\d+)", pattern) + "$")

    def deco(fn):
        ROUTES.append((method, rx, fn))
        return fn
    return deco


class Resp:
    """Réponse non-JSON (HTML brut, redirection, CSV…)."""
    def __init__(self, status, body, content_type="text/html; charset=utf-8", headers=None):
        self.status = status
        self.body = body if isinstance(body, bytes) else str(body).encode("utf-8", "ignore")
        self.content_type = content_type
        self.headers = headers or {}


class Ctx:
    """Contexte de requête passé aux handlers."""
    def __init__(self, handler, body, query):
        self.h = handler
        self.body = body
        self.query = query          # dict[str, str] (dernière valeur)

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

    def is_editor(self, u):
        """VULN (BFLA) : jeton de service OU rôle 'editor' passent pour admin."""
        if self.header("X-Service-Token") == ADMIN_SERVICE_TOKEN:
            return True
        return bool(u and u.get("role") in ("admin", "editor"))


def _next_id(table):
    return (max(DB[table]) + 1) if DB[table] else 1


# --- Handlers : contenu -----------------------------------------------------
@route("GET", "/")
def root(c):
    return 200, {"name": "CMS — fausse appli de contenu", "vulnerable": 1,
                 "hint": "POST /createdb puis POST /auth/login"}


@route("POST", "/createdb")
def createdb(c):
    seed()
    _seed_media_files()
    return 200, {"message": "Database seeded."}


@route("POST", "/auth/login")
def login(c):
    for u in DB["users"].values():
        if u["username"] == c.body.get("username") and u["password"] == c.body.get("password"):
            tok = jwt_sign({"sub": u["username"], "role": u["role"],
                            "iat": int(time.time()), "exp": int(time.time()) + 3600})
            return 200, {"token": tok, "token_type": "Bearer"}
    return 401, {"detail": "invalid credentials"}


@route("POST", "/auth/register")
def register(c):
    """VULN (mass assignment) : l'inscription fusionne le corps SANS liste blanche
    → un visiteur s'auto-attribue role=admin dès la création."""
    uid = _next_id("users")
    u = {"id": uid, "username": c.body.get("username", f"user{uid}"),
         "password": c.body.get("password", "x"), "role": "subscriber",
         "account_id": uid, "api_key": f"AK-user-{uid:03d}", "email": ""}
    u.update(c.body)                              # ⚠️ role/api_key/id écrasables
    u["id"] = uid
    DB["users"][uid] = u
    return 201, u


@route("POST", "/auth/reset-request")
def reset_request(c):
    """VULN (auth) : renvoie un jeton de reset prédictible ET utilisable tel quel."""
    username = c.body.get("username", "")
    return 200, {"username": username, "reset_token": reset_token(username),
                 "note": "utilisez ce jeton sur /auth/reset-confirm"}


@route("POST", "/auth/reset-confirm")
def reset_confirm(c):
    """VULN (auth) : accepte le jeton prédictible → prise de contrôle de tout compte."""
    username = c.body.get("username", "")
    token = c.body.get("token", "")
    if token != reset_token(username):
        return 400, {"detail": "invalid token"}
    for u in DB["users"].values():
        if u["username"] == username:
            u["password"] = c.body.get("new_password", u["password"])
            return 200, {"message": f"password reset for {username}"}
    return 404, {"detail": "unknown user"}


@route("GET", "/me")
def me(c):
    u = c.user()
    return (200, u) if u else (401, {"detail": "authentication required"})


@route("PATCH", "/me")
def patch_me(c):
    """VULN (mass assignment) : fusion sans allowlist → role=admin, changement d'id."""
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


@route("GET", "/articles")
def articles_list(c):
    """VULN (excessive data exposure) : ?status=draft expose les brouillons de TOUS
    les auteurs (notes confidentielles comprises), sans contrôle de propriété.
    Par défaut, seul le contenu publié devrait sortir."""
    status = c.query.get("status")
    items = list(DB["articles"].values())
    if status:
        items = [a for a in items if a["status"] == status]   # ⚠️ pas de filtre par auteur
    else:
        items = [a for a in items if a["status"] == "published"]
    return 200, {"articles": items}


@route("GET", "/articles/<int:aid>")
def article_get(c, aid):
    """VULN (BOLA) : tout authentifié lit le brouillon d'autrui + ses secret_notes."""
    if not c.user():
        return 401, {"detail": "authentication required"}
    a = DB["articles"].get(int(aid))
    return (200, a) if a else (404, {"detail": "not found"})


@route("POST", "/articles")
def article_create(c):
    """VULN (mass assignment) : author_id/status/id contrôlables → usurpation d'auteur
    et publication directe en contournant la revue éditoriale."""
    u = c.user()
    if not u:
        return 401, {"detail": "authentication required"}
    aid = _next_id("articles")
    a = {"id": aid, "author_id": u["id"], "status": "draft",
         "title": c.body.get("title", "sans titre"), "body": c.body.get("body", ""),
         "secret_notes": ""}
    a.update(c.body)                              # ⚠️ author_id/status écrasables
    a["id"] = aid
    DB["articles"][aid] = a
    return 201, a


@route("POST", "/articles/<int:aid>/publish")
def article_publish(c, aid):
    """VULN (flux métier/BFLA) : un simple 'author' publie son propre brouillon sans
    l'aval d'un 'editor' → le workflow de revue éditoriale est contournable."""
    u = c.user()
    if not u:
        return 401, {"detail": "authentication required"}
    a = DB["articles"].get(int(aid))
    if not a:
        return 404, {"detail": "not found"}
    a["status"] = "published"                    # ⚠️ aucune vérification de rôle/approbation
    return 200, {"id": a["id"], "status": a["status"], "published_by": u["username"]}


@route("DELETE", "/articles/<int:aid>")
def article_delete(c, aid):
    """VULN (BFLA) : n'importe quel authentifié supprime l'article d'autrui."""
    u = c.user()
    if not u:
        return 401, {"detail": "authentication required"}
    if int(aid) in DB["articles"]:
        del DB["articles"][int(aid)]             # ⚠️ pas de contrôle auteur/éditeur
        return 200, {"deleted": int(aid)}
    return 404, {"detail": "not found"}


# --- Commentaires : XSS stocké ----------------------------------------------
@route("POST", "/articles/<int:aid>/comments")
def comment_add(c, aid):
    """Le corps est stocké TEL QUEL (pas d'échappement) : charge utile XSS possible."""
    cid = _next_id("comments")
    com = {"id": cid, "article_id": int(aid),
           "author": c.body.get("author", "anon"), "body": c.body.get("body", "")}
    DB["comments"][cid] = com
    return 201, com


@route("GET", "/articles/<int:aid>/render")
def article_render(c, aid):
    """VULN (XSS stocké) : rend l'article + commentaires en HTML SANS échappement.
    Un commentaire contenant <script> s'exécute chez le lecteur."""
    a = DB["articles"].get(int(aid))
    if not a:
        return Resp(404, "<h1>404</h1>")
    coms = [x for x in DB["comments"].values() if x["article_id"] == int(aid)]
    html = f"<article><h1>{a['title']}</h1><div>{a['body']}</div><hr><h3>Commentaires</h3>"
    for x in coms:
        html += f"<p><b>{x['author']}</b> : {x['body']}</p>"   # ⚠️ injection HTML
    html += "</article>"
    return Resp(200, html)


@route("GET", "/search")
def search(c):
    """VULN (XSS réfléchi) : le terme de recherche est réinjecté brut dans la page."""
    q = c.query.get("q", "")
    html = f"<h1>Résultats pour : {q}</h1><ul></ul>"          # ⚠️ q non échappé
    return Resp(200, html)


@route("GET", "/articles/search")
def articles_search(c):
    """VULN (SQLi, SIMULÉE sans vraie base — pédagogique). On modélise la requête
    `SELECT * FROM articles WHERE title = '<q>'` : `q` est concaténé sans échapper.
    - apostrophes non appariées -> requête cassée -> erreur SGBD (error-based) ;
    - tautologie `' OR '1'='1` -> tout sort, brouillons compris (boolean-based) ;
    - `SLEEP(n)` -> délai réel (time-based)."""
    q = c.query.get("q", "")
    low = q.lower()
    m = re.search(r"sleep\((\d+)\)", low)                     # time-based
    if m:
        time.sleep(min(int(m.group(1)), 6))
        return 200, {"results": []}
    if q.count("'") % 2 == 1:                                 # guillemet non apparié -> erreur
        return 500, {"error": "You have an error in your SQL syntax; check the manual that "
                              "corresponds to your MySQL server version near \"'\" at line 1"}
    if re.search(r"or\s+'?1'?\s*=\s*'?1", low) or "or 1=1" in low:   # tautologie
        return 200, {"results": list(DB["articles"].values())}
    res = [a for a in DB["articles"].values() if low in a["title"].lower()]
    return 200, {"results": res}


@route("POST", "/articles/query")
def articles_query(c):
    """VULN (NoSQLi, SIMULÉE façon Mongo). Le filtre `title` est passé tel quel :
    - un OPÉRATEUR ($ne/$gt/$regex/$in) élargit le résultat à tout (bypass de filtre) ;
    - `$where: "sleep(ms)"` -> délai (time-based) ;
    - opérateur inconnu -> MongoError (error-based)."""
    spec = c.body.get("title", "")
    if isinstance(spec, dict):
        if "$where" in spec:
            m = re.search(r"sleep\((\d+)\)", str(spec.get("$where", "")).lower())
            if m:
                time.sleep(min(int(m.group(1)) // 1000 or int(m.group(1)), 6))
            return 200, {"results": list(DB["articles"].values())}
        if any(k in spec for k in ("$ne", "$gt", "$lt", "$regex", "$in")):
            return 200, {"results": list(DB["articles"].values())}   # opérateur -> tout
        return 500, {"error": "MongoServerError: unknown operator: "
                              + next(iter(spec), "?")}
    res = [a for a in DB["articles"].values() if a["title"] == spec]
    return 200, {"results": res}


# --- Rendu de gabarit : SSTI ------------------------------------------------
@route("POST", "/preview")
def preview(c):
    """VULN (SSTI / format string) : le gabarit fourni est passé à str.format avec
    un contexte contenant la config → `{config[secret_key]}` divulgue le secret,
    `{article[secret_notes]}` fuit les notes privées. Angle mort DAST classique."""
    tpl = c.body.get("template", "")
    context = {"config": CONFIG, "article": DB["articles"].get(1, {}),
               "user": c.user() or {}}
    try:
        rendered = tpl.format(**context)         # ⚠️ format string contrôlé par l'utilisateur
    except Exception as e:
        rendered = f"template error: {e}"
    return 200, {"rendered": rendered}


# --- Médias : SSRF, path traversal ------------------------------------------
@route("POST", "/media/fetch")
def media_fetch(c):
    """VULN (SSRF/API7) : télécharge une URL fournie sans filtrer les cibles internes
    → atteint /internal/metadata (pivot) et 169.254.169.254."""
    if not c.user():
        return 401, {"detail": "authentication required"}
    url = c.body.get("url", "")
    try:
        with urllib.request.urlopen(url, timeout=4) as r:      # ⚠️ SSRF
            return 200, {"fetched": url, "status": r.status,
                         "body": r.read(2000).decode("utf-8", "ignore")}
    except Exception as e:
        return 502, {"fetched": url, "error": str(e)}


@route("GET", "/media/raw")
def media_raw(c):
    """VULN (path traversal / LFI) : concatène ?path au dossier média sans normaliser
    → `?path=../../etc/passwd` lit des fichiers arbitraires. Angle mort DAST."""
    rel = c.query.get("path", "")
    full = os.path.join(MEDIA_DIR, rel)          # ⚠️ pas de contrôle de confinement
    try:
        with open(full, "rb") as f:
            return Resp(200, f.read(4000), content_type="text/plain; charset=utf-8")
    except Exception as e:
        return Resp(404, f"not found: {e}", content_type="text/plain; charset=utf-8")


# --- Redirection : open redirect --------------------------------------------
@route("GET", "/go")
def go(c):
    """VULN (open redirect) : redirige vers ?to sans liste blanche de domaines
    → hameçonnage (le lien part du domaine de confiance du CMS)."""
    to = c.query.get("to", "/")
    return Resp(302, "", headers={"Location": to})            # ⚠️ destination arbitraire


# --- Export : injection de formule CSV --------------------------------------
@route("GET", "/export/subscribers.csv")
def export_csv(c):
    """VULN (CSV/formula injection + exposition) : dump des utilisateurs en CSV, champs
    non préfixés → un pseudo commençant par '=' devient une formule dans un tableur."""
    u = c.user()
    if not c.is_editor(u):
        return 403, {"detail": "editor required"}
    rows = ["id,username,email,role"]
    for x in DB["users"].values():
        rows.append(f"{x['id']},{x['username']},{x.get('email', '')},{x['role']}")  # ⚠️ pas de neutralisation '=+-@'
    return Resp(200, "\n".join(rows), content_type="text/csv; charset=utf-8")


# --- Admin / interne / shadow -----------------------------------------------
@route("GET", "/admin/users")
def admin_users(c):
    """VULN (BFLA/API5) : dump complet (mots de passe, clés) via le jeton de service
    (fin de chaîne SSRF), OU par un 'editor' (contrôle trop permissif), OU par un
    jeton alg=none forgé role=admin."""
    u = c.user()
    if not c.is_editor(u):
        return 403, {"detail": "admin required"}
    return 200, {"users": list(DB["users"].values())}


@route("GET", "/internal/metadata")
def internal_metadata(c):
    """« Interne » : contrôle par IP source (127.0.0.1) — exactement ce que satisfait
    une SSRF (le serveur se requête lui-même). De l'extérieur → 403."""
    if c.remote_addr() not in ("127.0.0.1", "::1"):
        return 403, {"detail": "internal endpoint"}
    return 200, {"service_token": ADMIN_SERVICE_TOKEN, "note": "use as X-Service-Token"}


@route("GET", "/debug/config")
def debug_config(c):
    """VULN (API9/exposition) : endpoint oublié qui divulgue le secret de signature
    et le jeton de service — non référencé, découvert par extrapolation."""
    return 200, {"secret_key": SECRET, "admin_service_token": ADMIN_SERVICE_TOKEN,
                 "users": len(DB["users"]), "env": CONFIG["env"]}


@route("GET", "/actuator/env")
def actuator_env(c):
    """VULN (shadow/exposition) : faux endpoint façon Spring Actuator — seconde
    surface d'extrapolation qui recrache la configuration."""
    return 200, {"activeProfiles": [CONFIG["env"]],
                 "propertySources": [{"name": "app", "properties": dict(CONFIG)}]}


# --- Serveur HTTP -----------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _dispatch(self, method):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        query = {k: v[-1] for k, v in urllib.parse.parse_qs(parsed.query).items()}
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
                    result = fn(Ctx(self, body, query), **mt.groupdict())
                except Exception as e:               # pas de 500 opaque en démo
                    result = (500, {"error": str(e)})
                return self._send(result)
        self._send((404, {"detail": "not found"}))

    def _send(self, result):
        if isinstance(result, Resp):
            status, data, ctype, extra = result.status, result.body, result.content_type, result.headers
        else:
            status, payload = result
            data = json.dumps(payload).encode()
            ctype, extra = "application/json", {}
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        # VULN (CORS) : reflète l'Origin ET autorise les credentials → n'importe quel
        # site tiers peut lire les réponses authentifiées de la victime.
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)   # ⚠️ reflet sans allowlist
            self.send_header("Access-Control-Allow-Credentials", "true")
        for k, v in extra.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PATCH(self):
        self._dispatch("PATCH")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def log_message(self, *a):
        pass                                          # silencieux


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 5000), Handler).serve_forever()
