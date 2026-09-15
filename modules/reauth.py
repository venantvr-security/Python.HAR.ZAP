"""
Ré-authentification enfichable pour DAST authentifié (sessions qui tournent).

Problème : une app sans MFA mais avec (a) un NONCE anti-rejeu au login, (b) un
jeton de session RENOUVELÉ dynamiquement (cookie glissant / header rotatif), et
(c) une fin de session (redirection / 401 / TTL de cookie). Un jeton figé dans le
HAR périme donc en cours de scan.

Design : des STRATÉGIES enfichables, sélectionnées par nom en config.
  - NonceStrategy   : d'où vient le nonce et comment l'extraire.
  - SessionStrategy : comment récupérer le matériel de session après login.
  - RotationStrategy: comment suivre le renouvellement à chaque réponse.
  - ExpiryStrategy  : quand re-loguer (réactif redirection/401, PROACTIF via la
                      TTL du cookie/JWT, ou NÉGOCIÉ par l'IA).

Discipline du projet : l'IA PROPOSE (une spec d'extraction déduite du code source,
une décision « la session est-elle morte ? »), le CODE DISPOSE (exécution
déterministe de la spec, mise en cache). Sans client LLM, les stratégies IA sont
inertes → repli sur les stratégies déterministes. Les stratégies IA appellent le
modèle : elles ne doivent tourner que sous attestation d'autorisation.

L'exécuteur attendu est celui déjà utilisé partout :
    send(method, url, headers=None, body=None) -> {status, body, headers, ...}
`ReAuthenticator.wrap(send)` rend un exécuteur « session-aware » à brancher tel
quel dans n'importe quel moteur.
"""
import base64
import json
import re
import time
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Callable, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from .utils import get_logger

logger = get_logger("reauth")

SendFn = Callable[..., Dict]


# =============================================================================
# Store de session mutable (le cœur du « renouvelé dynamiquement »)
# =============================================================================
class SessionStore:
    """Détient le matériel d'auth COURANT (cookies + en-têtes) et sa TTL."""

    def __init__(self):
        self.cookies: Dict[str, str] = {}
        self.headers: Dict[str, str] = {}
        self.expires_at: Optional[float] = None   # epoch, si connue

    def auth_headers(self) -> Dict[str, str]:
        """En-têtes à injecter dans la requête (Cookie agrégé + en-têtes jetons)."""
        out = dict(self.headers)
        if self.cookies:
            out['Cookie'] = '; '.join(f'{k}={v}' for k, v in self.cookies.items())
        return out

    def merge_cookies(self, cookies: Dict[str, str]):
        self.cookies.update({k: v for k, v in cookies.items() if v is not None})

    @property
    def established(self) -> bool:
        return bool(self.cookies or self.headers)


# =============================================================================
# Helpers d'extraction déterministes
# =============================================================================
def _dotted(data, path: str):
    cur = data
    for seg in path.split('.'):
        if isinstance(cur, dict) and seg in cur:
            cur = cur[seg]
        else:
            return None
    return cur


def _resp_cookies(resp: Dict) -> Dict[str, str]:
    """Extrait les cookies d'une réponse : liste `set_cookie` si dispo, sinon
    l'en-tête `Set-Cookie` (agrégé)."""
    out: Dict[str, str] = {}
    raw = resp.get('set_cookie') or []
    if isinstance(raw, str):
        raw = [raw]
    hdrs = resp.get('headers') or {}
    if not raw:
        sc = hdrs.get('Set-Cookie') or hdrs.get('set-cookie')
        if sc:
            raw = [sc]
    for line in raw:
        try:
            c = SimpleCookie()
            c.load(line)
            for k, morsel in c.items():
                out[k] = morsel.value
        except Exception:
            continue
    return out


def _cookie_ttl(resp: Dict) -> Optional[float]:
    """TTL (epoch) déduite de Max-Age/Expires d'un Set-Cookie, si présente."""
    raw = resp.get('set_cookie') or []
    if isinstance(raw, str):
        raw = [raw]
    hdrs = resp.get('headers') or {}
    if not raw:
        sc = hdrs.get('Set-Cookie') or hdrs.get('set-cookie')
        if sc:
            raw = [sc]
    for line in raw:
        m = re.search(r'max-age=(\d+)', line, re.I)
        if m:
            return time.time() + int(m.group(1))
        m = re.search(r'expires=([^;]+)', line, re.I)
        if m:
            try:
                from email.utils import parsedate_to_datetime
                return parsedate_to_datetime(m.group(1)).timestamp()
            except Exception:
                pass
    return None


def _jwt_exp(token: str) -> Optional[float]:
    """`exp` d'un JWT (sans vérif de signature — on lit juste la TTL)."""
    try:
        payload = token.split('.')[1]
        payload += '=' * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return float(data['exp']) if 'exp' in data else None
    except Exception:
        return None


# =============================================================================
# Stratégies : NONCE
# =============================================================================
class NonceStrategy:
    def fetch(self, send: SendFn, base_url: str) -> Optional[str]:
        raise NotImplementedError


@dataclass
class RegexNonce(NonceStrategy):
    """GET une page et extrait le nonce par regex (champ caché HTML, etc.)."""
    url: str
    pattern: str
    group: int = 1

    def fetch(self, send, base_url):
        r = send('GET', urljoin(base_url, self.url)) or {}
        m = re.search(self.pattern, r.get('body', '') or '')
        return m.group(self.group) if m else None


@dataclass
class JsonNonce(NonceStrategy):
    """GET un endpoint JSON (type /csrf) et lit le nonce à un chemin pointé."""
    url: str
    path: str

    def fetch(self, send, base_url):
        r = send('GET', urljoin(base_url, self.url)) or {}
        try:
            return str(_dotted(json.loads(r.get('body', '') or 'null'), self.path) or '') or None
        except Exception:
            return None


@dataclass
class CookieNonce(NonceStrategy):
    """Le nonce est posé en cookie (double-submit) par une page d'amorçage."""
    url: str
    cookie: str

    def fetch(self, send, base_url):
        r = send('GET', urljoin(base_url, self.url)) or {}
        return _resp_cookies(r).get(self.cookie)


@dataclass
class AiNonce(NonceStrategy):
    """L'IA DÉDUIT du code source où est le nonce et rend une spec d'extraction
    concrète (regex/json/cookie), exécutée ensuite de façon déterministe et mise
    en cache. La spec est PERSISTÉE dans le DSL (store) → plus d'appel IA ensuite.
    Sans client → inerte (None)."""
    url: str
    source: str = ''
    client: object = None
    store: object = None           # AuthRecipeStore (persistance DSL)
    host: str = ''
    _derived: Optional[NonceStrategy] = field(default=None, init=False)

    def fetch(self, send, base_url):
        if self._derived is None:
            if self.client is None:
                return None
            sample = send('GET', urljoin(base_url, self.url)) or {}
            spec = _ai_derive_extraction(self.client, kind='nonce', url=self.url,
                                         source=self.source, sample=sample)
            if spec is not None:
                if self.store is not None and self.host:
                    self.store.record_slot(self.host, 'nonce', spec)   # mémoire persistante
                self._derived = _build(NONCE_STRATEGIES, spec) or _NULL_NONCE
            else:
                self._derived = _NULL_NONCE
        return self._derived.fetch(send, base_url)


class _NullNonce(NonceStrategy):
    def fetch(self, send, base_url):
        return None


_NULL_NONCE = _NullNonce()


# =============================================================================
# Stratégies : capture de SESSION après login
# =============================================================================
class SessionStrategy:
    def capture(self, resp: Dict, store: SessionStore):
        raise NotImplementedError


@dataclass
class CookieSession(SessionStrategy):
    """La session revient en Set-Cookie (cas le plus courant)."""
    names: Optional[List[str]] = None

    def capture(self, resp, store):
        cookies = _resp_cookies(resp)
        if self.names:
            cookies = {k: v for k, v in cookies.items() if k in self.names}
        store.merge_cookies(cookies)
        ttl = _cookie_ttl(resp)
        if ttl:
            store.expires_at = ttl


@dataclass
class JsonSession(SessionStrategy):
    """Le jeton revient dans le corps JSON → injecté en en-tête (Bearer par déf.)."""
    path: str
    header: str = 'Authorization'
    scheme: str = 'Bearer '

    def capture(self, resp, store):
        try:
            tok = _dotted(json.loads(resp.get('body', '') or 'null'), self.path)
        except Exception:
            tok = None
        if tok:
            store.headers[self.header] = f'{self.scheme}{tok}'
            exp = _jwt_exp(str(tok))
            if exp:
                store.expires_at = exp


@dataclass
class HeaderSession(SessionStrategy):
    """Le jeton revient dans un en-tête de réponse."""
    resp_header: str
    inject_header: Optional[str] = None

    def capture(self, resp, store):
        val = (resp.get('headers') or {}).get(self.resp_header)
        if val:
            store.headers[self.inject_header or self.resp_header] = val


@dataclass
class AiSession(SessionStrategy):
    """L'IA déduit du code source comment la session est rendue et produit une
    spec concrète (cookie/json/header), exécutée déterministiquement, cachée ET
    persistée dans le DSL (store) → plus d'appel IA ensuite."""
    source: str = ''
    client: object = None
    store: object = None           # AuthRecipeStore (persistance DSL)
    host: str = ''
    _derived: Optional[SessionStrategy] = field(default=None, init=False)

    def capture(self, resp, store):
        if self._derived is None:
            if self.client is None:
                return
            spec = _ai_derive_extraction(self.client, kind='session', url='',
                                         source=self.source, sample=resp)
            if spec is not None:
                if self.store is not None and self.host:
                    self.store.record_slot(self.host, 'session', spec)  # mémoire persistante
                self._derived = _build(SESSION_STRATEGIES, spec) or _NULL_SESSION
            else:
                self._derived = _NULL_SESSION
        self._derived.capture(resp, store)


class _NullSession(SessionStrategy):
    def capture(self, resp, store):
        return


_NULL_SESSION = _NullSession()


# =============================================================================
# Stratégies : ROTATION (le matériel « renew » à chaque réponse)
# =============================================================================
class RotationStrategy:
    def apply(self, resp: Dict, store: SessionStore):
        raise NotImplementedError


@dataclass
class RotatingCookie(RotationStrategy):
    """Nouveau Set-Cookie à chaque réponse → on met le store à jour en continu."""
    def apply(self, resp, store):
        cookies = _resp_cookies(resp)
        if cookies:
            store.merge_cookies(cookies)
            ttl = _cookie_ttl(resp)
            if ttl:
                store.expires_at = ttl


@dataclass
class RotatingHeader(RotationStrategy):
    """Un en-tête de réponse rotatif porte le nouveau jeton à réinjecter."""
    resp_header: str
    inject_header: Optional[str] = None

    def apply(self, resp, store):
        val = (resp.get('headers') or {}).get(self.resp_header)
        if val:
            store.headers[self.inject_header or self.resp_header] = val


class NoRotation(RotationStrategy):
    def apply(self, resp, store):
        return


# =============================================================================
# Stratégies : EXPIRATION (réactive / proactive TTL / négociée IA)
# =============================================================================
class ExpiryStrategy:
    def expired(self, resp: Optional[Dict], store: SessionStore) -> bool:
        raise NotImplementedError


@dataclass
class RedirectExpiry(ExpiryStrategy):
    """Réactif : 401/403, ou redirection vers la page de login."""
    login_path: str = '/login'

    def expired(self, resp, store):
        if not resp:
            return False
        status = int(resp.get('status', 0) or 0)
        if status in (401, 403):
            return True
        if 300 <= status < 400:
            loc = (resp.get('location', '') or
                   (resp.get('headers') or {}).get('Location', '') or '')
            return self.login_path in loc
        return False


@dataclass
class CookieTtlExpiry(ExpiryStrategy):
    """Proactif : la durée est PORTÉE par le cookie/JWT (Max-Age/Expires/exp). On
    renouvelle AVANT la mort, avec une marge (skew)."""
    skew: float = 30.0

    def expired(self, resp, store):
        if store.expires_at is None:
            return False
        return time.time() + self.skew >= store.expires_at


@dataclass
class AiExpiry(ExpiryStrategy):
    """Négocié : l'IA juge, à partir de la réponse, si la session est morte /
    expirante (corps ambigu, message applicatif, code custom). Sans client →
    jamais expiré (pas de re-auth intempestive)."""
    client: object = None

    def expired(self, resp, store):
        if not resp or self.client is None:
            return False
        return _ai_session_dead(self.client, resp)


@dataclass
class CompositeExpiry(ExpiryStrategy):
    """OR de plusieurs stratégies : proactif TTL + réactif redirection + IA."""
    strategies: List[ExpiryStrategy] = field(default_factory=list)

    def expired(self, resp, store):
        return any(s.expired(resp, store) for s in self.strategies)


# =============================================================================
# Registres (enfichabilité par nom, depuis la config)
# =============================================================================
NONCE_STRATEGIES = {'regex': RegexNonce, 'json': JsonNonce, 'cookie': CookieNonce, 'ai': AiNonce}
SESSION_STRATEGIES = {'cookie': CookieSession, 'json': JsonSession, 'header': HeaderSession, 'ai': AiSession}
ROTATION_STRATEGIES = {'cookie': RotatingCookie, 'header': RotatingHeader, 'none': NoRotation}
EXPIRY_STRATEGIES = {'redirect': RedirectExpiry, 'cookie_ttl': CookieTtlExpiry, 'ai': AiExpiry}
_REG = {'nonce': NONCE_STRATEGIES, 'session': SESSION_STRATEGIES}


def _build(registry: Dict, spec, client=None, source=''):
    """Instancie une stratégie depuis {strategy: name, ...params} ; injecte
    `client`/`source` aux variantes IA."""
    if spec is None:
        return None
    name = spec.get('strategy')
    cls = registry.get(name)
    if cls is None:
        raise ValueError(f"unknown strategy '{name}' (choices: {sorted(registry)})")
    params = {k: v for k, v in spec.items() if k != 'strategy'}
    if name == 'ai':
        fields = getattr(cls, '__dataclass_fields__', {})
        if 'client' in fields:
            params.setdefault('client', client)
        if 'source' in fields:              # nonce/session en ont un ; expiry non
            params.setdefault('source', source)
    return cls(**params)


# =============================================================================
# Orchestrateur
# =============================================================================
@dataclass
class LoginRecipe:
    login_url: str
    method: str = 'POST'
    credentials: Dict[str, str] = field(default_factory=dict)  # champ->valeur
    nonce_field: Optional[str] = None                          # nom du champ nonce
    nonce: Optional[NonceStrategy] = None
    session: Optional[SessionStrategy] = None


class ReAuthenticator:
    """Login nonce-aware + suivi de rotation + re-auth sur expiration. `wrap(send)`
    rend un exécuteur session-aware branché tel quel dans les moteurs."""

    def __init__(self, recipe: LoginRecipe, rotation: RotationStrategy,
                 expiry: ExpiryStrategy, base_url: str = '',
                 store: Optional[SessionStore] = None, max_retries: int = 1):
        self.recipe = recipe
        self.rotation = rotation
        self.expiry = expiry
        self.base_url = base_url
        self.store = store or SessionStore()
        self.max_retries = max_retries

    def login(self, send: SendFn) -> bool:
        r = self.recipe
        body = dict(r.credentials)
        if r.nonce is not None and r.nonce_field:
            n = r.nonce.fetch(send, self.base_url)
            if n is None:
                logger.warning("reauth_nonce_missing")
                return False
            body[r.nonce_field] = n
        resp = send(r.method, urljoin(self.base_url, r.login_url), None, body) or {}
        if not (200 <= int(resp.get('status', 0) or 0) < 400):
            logger.warning("reauth_login_failed", status=resp.get('status'))
            return False
        if r.session is not None:
            r.session.capture(resp, self.store)
        # même si la session revient en Set-Cookie sans SessionStrategy explicite :
        self.rotation.apply(resp, self.store)
        logger.info("reauth_login_ok", established=self.store.established)
        return self.store.established

    def wrap(self, send: SendFn) -> SendFn:
        def session_send(method, url, headers=None, body=None):
            if not self.store.established:
                self.login(send)
            # Proactif : renouveler avant expiration (TTL portée par le cookie/JWT).
            if self.expiry.expired(None, self.store):
                self.login(send)

            def _one():
                merged = {**self.store.auth_headers(), **(headers or {})}
                resp = send(method, url, merged, body) or {}
                self.rotation.apply(resp, self.store)
                return resp

            resp = _one()
            # Réactif : la réponse dit que la session est morte → re-login + retry.
            tries = 0
            while self.expiry.expired(resp, self.store) and tries < self.max_retries:
                tries += 1
                if self.login(send):
                    resp = _one()
                else:
                    break
            return resp
        return session_send

    @classmethod
    def from_config(cls, config: Dict, client=None) -> Optional['ReAuthenticator']:
        """Construit depuis config['reauth'] ; None si absent. Schéma :

        reauth:
          base_url: https://app
          login: { url: /login, method: POST, credentials: {username: u, password: p},
                   nonce_field: csrf }
          nonce:    { strategy: ai|regex|json|cookie, ... }
          session:  { strategy: ai|cookie|json|header, ... }
          rotation: { strategy: cookie|header|none, ... }
          expiry:   { strategies: [ {strategy: cookie_ttl}, {strategy: redirect, login_path: /login},
                                    {strategy: ai} ] }
          source: "<extrait du code du handler de login, pour les stratégies ai>"
        """
        rc = (config or {}).get('reauth')
        if not rc:
            return None
        source = rc.get('source', '')
        login = rc.get('login', {})
        base_url = rc.get('base_url', '')

        # Mémoire DSL : une recette déjà découverte remplace la stratégie 'ai'
        # (plus aucun appel modèle). Les slots 'ai' non encore résolus reçoivent
        # le store pour écrire leur découverte au premier login.
        from urllib.parse import urlparse as _up
        host = _up(base_url).netloc or base_url
        store = None
        recipe_file = rc.get('recipe_file')
        if recipe_file:
            from .auth_dsl import AuthRecipeStore
            store = AuthRecipeStore(recipe_file)

        def _slot(name):
            spec = rc.get(name)
            # Déjà mémorisé concrètement ? on l'utilise, l'IA est court-circuitée.
            if store is not None and store.has_slot(host, name):
                return _build(_REG[name], store.get(host)[name])
            # Sinon on construit (peut être 'ai') en passant store+host pour l'écriture.
            reg = _REG[name]
            if spec and spec.get('strategy') == 'ai':
                built = spec.copy()
                s = _build(reg, built, client, source)
                if s is not None and store is not None:
                    s.store, s.host = store, host
                return s
            return _build(reg, spec, client, source)

        recipe = LoginRecipe(
            login_url=login.get('url', '/login'),
            method=login.get('method', 'POST'),
            credentials=login.get('credentials', {}),
            nonce_field=login.get('nonce_field'),
            nonce=_slot('nonce'),
            session=_slot('session'),
        )
        rotation = _build(ROTATION_STRATEGIES, rc.get('rotation')) or RotatingCookie()
        exp_spec = rc.get('expiry') or {}
        if 'strategies' in exp_spec:
            expiry = CompositeExpiry([_build(EXPIRY_STRATEGIES, s, client)
                                      for s in exp_spec['strategies']])
        else:
            expiry = _build(EXPIRY_STRATEGIES, exp_spec, client) or RedirectExpiry()
        return cls(recipe, rotation, expiry, base_url=base_url)


# =============================================================================
# Ponts IA (proposent une spec / une décision ; jamais d'exécution directe)
# =============================================================================
def _ai_derive_extraction(client, kind: str, url: str, source: str, sample: Dict):
    """Demande à l'IA UNE spec d'extraction concrète (dict {strategy, ...}) à
    partir du code source et d'un échantillon de réponse. Le dict est validable,
    persistable dans le DSL, et instanciable par _build. `kind` ∈ {'nonce','session'}."""
    reg = NONCE_STRATEGIES if kind == 'nonce' else SESSION_STRATEGIES
    body = (sample.get('body', '') or '')[:1500]
    headers = sample.get('headers') or {}
    system = ("You map an app's login mechanism to a concrete extraction spec. "
              "Return ONLY compact JSON. For a NONCE choose one of: "
              '{"strategy":"regex","url":"...","pattern":"...","group":1} | '
              '{"strategy":"json","url":"...","path":"a.b"} | '
              '{"strategy":"cookie","url":"...","cookie":"NAME"}. '
              "For a SESSION choose one of: "
              '{"strategy":"cookie","names":["sid"]} | '
              '{"strategy":"json","path":"token","header":"Authorization","scheme":"Bearer "} | '
              '{"strategy":"header","resp_header":"X-Token","inject_header":"Authorization"}. '
              "No prose.")
    user = (f"kind={kind}\nlogin url={url}\n\nSOURCE (login handler):\n{source[:2500]}\n\n"
            f"SAMPLE response headers:\n{json.dumps(dict(list(headers.items())[:20]))}\n\n"
            f"SAMPLE response body (truncated):\n{body}")
    try:
        resp = client.complete(user, system=system)
        spec = _first_json(getattr(resp, 'content', '') or '')
    except Exception as e:
        logger.warning("ai_derive_failed", kind=kind, error=str(e))
        return None
    if not isinstance(spec, dict) or spec.get('strategy') not in reg:
        return None
    try:
        _build(reg, spec)                # valide que la spec est instanciable
    except Exception as e:
        logger.warning("ai_derive_bad_spec", kind=kind, error=str(e), spec=spec)
        return None
    return spec


def _ai_session_dead(client, resp: Dict) -> bool:
    """L'IA juge si la réponse traduit une session morte/expirée (négociation)."""
    body = (resp.get('body', '') or '')[:800]
    system = ("Given an HTTP response, decide if it indicates an EXPIRED or INVALID "
              'session (needs re-login). Return ONLY {"expired": true|false}.')
    user = f"status={resp.get('status')}\nbody:\n{body}"
    try:
        r = client.complete(user, system=system)
        spec = _first_json(getattr(r, 'content', '') or '')
        return bool(isinstance(spec, dict) and spec.get('expired'))
    except Exception:
        return False


def _first_json(text: str):
    m = re.search(r'\{.*\}', text or '', re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None
