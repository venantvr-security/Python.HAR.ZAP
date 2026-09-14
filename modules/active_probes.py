"""
Sondes actives pour les risques API non couverts par les autres moteurs :
API4 (Unrestricted Resource Consumption), API7 (SSRF), API2 (Broken Authentication).

IA : les sondes sont déterministes par nature (compter les 429, injecter des URLs
internes connues, décoder un JWT). Le SEUL point de jugement est l'adjudication
d'une réponse SSRF ambiguë — confiée à un adjudicateur optionnel (LLM), sinon à
une heuristique de marqueurs. Le reste n'utilise pas de modèle : ce serait du
non-déterminisme injustifié.
"""
import base64
import json
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from .utils import get_logger

logger = get_logger("active.probes")

# --- API7 SSRF : cibles internes classiques + marqueurs de fuite ---
_SSRF_PAYLOADS = [
    'http://169.254.169.254/latest/meta-data/',   # AWS metadata
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://127.0.0.1:80/', 'http://localhost/', 'file:///etc/passwd',
]
_SSRF_MARKERS = ('ami-id', 'instance-id', 'computeMetadata', 'root:x:', 'meta-data',
                 'iam/security-credentials')
_URLISH_PARAM = re.compile(r'(url|uri|link|src|dest|target|callback|redirect|next|image|fetch|webhook)', re.I)


@dataclass
class ProbeFinding:
    category: str    # API4 / API7 / API2
    severity: str
    title: str
    url: str
    detail: str = ''
    source: str = 'deterministic'   # 'deterministic' (marqueur) | 'llm' (adjugé)
    confidence: float = 0.9
    payload: str = ''               # charge gagnante (pour l'enrichissement ZAP)

    def flat(self) -> Dict:
        v = self.verdict
        return {'source': f'probe_{self.category.lower()}', 'risk': self.severity,
                'name': self.title, 'url': self.url, 'payload': self.payload,
                'status': v.status, 'adjudication': v.source}

    @property
    def verdict(self):
        """Vocabulaire commun (modules.llm.investigation). Un marqueur non
        ambigu = CONFIRMED ; une adjudication LLM = SUSPECTED (à marquer)."""
        from .llm.investigation import Verdict, Evidence, CONFIRMED, SUSPECTED
        status = CONFIRMED if self.source == 'deterministic' else SUSPECTED
        return Verdict(status, self.detail or self.title, self.confidence, self.source,
                       Evidence(request=self.url, note=self.detail))


# =============================================================================
# API4 — Unrestricted Resource Consumption (rate limiting)
# =============================================================================
def probe_rate_limit(execute_fn: Callable[[str, str], Dict], url: str,
                     method: str = 'GET', burst: int = 20,
                     max_workers: int = 10) -> Optional[ProbeFinding]:
    """Tire `burst` requêtes EN PARALLÈLE ; absence totale de throttling (429/503)
    = API4. Le burst concurrent est à la fois plus réaliste (le throttling se
    déclenche sous charge simultanée) et bien plus rapide que du séquentiel.
    Déterministe : on compte les statuts, aucun modèle.
    """
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=min(max_workers, burst)) as ex:
        statuses = [int((r or {}).get('status', 0))
                    for r in ex.map(lambda _: execute_fn(url, method) or {}, range(burst))]
    throttled = sum(1 for s in statuses if s in (429, 503))
    ok = sum(1 for s in statuses if 200 <= s < 300)
    if ok >= burst and throttled == 0:
        return ProbeFinding('API4', 'Medium', 'No rate limiting observed', url,
                            f"{burst}/{burst} requests succeeded, 0 throttled")
    return None


# =============================================================================
# API7 — Server-Side Request Forgery
# =============================================================================
def _iter_urlish_in_body(obj, path=()):
    """Parcourt un corps JSON et rend (chemin, valeur) pour chaque feuille chaîne
    dont la CLÉ est url-ish — imbrication et listes comprises. Le point d'injection
    SSRF le plus courant (POST /media/fetch {"url": "..."}) vit dans le corps, pas
    dans la query : c'était l'angle mort de la sonde."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                yield from _iter_urlish_in_body(v, path + (k,))
            elif isinstance(v, str) and _URLISH_PARAM.search(str(k)):
                yield path + (k,), v
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _iter_urlish_in_body(v, path + (i,))


def _set_in(obj, path, value):
    """Copie profonde de `obj` avec la feuille `path` remplacée par `value`."""
    import copy
    new = copy.deepcopy(obj)
    cur = new
    for p in path[:-1]:
        cur = cur[p]
    cur[path[-1]] = value
    return new


def _call(execute_fn, url, method, body):
    """Appelle l'exécuteur en tolérant l'ancienne signature (url, method) : les
    exécuteurs qui savent poster un corps reçoivent `body`, les autres non."""
    try:
        return execute_fn(url, method, body) or {}
    except TypeError:
        return execute_fn(url, method) or {}


def _probe_point(execute_fn, method, mutate, label, adjudicator) -> Optional[ProbeFinding]:
    """Teste un point d'injection unique (query OU corps) : `mutate(payload)` rend
    le couple (url, body) à envoyer. Marqueur interne = CONFIRMED ; sinon
    l'adjudicateur LLM optionnel tranche l'ambigu (SUSPECTED)."""
    for payload in _SSRF_PAYLOADS:
        probe_url, probe_body = mutate(payload)
        r = _call(execute_fn, probe_url, method, probe_body)
        body = (r.get('body', '') or '')
        if any(m in body for m in _SSRF_MARKERS):
            return ProbeFinding('API7', 'Critical',
                f"SSRF via {label} — internal resource reflected",
                probe_url, f"payload {payload}", payload=payload)
        if adjudicator is not None and getattr(adjudicator, 'available', False):
            v = adjudicator.classify_owasp(
                {'alert': f'Possible SSRF via {label}={payload}', 'url': probe_url},
                {'API7:2023': 'SSRF'})
            if v:
                return ProbeFinding('API7', 'High',
                    f"SSRF suspected via {label} (LLM-adjudicated)",
                    probe_url, v.get('reason', ''), source='llm', confidence=0.6,
                    payload=payload)
    return None


def probe_ssrf(execute_fn: Callable, targets: List[Dict],
               adjudicator=None) -> List[ProbeFinding]:
    """Injecte des URLs internes dans les paramètres url-ish, en query STRING **et**
    dans le corps JSON (clé imbriquée comprise). Détection par marqueurs
    (déterministe) ; l'adjudicateur LLM optionnel tranche l'ambigu.

    `execute_fn(url, method, body=None)` : quand un corps est fourni, l'exécuteur
    doit le poster (JSON). Les exécuteurs à 2 arguments restent tolérés (cf. _call)."""
    findings: List[ProbeFinding] = []
    for t in targets:
        url, method = t.get('url', ''), t.get('method', 'GET')
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        # 1) Injection dans la query string.
        for param in [p for p in params if _URLISH_PARAM.search(p)]:
            def mutate(payload, _p=param, _params=params, _parsed=parsed):
                q = dict(_params)
                q[_p] = [payload]
                probe_url = urlunparse((_parsed.scheme, _parsed.netloc, _parsed.path,
                                        _parsed.params, urlencode(q, doseq=True),
                                        _parsed.fragment))
                return probe_url, None
            f = _probe_point(execute_fn, method, mutate, f"query '{param}'", adjudicator)
            if f:
                findings.append(f)

        # 2) Injection dans le corps JSON (POST/PUT/PATCH avec une clé url-ish).
        body = t.get('body')
        if isinstance(body, (dict, list)):
            for bpath, _ in _iter_urlish_in_body(body):
                label = "body '" + '.'.join(str(p) for p in bpath) + "'"

                def mutate(payload, _bp=bpath, _body=body, _url=url):
                    return _url, _set_in(_body, _bp, payload)
                f = _probe_point(execute_fn, method, mutate, label, adjudicator)
                if f:
                    findings.append(f)
    return findings


def ssrf_targets(har_data: Dict, limit: int = 12) -> List[Dict]:
    """Cibles SSRF extraites du HAR : toute requête dont un paramètre url-ish
    apparaît en query string OU dans le corps JSON. Contrairement à get_targets
    (GET seulement), inclut les écritures (POST/PUT/PATCH) et leur corps parsé."""
    out: List[Dict] = []
    seen = set()
    for e in (har_data or {}).get('log', {}).get('entries', []) or []:
        req = e.get('request', {})
        url = req.get('url', '')
        method = (req.get('method', 'GET') or 'GET').upper()
        parsed = urlparse(url)
        has_query_urlish = any(_URLISH_PARAM.search(p) for p in parse_qs(parsed.query))

        body = None
        text = (req.get('postData', {}) or {}).get('text', '')
        if text:
            try:
                parsed_body = json.loads(text)
                if any(True for _ in _iter_urlish_in_body(parsed_body)):
                    body = parsed_body
            except Exception:
                body = None

        if not has_query_urlish and body is None:
            continue
        key = (method, parsed.path)
        if key in seen:
            continue
        seen.add(key)
        out.append({'url': url, 'method': method, 'body': body})
        if len(out) >= limit:
            break
    return out


# =============================================================================
# API2 — Broken Authentication (checks statiques sur les tokens du HAR)
# =============================================================================
def _decode_jwt(token: str) -> Optional[Dict]:
    parts = token.split('.')
    if len(parts) != 3:
        return None
    try:
        header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
        return {'header': header, 'payload': payload}
    except Exception:
        return None


def probe_auth(har_data: Dict) -> List[ProbeFinding]:
    """Checks d'authentification statiques (déterministes, sans réseau) :
    token dans l'URL, JWT alg=none, JWT sans expiration."""
    findings: List[ProbeFinding] = []
    seen_tokens = set()
    for e in (har_data or {}).get('log', {}).get('entries', []) or []:
        req = e.get('request', {})
        url = req.get('url', '')
        # Token passé en clair dans l'URL (fuit dans les logs/historique/referer).
        for name, vals in parse_qs(urlparse(url).query).items():
            if name.lower() in ('token', 'access_token', 'api_key', 'apikey', 'auth', 'jwt'):
                findings.append(ProbeFinding('API2', 'High',
                    f"Credential in URL query ('{name}')", url,
                    'Tokens in URLs leak via logs, history and Referer'))
        # Analyse des JWT présents dans les en-têtes Authorization.
        for h in req.get('headers', []):
            if h.get('name', '').lower() == 'authorization':
                val = h.get('value', '')
                m = re.search(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', val)
                if not m or m.group(0) in seen_tokens:
                    continue
                seen_tokens.add(m.group(0))
                dec = _decode_jwt(m.group(0))
                if not dec:
                    continue
                alg = str(dec['header'].get('alg', '')).lower()
                if alg == 'none':
                    findings.append(ProbeFinding('API2', 'Critical',
                        'JWT accepts alg=none', url, 'Unsigned token accepted'))
                if 'exp' not in dec['payload']:
                    findings.append(ProbeFinding('API2', 'High',
                        'JWT without expiration (no exp claim)', url,
                        'Non-expiring tokens cannot be revoked by timeout'))
    return findings
