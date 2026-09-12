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

    def flat(self) -> Dict:
        return {'source': f'probe_{self.category.lower()}', 'risk': self.severity,
                'name': self.title, 'url': self.url}


# =============================================================================
# API4 — Unrestricted Resource Consumption (rate limiting)
# =============================================================================
def probe_rate_limit(execute_fn: Callable[[str, str], Dict], url: str,
                     method: str = 'GET', burst: int = 20) -> Optional[ProbeFinding]:
    """Tire `burst` requêtes ; absence totale de throttling (429/503) = API4.

    Déterministe : on compte les statuts, aucun modèle.
    """
    statuses = []
    for _ in range(burst):
        r = execute_fn(url, method) or {}
        statuses.append(int(r.get('status', 0)))
    throttled = sum(1 for s in statuses if s in (429, 503))
    ok = sum(1 for s in statuses if 200 <= s < 300)
    if ok >= burst and throttled == 0:
        return ProbeFinding('API4', 'Medium', 'No rate limiting observed', url,
                            f"{burst}/{burst} requests succeeded, 0 throttled")
    return None


# =============================================================================
# API7 — Server-Side Request Forgery
# =============================================================================
def probe_ssrf(execute_fn: Callable[[str, str], Dict], targets: List[Dict],
               adjudicator=None) -> List[ProbeFinding]:
    """Injecte des URLs internes dans les paramètres url-ish. Détection par
    marqueurs (déterministe) ; l'adjudicateur LLM optionnel tranche l'ambigu."""
    findings: List[ProbeFinding] = []
    for t in targets:
        url, method = t.get('url', ''), t.get('method', 'GET')
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        urlish = [p for p in params if _URLISH_PARAM.search(p)]
        for param in urlish:
            for payload in _SSRF_PAYLOADS:
                q = dict(params)
                q[param] = [payload]
                probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                        parsed.params, urlencode(q, doseq=True), parsed.fragment))
                r = execute_fn(probe_url, method) or {}
                body = (r.get('body', '') or '')
                if any(m in body for m in _SSRF_MARKERS):
                    findings.append(ProbeFinding('API7', 'Critical',
                        f"SSRF via '{param}' — internal resource reflected",
                        probe_url, f"payload {payload}"))
                    break  # un hit suffit pour ce paramètre
                elif adjudicator is not None and getattr(adjudicator, 'available', False):
                    v = adjudicator.classify_owasp(
                        {'alert': f'Possible SSRF via {param}={payload}',
                         'url': probe_url}, {'API7:2023': 'SSRF'})
                    if v:
                        findings.append(ProbeFinding('API7', 'High',
                            f"SSRF suspected via '{param}' (LLM-adjudicated)",
                            probe_url, v.get('reason', '')))
                        break
    return findings


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
