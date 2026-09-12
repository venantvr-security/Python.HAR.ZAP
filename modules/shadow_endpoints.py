"""
Détection d'endpoints fantômes (OWASP API9 — Improper Inventory Management).

Compare le trafic réel (HAR) à la spec OpenAPI : un endpoint présent dans le
trafic mais absent de la spec est un « endpoint fantôme » (shadow) — souvent une
route de debug, une ancienne version, ou une API interne oubliée.

IA : le diff est 100% déterministe (différence d'ensembles) — aucune raison d'y
mettre un modèle. L'IA n'intervient QUE pour juger si un endpoint fantôme paraît
sensible (jugement), via un classifieur optionnel ; sinon une heuristique par
mots-clés prend le relais.
"""
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

from .regression_gate import endpoint_template

_SENSITIVE_HINTS = ('admin', 'debug', 'internal', 'test', 'dev', 'token', 'secret',
                    'config', 'backup', 'export', 'sql', 'root', 'private', 'v0',
                    'legacy', 'deprecated', 'actuator', 'swagger', 'graphql')


@dataclass
class ShadowFinding:
    endpoint: str          # « METHOD /path/{id} »
    url: str
    sensitive: bool = False
    reason: str = ''
    source_tag: str = 'shadow_endpoint'

    @property
    def severity(self) -> str:
        return 'High' if self.sensitive else 'Low'


def _har_endpoints(har_data: Dict) -> Dict[str, str]:
    """Gabarit -> url échantillon, depuis le HAR."""
    out: Dict[str, str] = {}
    for e in (har_data or {}).get('log', {}).get('entries', []) or []:
        req = e.get('request', {})
        url, method = req.get('url', ''), req.get('method', 'GET').upper()
        if url:
            out.setdefault(f"{method} {endpoint_template(url)}", url)
    return out


def _spec_templates(spec_endpoints: List[Dict]) -> Set[str]:
    """Gabarits « METHOD /path/{id} » depuis les endpoints OpenAPI parsés."""
    out = set()
    for ep in spec_endpoints or []:
        method = str(ep.get('method', 'GET')).upper()
        path = ep.get('path', '')
        # Normalise les {param} de la spec vers le même gabarit {id} que le HAR
        # (on remplace par un jeton numérique, que endpoint_template réduit en {id}).
        tpl = endpoint_template(re.sub(r'\{[^/}]+\}', '1', path))
        out.add(f"{method} {tpl}")
    return out


def find_shadow_endpoints(har_data: Dict, spec_endpoints: List[Dict],
                          classifier=None) -> List[ShadowFinding]:
    """Endpoints en trafic absents de la spec. `classifier` (optionnel) juge la
    sensibilité via LLM ; sinon heuristique par mots-clés."""
    documented = _spec_templates(spec_endpoints)
    findings: List[ShadowFinding] = []
    for tpl, url in _har_endpoints(har_data).items():
        if tpl in documented:
            continue
        low = tpl.lower()
        hit = next((h for h in _SENSITIVE_HINTS if h in low), None)
        sensitive, reason = (bool(hit), f"keyword '{hit}'" if hit else '')
        if classifier is not None and getattr(classifier, 'available', False):
            verdict = classifier.classify_owasp(
                {'alert': f'Undocumented endpoint {tpl}', 'url': url},
                {'API9:2023': 'Improper Inventory Management'})
            if verdict:
                sensitive, reason = True, verdict.get('reason', 'LLM: sensitive')
        findings.append(ShadowFinding(tpl, url, sensitive, reason))
    findings.sort(key=lambda f: (not f.sensitive, f.endpoint))
    return findings


def shadow_findings_flat(findings: List[ShadowFinding]) -> List[Dict]:
    """Format « à plat » pour la sortie findings-first et la gate."""
    return [{'source': 'shadow_endpoint', 'risk': f.severity,
             'name': f"Undocumented endpoint {f.endpoint}"
                     + (f" ({f.reason})" if f.reason else ''),
             'url': f.url} for f in findings]
