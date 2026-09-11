"""
Campagne adaptative — orchestre les boucles adaptatives sur les cibles extraites
d'un HAR, puis enrichit les patterns payloads (PatternStore + export ZAP).

Un seul point d'entrée pour la commande `diagnose` : on lui fournit deux
exécuteurs HTTP réels (un GET url->réponse, un WRITE url+payload->réponse) et il
lance IDOR / Mass Assignment / Hidden Params en boucle fermée, puis flush le
vocabulaire découvert. Les exécuteurs sont injectés => testable hors-ligne.
"""
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

from ..utils import get_logger
from .adaptive_idor import AdaptiveIDORLoop
from .adaptive_mass_assignment import AdaptiveMassAssignmentLoop
from .adaptive_hidden_params import AdaptiveHiddenParamsLoop

logger = get_logger("llm.adaptive_campaign")

# http_get(url, method) -> {'status','content_length','body'}
# http_write(url, method, payload_dict) -> {'status','body'}
HttpGet = Callable[[str, str], Dict]
HttpWrite = Callable[[str, str, Dict], Dict]

_ID_PARAM_HINTS = ('id', 'user', 'account', 'order', 'invoice', 'uuid', 'key', 'ref')
_WRITE_METHODS = ('POST', 'PUT', 'PATCH')


@dataclass
class CampaignResult:
    idor: List = field(default_factory=list)
    mass_assignment: List = field(default_factory=list)
    hidden_params: List = field(default_factory=list)
    enriched: Dict[str, int] = field(default_factory=dict)
    exported: Dict[str, str] = field(default_factory=dict)

    def summary(self) -> Dict:
        return {
            'idor_vulnerable': sum(1 for f in self.idor if f.vulnerable),
            'mass_assignment_vulnerable': sum(1 for f in self.mass_assignment if f.vulnerable),
            'hidden_params_vulnerable': sum(1 for f in self.hidden_params if f.vulnerable),
            'patterns_enriched': self.enriched,
            'zap_exported': list(self.exported.keys()),
        }


def _entries(har_data: Dict) -> List[Dict]:
    return (har_data or {}).get('log', {}).get('entries', []) or []


def id_targets(har_data: Dict, limit: int = 15) -> List[Dict]:
    """Endpoints porteurs d'un identifiant énumérable (segment de chemin numérique
    ou paramètre de requête id-like à valeur numérique)."""
    out, seen = [], set()
    for e in _entries(har_data):
        req = e.get('request', {})
        url, method = req.get('url', ''), req.get('method', 'GET')
        # IDOR est un test d'accès en lecture : n'énumérer que les endpoints GET/HEAD.
        if method.upper() not in ('GET', 'HEAD'):
            continue
        parsed = urlparse(url)
        # Segment de chemin numérique
        for seg in parsed.path.split('/'):
            if seg.isdigit():
                key = (method, parsed.path)
                if key not in seen:
                    seen.add(key)
                    out.append({'url': url, 'method': method, 'original_value': seg})
                break
        # Paramètre de requête id-like
        for name, vals in parse_qs(parsed.query).items():
            if any(h in name.lower() for h in _ID_PARAM_HINTS) and vals and vals[0].isdigit():
                key = (method, parsed.path, name)
                if key not in seen:
                    seen.add(key)
                    out.append({'url': url, 'method': method,
                                'param': name, 'original_value': vals[0]})
                break
        if len(out) >= limit:
            break
    return out


def mutation_targets(har_data: Dict, limit: int = 15) -> List[Dict]:
    """Endpoints d'écriture (POST/PUT/PATCH) — cibles d'affectation de masse."""
    out, seen = [], set()
    for e in _entries(har_data):
        req = e.get('request', {})
        method = req.get('method', 'GET').upper()
        if method in _WRITE_METHODS:
            parsed = urlparse(req.get('url', ''))
            key = (method, parsed.path)
            if key not in seen:
                seen.add(key)
                out.append({'url': req.get('url', ''), 'method': method})
        if len(out) >= limit:
            break
    return out


def get_targets(har_data: Dict, limit: int = 15) -> List[Dict]:
    """Endpoints GET — cibles de paramètres cachés."""
    out, seen = [], set()
    for e in _entries(har_data):
        req = e.get('request', {})
        if req.get('method', 'GET').upper() == 'GET':
            parsed = urlparse(req.get('url', ''))
            key = parsed.path
            if key not in seen:
                seen.add(key)
                out.append({'url': req.get('url', ''), 'method': 'GET'})
        if len(out) >= limit:
            break
    return out


class AdaptiveCampaign:
    """Lance les boucles adaptatives et enrichit les patterns payloads."""

    def __init__(self, config: Optional[Dict] = None, client=None, enricher=None,
                 *, max_targets: int = 10, context: Optional[Dict] = None):
        self.config = config or {}
        self.client = client
        self.enricher = enricher
        self.max_targets = max_targets
        self.context = context or {}

    def run(self, har_data: Dict, http_get: HttpGet, http_write: HttpWrite) -> CampaignResult:
        result = CampaignResult()

        for t in id_targets(har_data, self.max_targets):
            result.idor.append(AdaptiveIDORLoop(http_get, self.client).run(t))

        for t in mutation_targets(har_data, self.max_targets):
            # L'exécuteur d'écriture est lié à la cible courante (URL + méthode).
            bound = lambda payload, _t=t: http_write(_t['url'], _t.get('method', 'POST'), payload)
            result.mass_assignment.append(
                AdaptiveMassAssignmentLoop(bound, self.client, context=self.context).run(t))

        for t in get_targets(har_data, self.max_targets):
            result.hidden_params.append(AdaptiveHiddenParamsLoop(http_get, self.client).run(t))

        if self.enricher is not None:
            result.enriched = {
                'idor': self.enricher.record_idor(result.idor),
                'mass_assignment': self.enricher.record_mass_assignment(result.mass_assignment),
                'hidden_params': self.enricher.record_hidden_params(result.hidden_params),
            }
            result.exported = self.enricher.flush()

        logger.info("adaptive_campaign_done", **result.summary())
        return result
