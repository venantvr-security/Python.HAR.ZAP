"""
Extrapolation de routes — deviner la surface NON observée.

Un HAR ne capture que ce que l'utilisateur a cliqué. Un pentester, lui, extrapole :
« j'ai vu `GET /users/v1/{id}`, il existe sûrement un `DELETE`… j'ai vu
`/users/v1`, tentons `/users/v1/_debug`, `/admin`, `/export`… ». C'est ce
raisonnement qu'on confie ICI au LLM : à partir des routes observées, il PROPOSE
des routes plausibles mais absentes du HAR (endpoints cachés/non documentés).

Discipline du projet :
- L'IA PROPOSE des candidats (jugement : conventions de nommage, endpoints
  sensibles typiques du domaine). Repli déterministe si pas de modèle : expansion
  structurelle (verbes CRUD manquants, suffixes sensibles connus).
- Le CODE DISPOSE : les candidats ne sont que des HYPOTHÈSES. On les SONDE
  (méthodes sûres uniquement) ; seuls ceux qui répondent autre chose que
  404/405 sont retenus comme réels → alimente l'inventaire (shadow endpoints,
  API9) et la surface BOLA.
- Aucune méthode destructive n'est sondée automatiquement (POST/PUT/PATCH/DELETE
  restent des candidats non sondés, à valider par un humain).
"""
import json
import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse, urlunparse

from ..utils import get_logger
from .adaptive_idor import _extract_json

logger = get_logger("llm.route_extrapolator")

SendFn = Callable[..., Dict]

# Suffixes sensibles/administratifs fréquents à tenter sur chaque ressource.
_SENSITIVE_SUFFIXES = ('_debug', 'debug', 'admin', 'export', 'all', 'dump',
                       'config', 'internal', 'backup', 'search')
# Seules ces méthodes sont sondées automatiquement (idempotentes / sans effet).
_SAFE_METHODS = ('GET', 'HEAD', 'OPTIONS')
_PARAM_RE = re.compile(r'^\{.+\}$')


@dataclass
class CandidateRoute:
    method: str
    path: str
    rationale: str = ""
    source: str = "offline"
    risk: str = "medium"
    status: Optional[int] = None       # rempli après sondage
    exists: Optional[bool] = None

    def to_dict(self) -> Dict:
        return {'method': self.method, 'path': self.path, 'rationale': self.rationale,
                'source': self.source, 'risk': self.risk,
                'status': self.status, 'exists': self.exists}


def extrapolate_routes(model, client=None, max_candidates: int = 40) -> List[CandidateRoute]:
    """Propose des routes plausibles absentes du HAR. LLM en priorité, sinon
    heuristique structurelle. Dédupliqué contre les routes déjà observées."""
    observed = {(r.method, r.path_template) for r in model.routes.values()}
    candidates: List[CandidateRoute] = []
    if client is not None:
        candidates = _extrapolate_llm(model, client) or []
    if not candidates:
        candidates = _extrapolate_offline(model)

    # Dédup contre l'observé et entre candidats.
    seen = set(observed)
    uniq: List[CandidateRoute] = []
    for c in candidates:
        key = (c.method.upper(), c.path)
        if key in seen:
            continue
        seen.add(key)
        uniq.append(c)
    logger.info("routes_extrapolated", count=len(uniq),
                source=uniq[0].source if uniq else "none")
    return uniq[:max_candidates]


def _extrapolate_offline(model) -> List[CandidateRoute]:
    """Expansion structurelle : verbes CRUD manquants + suffixes sensibles."""
    out: List[CandidateRoute] = []
    by_resource: Dict[str, List] = {}
    for r in model.routes.values():
        by_resource.setdefault(r.resource, []).append(r)

    for resource, routes in by_resource.items():
        methods_seen = {(r.method, r.path_template) for r in routes}
        # Un chemin de collection de la ressource (le plus court sans param).
        collections = sorted(
            {r.path_template for r in routes if not r.id_params},
            key=len)
        item_paths = {r.path_template for r in routes if r.id_params}

        base = collections[0] if collections else (routes[0].path_template if routes else None)
        if not base:
            continue

        # Verbes CRUD manquants sur l'item.
        for ip in item_paths:
            for m in ('GET', 'PUT', 'PATCH', 'DELETE'):
                if (m, ip) not in methods_seen:
                    out.append(CandidateRoute(m, ip, "CRUD manquant sur l'objet",
                                              "offline", "high" if m == 'DELETE' else "medium"))
        # Création sur la collection si jamais vue.
        if not any(m == 'POST' for (m, _p) in methods_seen):
            out.append(CandidateRoute('POST', base, "création non observée", "offline"))

        # Suffixes sensibles sur la collection.
        for suf in _SENSITIVE_SUFFIXES:
            out.append(CandidateRoute('GET', f"{base.rstrip('/')}/{suf}",
                                      f"endpoint sensible probable ({suf})",
                                      "offline", "high"))
    return out


def _extrapolate_llm(model, client) -> Optional[List[CandidateRoute]]:
    observed = sorted({r.template for r in model.routes.values()})
    resources = sorted({r.resource for r in model.routes.values()})
    prompt = (
        "You are mapping a REST API from partial traffic. Given the OBSERVED routes, "
        "propose likely-existing but UNOBSERVED routes an attacker should probe "
        "(hidden/undocumented endpoints, missing CRUD verbs, admin/debug/export "
        "variants) based on naming conventions and the business domain.\n"
        f"Resources: {resources}\n"
        f"Observed routes:\n" + "\n".join(f"  {t}" for t in observed) + "\n"
        'Return a JSON list of {"method": str, "path": str (concrete path, use '
        '{id} for identifiers), "why": str, "risk": "low|medium|high"}. '
        "Do not repeat observed routes. Max 25."
    )
    try:
        resp = client.complete(
            prompt, system="You are a web pentester. Answer only with the JSON list.")
        data = _extract_json(getattr(resp, 'content', None))
    except Exception as e:
        logger.warning("extrapolate_llm_failed", error=str(e))
        return None
    if not isinstance(data, list):
        return None
    out: List[CandidateRoute] = []
    for it in data:
        if isinstance(it, dict) and it.get('path'):
            out.append(CandidateRoute(
                method=str(it.get('method', 'GET')).upper(), path=str(it['path']),
                rationale=str(it.get('why', '')), source="llm",
                risk=str(it.get('risk', 'medium'))))
    return out


def _concretize(path: str) -> str:
    """Remplace les segments paramétrés par un id neutre."""
    return '/'.join('1' if _PARAM_RE.match(s) else s for s in path.split('/'))


def _top_keys(body: str):
    """Ensemble des clés de premier niveau d'un corps JSON objet, ou None."""
    try:
        data = json.loads(body or 'null')
    except (ValueError, TypeError):
        return None
    return frozenset(data.keys()) if isinstance(data, dict) else None


def probe_candidates(send: SendFn, base_url: str, candidates: List[CandidateRoute],
                     headers: Optional[Dict] = None,
                     item_keys: Optional[frozenset] = None) -> List[CandidateRoute]:
    """Sonde les candidats par des requêtes SÛRES et retient ceux qui existent
    VRAIMENT, en neutralisant DEUX pièges du catch-all `/{id}`.

    Piège 1 (statut) : `/books/v1/_debug` frappe la route `/{id}` (« _debug » = un
    id inexistant) et renvoie le même code que n'importe quel id (souvent 401/404).
    Parade : une SONDE DE CONTRÔLE (segment aléatoire) donne le comportement du
    catch-all ; on ne garde un candidat que si son statut DIFFÈRE (et ≠ 404/405/501/0).

    Piège 2 (id existant) : un mot deviné qui EST un id réel (`/users/v1/admin` où
    `admin` est un username) renvoie 200 alors que le contrôle aléatoire renvoie
    404 → faux positif. Parade : si `item_keys` (les clés du schéma d'item, du
    modèle sémantique) est fourni, un candidat 2xx dont le corps a EXACTEMENT ce
    schéma est un simple item, pas une route distincte → écarté.

    Les méthodes non sûres ne sont jamais émises (on ne mute pas en devinant) →
    elles restent non sondées (`exists=None`).
    """
    import uuid
    parsed = urlparse(base_url)
    control_cache: Dict[tuple, int] = {}

    def _probe(method: str, path: str):
        url = urlunparse((parsed.scheme, parsed.netloc, _concretize(path), '', '', ''))
        r = send(method, url, headers=headers) or {}
        return int(r.get('status', 0) or 0), (r.get('body', '') or '')

    def _control_status(method: str, path: str) -> int:
        parts = path.rstrip('/').split('/')
        base = '/'.join(parts[:-1]) or '/'
        key = (method, base)
        if key not in control_cache:
            control_cache[key] = _probe(method, f"{base}/zz{uuid.uuid4().hex[:8]}")[0]
        return control_cache[key]

    confirmed: List[CandidateRoute] = []
    for c in candidates:
        if c.method.upper() not in _SAFE_METHODS:
            continue
        c.status, body = _probe(c.method, c.path)
        control = _control_status(c.method, c.path)
        distinct = c.status not in (0, 404, 405, 501) and c.status != control
        # Un 2xx au schéma d'item = id existant sur la route /{id}, pas une route.
        looks_like_item = (item_keys is not None and 200 <= c.status < 300
                           and _top_keys(body) == item_keys)
        c.exists = distinct and not looks_like_item
        if c.exists:
            confirmed.append(c)
            logger.info("shadow_route_confirmed", method=c.method, path=c.path,
                        status=c.status, control=control, source=c.source)
    return confirmed
