"""
Orchestrateur d'investigations — câble la couche de second ordre dans le CLI.

À partir d'un exécuteur HTTP unique (`send(method, url, headers=None,
json_body=None)`), construit le modèle sémantique partagé (APIModel) et lance :
  - extrapolation de routes + sondage sûr (endpoints cachés, API9) ;
  - confirmateur d'auth (forge alg=none/sans signature + rejeu, API2).

Chaque moteur rend des findings « à plat » ({source, risk, name, url, status,
adjudication}) directement consommables par la sortie findings-first et la gate.
Rien n'est affirmé sans preuve : les verdicts non confirmés sortent en
`status='suspected'`, les infirmés (REFUTED) ne sont pas remontés.

Le BOLA multi-sessions vit dans la commande `matrix` (qui a les sessions par
rôle), pas ici : `diagnose` ne dispose que d'une seule session.
"""
from typing import Callable, Dict, List, Optional

from .utils import get_logger
from .semantic.api_model import APIModel

logger = get_logger("investigations")

SendFn = Callable[..., Dict]


def _item_keys_by_resource(model: APIModel) -> Dict[str, frozenset]:
    """Schéma d'item (clés de réponse) par ressource — pour écarter les id
    existants pris pour des endpoints cachés.

    On ne peut pas se fier à `is_item` : un id non numérique (`/users/v1/bob`)
    n'est pas *templaté*, donc la route n'est pas classée « item ». Heuristique
    structurelle robuste : pour chaque ressource, la route GET la PLUS PROFONDE
    (plus de segments que la collection), non sensible et avec des clés de
    réponse, expose le schéma d'un objet unique."""
    out: Dict[str, frozenset] = {}
    by_res: Dict[str, list] = {}
    for r in model.routes.values():
        if r.method == 'GET':
            by_res.setdefault(r.resource, []).append(r)
    for resource, routes in by_res.items():
        depths = [r.path_template.count('/') for r in routes]
        if not depths:
            continue
        min_depth = min(depths)
        # Candidats item = GET plus profonds que la collection, non sensibles.
        items = [r for r in routes if r.path_template.count('/') > min_depth
                 and not r.sensitive and r.resp_keys]
        items.sort(key=lambda r: r.path_template.count('/'), reverse=True)
        if items:
            out[resource] = frozenset(items[0].resp_keys)
    return out


def run_shadow(model: APIModel, send: SendFn, base_url: str,
               headers: Optional[Dict] = None, client=None) -> List[Dict]:
    """Extrapole des routes non observées puis les sonde ; retient les réelles."""
    from .semantic.api_model import resource_of_path as _resource_of_path
    from .llm.route_extrapolator import (extrapolate_routes, probe_candidates)  # noqa
    candidates = extrapolate_routes(model, client=client)
    item_keys = _item_keys_by_resource(model)
    # Sondage par ressource, avec le bon schéma d'item.
    by_res: Dict[str, list] = {}
    for c in candidates:
        by_res.setdefault(_resource_of_path(c.path), []).append(c)
    confirmed = []
    for resource, cands in by_res.items():
        confirmed += probe_candidates(send, base_url, cands, headers=headers,
                                      item_keys=item_keys.get(resource))
    out = [{'source': 'shadow_endpoint', 'risk': 'Medium' if c.risk != 'high' else 'High',
            'name': f"Shadow/undocumented route reachable: {c.method} {c.path}",
            'url': c.path, 'status': 'confirmed', 'adjudication': c.source}
           for c in confirmed]
    if out:
        logger.info("shadow_routes", count=len(out))
    return out


def run_auth_forge(model: APIModel, token: Optional[str], send: SendFn) -> List[Dict]:
    """Forge alg=none/sans signature et rejoue sur les endpoints protégés."""
    if not token:
        return []
    from .llm.auth_confirmer import AuthConfirmer
    conf = AuthConfirmer(send, api_model=model)
    urls = conf.protected_urls()
    out: List[Dict] = []
    seen = set()
    for url in urls:
        if url in seen:
            continue
        seen.add(url)
        for finding in conf.confirm(url, token):
            if finding.verdict.actionable:      # confirmé ou suspecté, pas réfuté
                flat = finding.flat()
                flat['risk'] = 'Critical' if finding.verdict.confirmed else 'Medium'
                out.append(flat)
    if out:
        logger.info("auth_forge", findings=len(out))
    return out


def _extract_bearer(header_value: str) -> Optional[str]:
    import re
    m = re.search(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', header_value or '')
    return m.group(0) if m else None


def run_investigations(har_data: Dict, send: SendFn, base_url: str,
                       headers: Optional[Dict] = None, client=None,
                       do_shadow: bool = True, do_auth: bool = True) -> List[Dict]:
    """Point d'entrée unique : bâtit le modèle et lance les moteurs demandés."""
    model = APIModel.from_har(har_data, client=client)
    findings: List[Dict] = []
    if do_shadow:
        findings += run_shadow(model, send, base_url, headers=headers, client=client)
    if do_auth:
        token = _extract_bearer((headers or {}).get('Authorization', ''))
        findings += run_auth_forge(model, token, send)
    return findings
