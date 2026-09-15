"""
Orchestrateur adaptatif — l'« articulation par IA » du DAST (prototype Phase-1).

Aujourd'hui l'opérateur coche des flags (--web, --injection, --investigate…) et
les moteurs tournent dans un ordre FIXE. C'est rigide : on scanne tout, pareil,
quelle que soit la cible, et on n'exploite pas ce qu'on vient de découvrir.

Ce module introduit un PLAN de scan calculé — quels moteurs lancer, sur quelles
cibles, dans quel ordre — à partir (a) de la forme de l'API (déterministe) et
(b) des findings déjà obtenus (boucle réactive). Deux planificateurs :

  - deterministic_plan : règles structurelles, ZÉRO IA (l'articulation « de base »,
    déjà plus agile qu'un pipeline figé) ;
  - ai_plan : l'IA PROPOSE un plan ordonné + une raison ; le CODE le VALIDE contre
    la liste blanche de moteurs (l'IA ne peut inventer aucune action) et l'exécute.
    Sans client -> repli déterministe. C'est la même discipline que partout :
    l'IA propose, le code dispose, rien d'offensif n'est décidé par le modèle.

Le prototype ne fait que PLANIFIER (il ne lance pas les moteurs — le CLI reste
maître de l'exécution). Il est pur, testable, sans effet de bord.
"""
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse

from ..utils import get_logger

logger = get_logger("llm.orchestrator")

# Moteurs orchestrables (liste blanche : l'IA ne peut proposer QUE ceux-là).
ENGINES = ('investigate', 'probes', 'web', 'injection', 'business_flow',
           'adaptive', 'matrix_bola', 'graphql')

_URLISH = re.compile(r'(url|uri|link|src|dest|target|callback|redirect|next|image|'
                     r'fetch|webhook|file|path|doc|page|template)', re.I)


@dataclass
class Step:
    engine: str
    rationale: str = ''
    priority: int = 5            # 1 = le plus urgent

    def to_dict(self) -> Dict:
        return {'engine': self.engine, 'rationale': self.rationale, 'priority': self.priority}


@dataclass
class Plan:
    steps: List[Step] = field(default_factory=list)
    source: str = 'deterministic'   # deterministic | llm

    def ordered(self) -> List[Step]:
        return sorted(self.steps, key=lambda s: s.priority)

    def engines(self) -> List[str]:
        seen, out = set(), []
        for s in self.ordered():
            if s.engine not in seen:
                seen.add(s.engine)
                out.append(s.engine)
        return out

    def to_dict(self) -> Dict:
        return {'source': self.source, 'steps': [s.to_dict() for s in self.ordered()]}


# --- contexte de scan (déterministe, à partir du HAR + findings) ------------
def scan_context(har_data: Dict, findings: Optional[List[Dict]] = None) -> Dict:
    """Résume ce qu'on sait de la cible : formes d'endpoints + findings acquis."""
    entries = (har_data or {}).get('log', {}).get('entries', []) or []
    has_auth = has_writes = urlish = graphql = False
    for e in entries:
        req = e.get('request', {})
        method = (req.get('method', 'GET') or 'GET').upper()
        url = req.get('url', '')
        if method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            has_writes = True
        for h in req.get('headers', []):
            if h.get('name', '').lower() in ('authorization', 'cookie', 'x-api-key'):
                has_auth = True
        if _URLISH.search(urlparse(url).query):
            urlish = True
        text = (req.get('postData', {}) or {}).get('text', '')
        if _URLISH.search(text or ''):
            urlish = True
        if '/graphql' in url or (text and '"query"' in text and '{' in text):
            graphql = True
    return {
        'endpoints': len(entries),
        'has_auth': has_auth,
        'has_writes': has_writes,
        'has_urlish_params': urlish,
        'is_graphql': graphql,
        'findings': findings or [],
    }


# --- planificateur déterministe (articulation « de base », sans IA) ---------
def deterministic_plan(ctx: Dict) -> Plan:
    """Choisit les moteurs pertinents selon la forme de l'API ET réagit aux
    findings déjà obtenus (priorise les suites d'exploitation)."""
    steps: List[Step] = [
        Step('investigate', "toujours : routes shadow (API9) + forge d'auth (API2)", 3),
    ]
    if ctx.get('is_graphql'):
        steps.append(Step('graphql', "endpoint GraphQL détecté", 2))
    if ctx.get('has_urlish_params'):
        steps.append(Step('probes', "paramètres url-ish -> SSRF / rate-limit", 3))
        steps.append(Step('web', "paramètres injectables -> traversal / SSTI / XSS / redirect", 4))
        steps.append(Step('injection', "paramètres injectables -> SQL / NoSQL", 4))
    if ctx.get('has_writes'):
        steps.append(Step('adaptive', "écritures observées -> mass-assignment / IDOR", 4))
        steps.append(Step('business_flow', "écritures observées -> abus de flux métier", 5))
    if ctx.get('has_auth'):
        steps.append(Step('matrix_bola', "session authentifiée -> matrice d'accès (BOLA/BFLA, multi-rôles)", 4))

    # --- boucle RÉACTIVE : la découverte reshape le plan ---
    for f in ctx.get('findings', []):
        name = (f.get('name') or f.get('title') or '').lower()
        src = (f.get('source') or '').lower()
        if 'alg=none' in name or 'jwt' in name or 'auth' in src:
            steps.append(Step('matrix_bola',
                "bypass d'auth confirmé -> tester l'accès aux routes privilégiées EN PRIORITÉ", 1))
        if 'ssrf' in name or 'ssrf' in src:
            steps.append(Step('investigate',
                "SSRF confirmée -> extrapoler les cibles internes (metadata, /internal)", 1))
        if 'api_key' in name or 'leak' in name or 'bola' in src:
            steps.append(Step('adaptive',
                "fuite d'identifiant/objet -> rejouer avec le contexte élargi", 2))
    return Plan(steps=steps, source='deterministic')


# --- planificateur IA (propose ; le code valide) ----------------------------
def ai_plan(client, ctx: Dict) -> Optional[Plan]:
    """L'IA propose un plan ordonné à partir du contexte. Chaque étape est VALIDÉE
    contre ENGINES (liste blanche) : une étape inconnue est écartée. Sans client
    ou en cas d'échec -> None (repli déterministe)."""
    if client is None:
        return None
    system = ("You plan a DAST scan. Given the API shape and findings so far, return "
              "ONLY JSON: {\"steps\":[{\"engine\":<one of " + '|'.join(ENGINES) +
              ">,\"rationale\":\"...\",\"priority\":1-9}]}. Order by what maximizes "
              "coverage and exploits findings (e.g. an auth bypass -> prioritize "
              "privileged-route access). Choose engines ONLY from the given list. No prose.")
    summary = {k: v for k, v in ctx.items() if k != 'findings'}
    fnames = [(f.get('name') or f.get('title') or '') for f in ctx.get('findings', [])][:20]
    user = f"API shape:\n{json.dumps(summary)}\n\nFindings so far:\n{json.dumps(fnames)}"
    try:
        resp = client.complete(user, system=system)
        data = _first_json(getattr(resp, 'content', '') or '')
    except Exception as e:
        logger.warning("ai_plan_failed", error=str(e))
        return None
    if not isinstance(data, dict) or not isinstance(data.get('steps'), list):
        return None
    steps: List[Step] = []
    for it in data['steps']:
        if not isinstance(it, dict):
            continue
        eng = str(it.get('engine', ''))
        if eng not in ENGINES:                      # l'IA ne peut PAS inventer d'action
            logger.info("ai_plan_dropped_unknown_engine", engine=eng)
            continue
        try:
            prio = int(it.get('priority', 5))
        except (TypeError, ValueError):
            prio = 5
        steps.append(Step(eng, str(it.get('rationale', '')), max(1, min(9, prio))))
    return Plan(steps=steps, source='llm') if steps else None


def next_plan(har_data: Dict, findings: Optional[List[Dict]] = None, client=None) -> Plan:
    """Point d'entrée : plan IA si dispo ET valide, sinon plan déterministe.
    Toujours un plan exploitable (jamais vide) grâce au repli."""
    ctx = scan_context(har_data, findings)
    plan = ai_plan(client, ctx)
    if plan is None or not plan.steps:
        plan = deterministic_plan(ctx)
    logger.info("scan_planned", source=plan.source, engines=plan.engines())
    return plan


def _first_json(text: str):
    m = re.search(r'\{.*\}', text or '', re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None
