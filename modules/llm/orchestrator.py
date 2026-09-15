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

# Moteurs qui MODIFIENT l'état de la cible (écritures/transitions/mutations).
# Exclus par une consigne « non destructif / lecture seule ».
DESTRUCTIVE_ENGINES = frozenset({'business_flow', 'adaptive'})

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


# --- Phase 3 : scoping en langage naturel -----------------------------------
@dataclass
class ScopeConstraints:
    """Contraintes de périmètre déduites d'une consigne (`--goal`)."""
    allow_engines: Optional[frozenset] = None   # si présent : ne garder que ceux-là
    deny_engines: frozenset = frozenset()
    path_include: List[str] = field(default_factory=list)   # ne cibler que ces sous-chemins
    path_exclude: List[str] = field(default_factory=list)
    non_destructive: bool = False
    max_engines: Optional[int] = None
    source: str = 'deterministic'

    def apply(self, plan: Plan) -> Plan:
        """Filtre un plan selon les contraintes (allow/deny, non destructif, budget)."""
        steps = []
        for s in plan.ordered():
            if s.engine in self.deny_engines:
                continue
            if self.allow_engines is not None and s.engine not in self.allow_engines:
                continue
            if self.non_destructive and s.engine in DESTRUCTIVE_ENGINES:
                continue
            steps.append(s)
        if self.max_engines:
            # borne par priorité (steps déjà ordonnés), en préservant l'unicité de moteur
            seen, kept = set(), []
            for s in steps:
                if s.engine not in seen:
                    seen.add(s.engine)
                    kept.append(s)
                if len(seen) >= self.max_engines:
                    break
            steps = kept
        return Plan(steps=steps, source=plan.source)

    def to_dict(self) -> Dict:
        return {'allow_engines': sorted(self.allow_engines) if self.allow_engines else None,
                'deny_engines': sorted(self.deny_engines), 'path_include': self.path_include,
                'path_exclude': self.path_exclude, 'non_destructive': self.non_destructive,
                'max_engines': self.max_engines, 'source': self.source}


_G_AUTHZ = re.compile(r'(authz|authoriz|access[\s-]*control|contrôle d.?acc|bola|bfla|'
                      r'privileg|privilège|\bidor\b|\brole|\brôle)', re.I)
_G_INJECT = re.compile(r'(inject|\bsqli?\b|no[\s-]?sql|\bsql\b)', re.I)
_G_WEB = re.compile(r'(\bxss\b|traversal|\blfi\b|ssti|template|redirect|\bweb\b)', re.I)
_G_SSRF = re.compile(r'\bssrf\b', re.I)
_G_SHADOW = re.compile(r'(shadow|inventor|découverte d.?endpoint|\bdebug\b|actuator)', re.I)
_G_NONDEST = re.compile(r'(non[\s-]?destructi|read[\s-]?only|lecture seule|passive|passif|'
                        r'\bsafe\b|sans écriture|sans modif)', re.I)
# Chemin d'URL dans une consigne libre. La barre d'un VRAI chemin n'est jamais
# collée à un mot : « /billing », « sur /admin » sont des chemins, mais « SQL/NoSQL »,
# « authn/authz », « 24/7 » sont des alternatives/fractions en prose — pas des
# chemins. Sans ce garde-fou, `--goal "teste l'injection SQL/NoSQL"` extrayait
# `/NoSQL`, restreignait le périmètre à 0 endpoint et le scan ne trouvait RIEN,
# silencieusement. Le lookbehind exige que la barre suive un début/espace/quote.
_G_PATH = re.compile(r'(?<![\w/])/[A-Za-z0-9][\w/\-]*')


def _deterministic_goal(goal: str) -> ScopeConstraints:
    allow = set()
    if _G_AUTHZ.search(goal):
        allow |= {'investigate', 'probes', 'matrix_bola', 'business_flow'}
    if _G_INJECT.search(goal):
        allow |= {'injection'}
    if _G_WEB.search(goal):
        allow |= {'web'}
    if _G_SSRF.search(goal):
        allow |= {'probes'}
    if _G_SHADOW.search(goal):
        allow |= {'investigate'}
    include = _G_PATH.findall(goal)
    return ScopeConstraints(
        allow_engines=frozenset(allow) if allow else None,
        path_include=include,
        non_destructive=bool(_G_NONDEST.search(goal)),
        source='deterministic')


def interpret_goal(goal: Optional[str], client=None) -> Optional[ScopeConstraints]:
    """Traduit une consigne libre en contraintes. L'IA raffine (allow/deny, chemins,
    non destructif) et le CODE valide les moteurs contre la liste blanche ; sans
    client -> parseur déterministe par mots-clés."""
    if not goal:
        return None
    if client is not None:
        c = _ai_goal(client, goal)
        if c is not None:
            return c
    return _deterministic_goal(goal)


def _ai_goal(client, goal: str) -> Optional[ScopeConstraints]:
    system = ("Translate a pentest scoping instruction into JSON constraints. Return ONLY: "
              "{\"allow_engines\":[...]|null,\"deny_engines\":[...],\"path_include\":[...],"
              "\"path_exclude\":[...],\"non_destructive\":true|false}. Engines MUST be a "
              "subset of: " + ', '.join(ENGINES) + ". path_* are URL path substrings. No prose.")
    try:
        resp = client.complete(f"Instruction:\n{goal}", system=system)
        data = _first_json(getattr(resp, 'content', '') or '')
    except Exception as e:
        logger.warning("ai_goal_failed", error=str(e))
        return None
    if not isinstance(data, dict):
        return None
    allow = data.get('allow_engines')
    allow = frozenset(e for e in allow if e in ENGINES) if isinstance(allow, list) else None
    deny = data.get('deny_engines')
    deny = frozenset(e for e in deny if e in ENGINES) if isinstance(deny, list) else frozenset()
    inc = [p for p in (data.get('path_include') or []) if isinstance(p, str)]
    exc = [p for p in (data.get('path_exclude') or []) if isinstance(p, str)]
    return ScopeConstraints(allow_engines=(allow or None), deny_engines=deny,
                            path_include=inc, path_exclude=exc,
                            non_destructive=bool(data.get('non_destructive')), source='llm')


def filter_har(har_data: Dict, include: Optional[List[str]] = None,
               exclude: Optional[List[str]] = None) -> Dict:
    """Restreint les entrées du HAR aux chemins voulus (scoping « only /billing »).
    Sans filtre -> le HAR d'origine (même objet)."""
    if not include and not exclude:
        return har_data
    ents = []
    for e in (har_data or {}).get('log', {}).get('entries', []) or []:
        path = urlparse(e.get('request', {}).get('url', '')).path
        if include and not any(inc in path for inc in include):
            continue
        if exclude and any(exc in path for exc in exclude):
            continue
        ents.append(e)
    return {'log': {'entries': ents}}


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
