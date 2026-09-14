"""
Moteur actif d'abus de flux métier — OWASP API6 (Unrestricted Access to
Sensitive Business Flows).

Les autres moteurs testent l'autorisation sur un endpoint isolé. Celui-ci cible la
LOGIQUE MÉTIER multi-étapes : un flux (panier → checkout → paiement → confirmation)
doit s'exécuter dans l'ordre, une seule fois, avec des valeurs valides. On tente
donc trois abus classiques et on adjuge si le serveur les accepte :

  1. Saut d'état   — exécuter l'étape finale sans les étapes gardiennes (payer).
  2. Manipulation  — valeur négative / nulle / hors-bornes sur un champ métier.
  3. Rejeu         — rejouer une action à usage unique (coupon, remboursement).

IA (au bon endroit) : reconstruire la machine à états et repérer l'étape gardienne
/ les champs monétaires est du jugement → LLM optionnel ; sinon heuristiques par
mots-clés. Adjuger « l'abus a-t-il réussi ? » sur une réponse ambiguë → LLM
optionnel ; sinon statut + marqueurs d'erreur. Tout est borné et à repli offline.
"""
import json
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional
from urllib.parse import urlparse

from .utils import get_logger

logger = get_logger("business.flow")

# execute(method, url, headers, body) -> {'status': int, 'body': str}
ExecuteFn = Callable[[str, str, Dict, Optional[Dict]], Dict]

_GUARD_HINTS = ('pay', 'payment', 'checkout', 'charge', 'confirm', 'verify', 'validate', 'authorize')
_FINAL_HINTS = ('confirm', 'complete', 'deliver', 'ship', 'fulfill', 'download', 'receipt', 'success')
_MONEY_FIELDS = re.compile(r'(qty|quantity|amount|price|total|count|balance|credit|discount|points|sum)', re.I)
_ONESHOT_HINTS = ('coupon', 'promo', 'redeem', 'refund', 'apply', 'voucher', 'gift', 'claim')
_ERROR_MARKERS = ('error', 'invalid', 'not allowed', 'forbidden', 'denied', 'unauthorized',
                  'required', 'must be', 'validation')
# Verbes de TRANSITION d'état : ces actions promeuvent un objet dans un workflow
# (brouillon -> publié, en attente -> approuvé). Sur une API sans contrôle, elles
# sont franchissables sans l'étape d'approbation censée les garder (API6).
_TRANSITION_VERBS = ('publish', 'approve', 'submit', 'activate', 'enable', 'moderate',
                     'accept', 'promote', 'release', 'authorize', 'unlock', 'verify',
                     'confirm', 'complete', 'finalize')
# Marqueurs d'un état « promu » observé au readback : confirme que la transition a
# réellement pris effet (et n'est pas un simple 200 sans conséquence).
_PROMOTED_MARKERS = ('publish', 'approved', 'active', 'enabled', 'live', 'accepted',
                     'completed', 'confirmed', 'released', 'verified')
_VERSION_SEG = re.compile(r'^v\d+$', re.I)


@dataclass
class Step:
    method: str
    url: str
    body: Optional[Dict] = None
    headers: Dict = field(default_factory=dict)

    @property
    def path(self) -> str:
        return urlparse(self.url).path


@dataclass
class Flow:
    name: str
    steps: List[Step] = field(default_factory=list)


@dataclass
class FlowFinding:
    kind: str          # state_skip / value_manipulation / replay / workflow_transition
    severity: str
    title: str
    url: str
    detail: str = ''
    source_tag: str = 'business_flow'
    status: str = 'confirmed'      # confirmed (preuve déterministe) | suspected
    source: str = 'deterministic'  # deterministic | llm

    def flat(self) -> Dict:
        return {'source': 'business_flow', 'risk': self.severity, 'name': self.title,
                'url': self.url, 'status': self.status, 'adjudication': self.source}


def _json_body(req: Dict) -> Optional[Dict]:
    pd = req.get('postData', {}) or {}
    txt = pd.get('text', '')
    if not txt:
        return None
    try:
        val = json.loads(txt)
        return val if isinstance(val, dict) else None
    except ValueError:
        return None


def extract_flows(har_data: Dict) -> List[Flow]:
    """Reconstruit des flux depuis le HAR : requêtes d'écriture ordonnées, groupées
    par ressource (2e segment de chemin). Heuristique déterministe."""
    groups: Dict[str, List[Step]] = {}
    for e in (har_data or {}).get('log', {}).get('entries', []) or []:
        req = e.get('request', {})
        method = req.get('method', 'GET').upper()
        if method not in ('POST', 'PUT', 'PATCH'):
            continue
        url = req.get('url', '')
        if not url:
            continue
        headers = {h.get('name'): h.get('value') for h in req.get('headers', []) if h.get('name')}
        groups.setdefault(_flow_key(urlparse(url).path), []).append(
            Step(method, url, _json_body(req), headers))
    return [Flow(name=k, steps=v) for k, v in groups.items() if v]


def _flow_key(path: str) -> str:
    """Nom de ressource = 1er segment non-version et non-numérique. Regroupe
    `/v1/orders/cart` sous 'orders' ET `/articles/1/publish` sous 'articles'
    (l'ancien `segs[1]` cassait ce dernier cas en le classant sous '1')."""
    segs = [s for s in path.split('/') if s]
    for s in segs:
        if _VERSION_SEG.match(s) or s.isdigit():
            continue
        return s
    return segs[0] if segs else 'flow'


def _accepted(resp: Dict, adjudicator=None, context: str = '') -> bool:
    status = int((resp or {}).get('status', 0))
    body = ((resp or {}).get('body', '') or '').lower()
    if not (200 <= status < 300):
        return False
    if any(m in body for m in _ERROR_MARKERS):
        return False
    if adjudicator is not None and getattr(adjudicator, 'available', False):
        v = adjudicator.classify_owasp(
            {'alert': f'Business-flow abuse accepted? {context}', 'url': ''},
            {'API6:2023': 'Sensitive Business Flows'})
        return bool(v)
    return True


def _last_seg(path: str) -> str:
    segs = [s for s in path.split('/') if s]
    return segs[-1].lower() if segs else ''


def _guard_step(flow: Flow) -> Optional[Step]:
    for s in flow.steps:
        if any(h in s.path.lower() for h in _GUARD_HINTS):
            return s
    return None


class BusinessFlowScanner:
    """Exécute les abus de flux et adjuge l'acceptation par le serveur."""

    def __init__(self, execute_fn: ExecuteFn, adjudicator=None, replay_n: int = 3,
                 read_fn: Optional[Callable[[str], Dict]] = None):
        self.execute = execute_fn
        self.adjudicator = adjudicator
        self.replay_n = replay_n
        # Lecture optionnelle (GET url -> {'status','body'}) pour CONFIRMER qu'une
        # transition d'état a réellement pris effet (sinon verdict 'suspected').
        self.read = read_fn

    def run(self, flows: List[Flow]) -> List[FlowFinding]:
        out: List[FlowFinding] = []
        for flow in flows:
            if len(flow.steps) >= 1:
                out += self._value_manipulation(flow)
                out += self._replay(flow)
                out += self._workflow_transition(flow)
            if len(flow.steps) >= 2:
                out += self._state_skip(flow)
        return out

    # 4. Transition de workflow : franchir une promotion d'état (publish/approve/…)
    #    sans l'étape d'approbation censée la garder. C'est le cœur d'API6 pour un
    #    CMS/workflow, que les 3 abus « e-commerce » ci-dessus ne couvraient pas.
    def _workflow_transition(self, flow: Flow) -> List[FlowFinding]:
        out: List[FlowFinding] = []
        seen = set()
        for step in flow.steps:
            verb = _last_seg(step.path)
            if verb not in _TRANSITION_VERBS or step.path in seen:
                continue
            seen.add(step.path)
            resp = self.execute(step.method, step.url, step.headers, step.body)
            if not _accepted(resp, self.adjudicator, f"transition {step.path}"):
                continue
            # Readback : l'objet parent est-il réellement passé dans l'état promu ?
            confirmed, evidence = self._confirm_transition(step, verb)
            status = 'confirmed' if confirmed else 'suspected'
            sev = 'High' if confirmed else 'Medium'
            logger.info("flow_transition", flow=flow.name, endpoint=step.path,
                        confirmed=confirmed)
            out.append(FlowFinding('workflow_transition', sev,
                f"Sensitive business flow — '{verb}' transition reachable without approval",
                step.url,
                evidence or f"'{verb}' accepted in a single session with no approval step",
                status=status))
        return out

    def _confirm_transition(self, step: Step, verb: str):
        """GET l'objet parent (URL sans le segment verbe) et cherche un marqueur
        d'état promu. Retourne (confirmé, preuve)."""
        if self.read is None:
            return False, ''
        parent = step.url.rsplit('/' + verb, 1)[0]
        if parent == step.url:
            return False, ''
        r = self.read(parent) or {}
        body = ((r.get('body', '') or '')).lower()
        if 200 <= int(r.get('status', 0)) < 300 and any(m in body for m in _PROMOTED_MARKERS):
            return True, f"readback {urlparse(parent).path} confirms promoted state after '{verb}'"
        return False, ''

    # 1. Saut d'état : exécuter l'étape finale sans les gardiennes.
    def _state_skip(self, flow: Flow) -> List[FlowFinding]:
        guard = _guard_step(flow)
        final = next((s for s in reversed(flow.steps)
                      if any(h in s.path.lower() for h in _FINAL_HINTS)), flow.steps[-1])
        if guard is None or final is guard:
            return []
        resp = self.execute(final.method, final.url, final.headers, final.body)
        if _accepted(resp, self.adjudicator, f"state-skip {final.path}"):
            logger.info("flow_state_skip", flow=flow.name, endpoint=final.path)
            return [FlowFinding('state_skip', 'High',
                    f"Business flow state-skip — '{final.path}' reachable without '{guard.path}'",
                    final.url, f"final step accepted without the guard step ({guard.path})")]
        return []

    # 2. Manipulation de valeur : négatif / nul / hors-bornes sur un champ métier.
    def _value_manipulation(self, flow: Flow) -> List[FlowFinding]:
        out: List[FlowFinding] = []
        for step in flow.steps:
            if not step.body:
                continue
            for k, v in list(step.body.items()):
                if not (_MONEY_FIELDS.search(k) and _is_number(v)):
                    continue
                for bad in (-1, 0, 999999999):
                    body = {**step.body, k: bad}
                    resp = self.execute(step.method, step.url, step.headers, body)
                    if _accepted(resp, self.adjudicator, f"{k}={bad}"):
                        logger.info("flow_value_manip", flow=flow.name, field=k, value=bad)
                        out.append(FlowFinding('value_manipulation', 'High',
                            f"Business logic — out-of-bounds '{k}={bad}' accepted",
                            step.url, f"field '{k}' set to {bad} without validation"))
                        break  # un abus suffit pour ce champ
        return out

    # 3. Rejeu : rejouer une action à usage unique N fois.
    def _replay(self, flow: Flow) -> List[FlowFinding]:
        step = next((s for s in flow.steps
                     if any(h in s.path.lower() for h in _ONESHOT_HINTS)), None)
        if step is None:
            return []
        ok = 0
        for _ in range(self.replay_n):
            if _accepted(self.execute(step.method, step.url, step.headers, step.body),
                         self.adjudicator, f"replay {step.path}"):
                ok += 1
        if ok >= self.replay_n:
            logger.info("flow_replay", flow=flow.name, endpoint=step.path, times=ok)
            return [FlowFinding('replay', 'Medium',
                    f"Business flow replay — one-shot action '{step.path}' accepted {ok}×",
                    step.url, f"single-use action succeeded {ok} times in a row")]
        return []


def _is_number(v) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, (int, float)):
        return True
    if isinstance(v, str):
        try:
            float(v)
            return True
        except ValueError:
            return False
    return False
