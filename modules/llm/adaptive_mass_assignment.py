"""
Boucle Mass Assignment adaptative — généralise le principe de la boucle IDOR
au vecteur d'élévation de privilèges par affectation de masse.

Principe (boucle fermée) : on injecte des champs sensibles (`role=admin`,
`is_admin=true`, `balance=999999`…), on observe si le serveur les accepte, puis
on affine — un champ accepté ouvre la voie à ses champs adjacents (`role` accepté
=> tenter `is_superuser`, `permissions`…). Les champs efficaces découverts sont
ensuite réinjectés dans le PatternStore (`mass_assignment` : `field=value`).

Le LLM propose les champs adjacents et adjuge « accepté vs rejeté » quand une clé
est configurée ; sinon un repli heuristique déterministe prend le relais
(`source="offline"`), pour que la CI reste verte sans clé.
"""
import json
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from ..utils import get_logger
from .adaptive_idor import _extract_json

logger = get_logger("llm.adaptive_mass_assignment")

# execute_fn(payload: dict) -> {'status': int, 'body': str}
ExecuteFn = Callable[[Dict], Dict]

# Amorces classiques d'élévation de privilèges, par ordre de sévérité.
_SEED_FIELDS = [
    ("role", "admin"), ("is_admin", True), ("is_staff", True),
    ("is_superuser", True), ("admin", True), ("verified", True),
    ("email_verified", True), ("balance", 999999), ("credit", 999999),
    ("discount_rate", 100),
]

# Champs adjacents à tenter quand une amorce est acceptée (repli offline).
_ADJACENCY = {
    "role": [("roles", ["admin"]), ("user_role", "admin"), ("is_superuser", True)],
    "is_admin": [("is_superuser", True), ("admin", True), ("privilege", "admin")],
    "balance": [("credit", 999999), ("wallet", 999999), ("funds", 999999)],
    "verified": [("email_verified", True), ("kyc_verified", True)],
    "discount_rate": [("discount", 100), ("price", 0)],
}


@dataclass
class MAObservation:
    field: str
    value: object
    status: int
    body: str = ""


@dataclass
class MAVerdict:
    accepted: bool
    confidence: float
    reason: str
    source: str = "offline"


@dataclass
class MAFinding:
    target_url: str
    accepted_fields: List[Dict] = field(default_factory=list)  # [{'field','value','reason'}]
    # Champs jugés acceptés par la seule heuristique de réponse mais NON confirmés
    # par une vérification de second ordre. Sur un endpoint de création qui répond
    # 2xx en ignorant les champs inconnus (cas très courant), l'heuristique en
    # produit beaucoup : ce sont des faux positifs potentiels tant qu'on n'a pas
    # observé l'effet réel (relecture de l'objet, action privilégiée).
    suspected_fields: List[Dict] = field(default_factory=list)
    tried: List[str] = field(default_factory=list)
    rounds: int = 0

    @property
    def vulnerable(self) -> bool:
        return bool(self.accepted_fields)

    def verdicts(self):
        """Résultats dans le vocabulaire commun (modules.llm.investigation) :
        champs confirmés = CONFIRMED, champs seulement suspectés = SUSPECTED."""
        from .investigation import Verdict, CONFIRMED, SUSPECTED
        out = [Verdict(CONFIRMED, f"field '{e['field']}' accepted: {e.get('reason', '')}",
                       0.9, "deterministic") for e in self.accepted_fields]
        out += [Verdict(SUSPECTED, f"field '{e['field']}' unconfirmed: {e.get('reason', '')}",
                        0.5, "deterministic") for e in self.suspected_fields]
        return out


class AdaptiveMassAssignmentLoop:
    """Découverte adaptative des champs d'affectation de masse acceptés."""

    def __init__(self, execute_fn: ExecuteFn, client=None, *,
                 max_rounds: int = 3, per_round: int = 6,
                 context: Optional[Dict] = None, verify_fn=None):
        self.execute_fn = execute_fn
        self.client = client
        self.max_rounds = max_rounds
        self.per_round = per_round
        self.context = context or {}
        # verify_fn(field, value) -> bool : vérification de second ordre confirmant
        # que l'injection a RÉELLEMENT pris effet (ex. relire l'objet, se logguer
        # et tester un accès privilégié). Sans elle, on ne peut pas distinguer
        # « champ stocké » de « champ ignoré » derrière un même 2xx.
        self.verify_fn = verify_fn

    @property
    def _llm_available(self) -> bool:
        return self.client is not None

    def run(self, target: Dict) -> MAFinding:
        """target = {'url', 'method'?}. On teste des champs sensibles un à un."""
        finding = MAFinding(target_url=target['url'])
        tried: set = set()
        candidates: List = list(_SEED_FIELDS)

        for rnd in range(1, self.max_rounds + 1):
            fresh = [(f, v) for (f, v) in candidates if f not in tried][:self.per_round]
            if not fresh:
                break

            round_accepted: List[str] = []
            for fld, val in fresh:
                tried.add(fld)
                finding.tried.append(fld)
                obs = self._observe(fld, val)
                verdict = self._interpret(obs)
                if not verdict.accepted:
                    continue
                # Vérification de second ordre : si fournie, elle seule fait foi.
                # Un champ non confirmé reste « suspecté » (faux positif probable)
                # et ne pilote pas le raffinement (on ne veut pas propager du bruit).
                if self.verify_fn is not None and not self.verify_fn(fld, val):
                    finding.suspected_fields.append(
                        {'field': fld, 'value': val,
                         'reason': f'{verdict.reason}; unconfirmed by verify_fn'})
                    continue
                finding.accepted_fields.append(
                    {'field': fld, 'value': val, 'reason': verdict.reason})
                round_accepted.append(fld)
                logger.info("mass_assignment_accepted", url=target['url'],
                            field=fld, source=verdict.source)

            candidates = self._refine(target, round_accepted, tried)

        finding.rounds = min(self.max_rounds, finding.rounds or self.max_rounds)
        return finding

    # --- exécution ------------------------------------------------------------
    def _observe(self, fld, val) -> MAObservation:
        resp = self.execute_fn({fld: val}) or {}
        return MAObservation(field=fld, value=val,
                             status=int(resp.get('status', 0)),
                             body=(resp.get('body', '') or '')[:2000])

    # --- interpret : accepté vs rejeté ---------------------------------------
    def _interpret(self, obs: MAObservation) -> MAVerdict:
        if self._llm_available:
            v = self._interpret_llm(obs)
            if v is not None:
                return v
        return self._interpret_offline(obs)

    def _interpret_offline(self, obs: MAObservation) -> MAVerdict:
        if obs.status not in (200, 201):
            return MAVerdict(False, 0.9, f"Rejected (status {obs.status})", "offline")
        low = obs.body.lower()
        # Un message d'erreur/validation dans un 200 signale un rejet applicatif.
        if any(k in low for k in ('error', 'invalid', 'not allowed', 'forbidden', 'denied')):
            return MAVerdict(False, 0.6, "Error message in body", "offline")
        # Champ renvoyé tel quel dans la réponse = signal fort d'acceptation.
        reflected = obs.field.lower() in low
        return MAVerdict(True, 0.9 if reflected else 0.6,
                         "Field reflected" if reflected else "Accepted (2xx, no error)",
                         "offline")

    def _interpret_llm(self, obs: MAObservation) -> Optional[MAVerdict]:
        from .prompts import get_prompt
        prompt = get_prompt('ma_interpret').render_user(
            field=obs.field, value=repr(obs.value), status=obs.status,
            body=repr(obs.body[:600]))
        data = self._ask_json(prompt)
        if isinstance(data, dict) and 'accepted' in data:
            return MAVerdict(bool(data['accepted']), float(data.get('confidence', 0.5)),
                             str(data.get('reason', '')), "llm")
        return None

    # --- refine : champs adjacents -------------------------------------------
    def _refine(self, target: Dict, accepted: List[str], tried: set) -> List:
        if self._llm_available and accepted:
            nxt = self._refine_llm(target, accepted, tried)
            if nxt:
                return nxt
        out: List = []
        for fld in accepted:
            for pair in _ADJACENCY.get(fld, []):
                if pair[0] not in tried:
                    out.append(pair)
        return out

    def _refine_llm(self, target: Dict, accepted: List[str], tried: set) -> List:
        from .prompts import get_prompt
        prompt = get_prompt('ma_refine').render_user(
            context=json.dumps(self.context)[:800], accepted=json.dumps(accepted))
        data = self._ask_json(prompt)
        out: List = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and item.get('field') and item['field'] not in tried:
                    out.append((item['field'], item.get('value', True)))
        return out[:self.per_round]

    def _ask_json(self, prompt: str):
        from .prompts.investigations import SYS_SECURITY_JSON
        try:
            resp = self.client.complete(prompt, system=SYS_SECURITY_JSON)
            return _extract_json(getattr(resp, 'content', None))
        except Exception as e:
            logger.warning("adaptive_ma_llm_failed", error=str(e))
            return None
