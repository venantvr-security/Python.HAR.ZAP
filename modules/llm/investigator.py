"""
Investigator — la couche de jugement « de second ordre ».

Les boucles adaptatives adjugent UNE observation (« ce 200 est-il une
acceptation ? »). Or sur un endpoint de création qui répond 2xx en ignorant les
champs inconnus, cette question n'a pas de réponse fiable depuis la seule
réponse d'écriture (cf. run terrain VAmPI : 10 faux positifs sur 11).

Un pentester ne s'arrête pas là : il CONFIRME par une seconde requête. « J'ai
injecté admin=true à l'inscription → je relis l'utilisateur créé via un endpoint
qui expose l'état → est-il réellement admin ? ». C'est ce raisonnement que
l'Investigator porte :

    hypothèse → plan de confirmation → exécution déterministe → verdict + preuve

Répartition IA / déterministe (principe du projet) :
- L'IA PROPOSE le *plan* : quel endpoint sert d'oracle de relecture, quelle clé
  identifie notre objet, quel attribut stocké prouve que l'injection a pris
  (y compris le mapping sémantique injected→stored : `is_admin` peut être stocké
  sous `admin`). C'est un vrai jugement, dépendant du domaine.
- Le CODE DISPOSE : il exécute le plan (requêtes, corrélation, comparaison).
  L'IA ne touche jamais le réseau → auditable, rejouable (record/replay), sûr.
- FALLBACK hors-ligne : sans modèle, une heuristique choisit l'oracle le plus
  plausible (endpoint « debug »/collection) et vérifie le champ injecté tel quel.
  Moins fin (pas de mapping sémantique), mais honnête et sans réseau côté IA.

Le produit de l'Investigator est une paire (execute_fn, verify_fn) directement
consommable par AdaptiveMassAssignmentLoop : seuls les champs CONFIRMÉS par
relecture atterrissent dans `accepted_fields`.
"""
import itertools
import json
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from ..utils import get_logger
from .adaptive_idor import _extract_json

logger = get_logger("llm.investigator")

# send(method, url, headers=None, json_body=None) -> {'status': int, 'body': str}
SendFn = Callable[..., Dict]

# Clés candidates pour identifier notre objet dans la réponse de l'oracle,
# par ordre de préférence (une valeur qu'on contrôle et qui est ré-exposée).
_IDENTITY_KEYS = ('username', 'user', 'login', 'id', 'uuid', 'email', 'name')


@dataclass
class ConfirmationPlan:
    """Comment confirmer qu'une injection a réellement pris effet."""
    oracle_url: str                      # GET qui reflète l'état stocké
    identity_field: str                  # clé qui retrouve notre objet dans l'oracle
    oracle_headers: Optional[Dict] = None
    record_path: Optional[str] = None    # clé de la liste d'enregistrements (ex. 'users')
    effect_field: Optional[str] = None   # attribut stocké prouvant l'effet (None => champ injecté)
    source: str = "offline"

    def to_dict(self) -> Dict:
        return {'oracle_url': self.oracle_url, 'identity_field': self.identity_field,
                'record_path': self.record_path, 'effect_field': self.effect_field,
                'source': self.source}


class MassAssignmentInvestigator:
    """Construit un plan de confirmation puis instrumente la boucle mass-assignment."""

    def __init__(self, send: SendFn, client=None,
                 oracle_candidates: Optional[List[str]] = None,
                 oracle_headers: Optional[Dict] = None):
        self.send = send
        self.client = client
        self.oracle_candidates = list(oracle_candidates or [])
        self.oracle_headers = oracle_headers or {}
        self._seq = itertools.count(1)

    # --- 1. Le plan : jugement (IA) avec repli déterministe -------------------
    def plan(self, target: Dict, base_body: Dict) -> ConfirmationPlan:
        if self.client is not None:
            p = self._plan_llm(target, base_body)
            if p is not None:
                logger.info("investigator_plan", source="llm", oracle=p.oracle_url)
                return p
        p = self._plan_offline(target, base_body)
        logger.info("investigator_plan", source="offline", oracle=p.oracle_url)
        return p

    def _plan_offline(self, target: Dict, base_body: Dict) -> ConfirmationPlan:
        """Heuristique : oracle = un endpoint « debug » ou de collection ; identité
        = première clé plausible du corps ; effet = le champ injecté lui-même."""
        oracle = self._pick_oracle_offline()
        identity = next((k for k in _IDENTITY_KEYS if k in base_body),
                        next(iter(base_body), 'id'))
        record_path = self._discover_record_path(oracle) if oracle else None
        return ConfirmationPlan(oracle_url=oracle or '', identity_field=identity,
                                oracle_headers=dict(self.oracle_headers),
                                record_path=record_path, effect_field=None,
                                source="offline")

    def _pick_oracle_offline(self) -> Optional[str]:
        if not self.oracle_candidates:
            return None
        # Un endpoint « debug/dump/all » expose typiquement l'état complet.
        for kw in ('debug', 'dump', 'all', 'list'):
            for url in self.oracle_candidates:
                if kw in url.lower():
                    return url
        # Sinon, la collection la plus courte (souvent la liste racine).
        return sorted(self.oracle_candidates, key=len)[0]

    def _discover_record_path(self, oracle_url: str) -> Optional[str]:
        """Sonde l'oracle une fois pour trouver où sont les enregistrements
        (liste racine, ou dict {clé: [...]}). Déterministe, une requête."""
        try:
            resp = self.send('GET', oracle_url, headers=self.oracle_headers)
            data = json.loads(resp.get('body', '') or 'null')
        except Exception:
            return None
        if isinstance(data, list):
            return None  # liste à la racine
        if isinstance(data, dict):
            list_keys = [k for k, v in data.items() if isinstance(v, list)]
            if len(list_keys) == 1:
                return list_keys[0]
            for k in ('users', 'data', 'items', 'results', 'records'):
                if k in data and isinstance(data[k], list):
                    return k
        return None

    def _plan_llm(self, target: Dict, base_body: Dict) -> Optional[ConfirmationPlan]:
        """L'IA choisit l'oracle, la clé d'identité, et l'attribut stocké prouvant
        l'effet (avec mapping sémantique injected→stored)."""
        prompt = (
            "You are confirming a mass-assignment vulnerability by a second request.\n"
            f"Write endpoint: {target.get('method', 'POST')} {target.get('url')}\n"
            f"Write body keys: {list(base_body)}\n"
            f"Candidate GET oracle endpoints (which one reflects stored state?):\n"
            + "\n".join(f"  - {u}" for u in self.oracle_candidates) + "\n"
            "Return JSON: {\"oracle_url\": str, \"identity_field\": str (a write-body key "
            "echoed back by the oracle), \"record_path\": str|null (json key holding the "
            "list of records, null if the oracle returns a bare list), \"effect_field\": "
            "str|null (the STORED attribute that proves the injection took effect, e.g. an "
            "injected 'is_admin' may be stored as 'admin'; null to check the injected field "
            "verbatim)}."
        )
        try:
            resp = self.client.complete(
                prompt, system="You are a security engineer. Answer only with the requested JSON.")
            data = _extract_json(getattr(resp, 'content', None))
        except Exception as e:
            logger.warning("investigator_plan_llm_failed", error=str(e))
            return None
        if not isinstance(data, dict) or not data.get('oracle_url'):
            return None
        return ConfirmationPlan(
            oracle_url=str(data['oracle_url']),
            identity_field=str(data.get('identity_field') or
                               next((k for k in _IDENTITY_KEYS if k in base_body), 'id')),
            oracle_headers=dict(self.oracle_headers),
            record_path=data.get('record_path') or None,
            effect_field=data.get('effect_field') or None,
            source="llm")

    # --- 2. Instrumentation : paire (execute_fn, verify_fn) -------------------
    def instrument(self, target: Dict, base_body: Dict,
                   plan: Optional[ConfirmationPlan] = None
                   ) -> Tuple[Callable, Callable, ConfirmationPlan]:
        """Rend (execute_fn, verify_fn, plan) pour AdaptiveMassAssignmentLoop.

        execute_fn et verify_fn partagent un état : à chaque écriture, l'identité
        (unique) utilisée est mémorisée par champ injecté, pour que la relecture
        cible le bon objet.
        """
        plan = plan or self.plan(target, base_body)
        method = target.get('method', 'POST')
        url = target['url']
        identity_by_field: Dict[str, str] = {}

        def _fresh_body(payload: Dict) -> Dict:
            body = dict(base_body)
            ident = f"inv_{next(self._seq)}"
            body[plan.identity_field] = ident
            # Évite les collisions de contrainte d'unicité sur les emails.
            for k in list(body):
                if 'email' in k.lower():
                    body[k] = f"{ident}@example.com"
            body.update(payload)
            fld = next(iter(payload), None)
            if fld is not None:
                identity_by_field[fld] = ident
            return body

        def execute_fn(payload: Dict) -> Dict:
            body = _fresh_body(payload)
            resp = self.send(method, url, headers=self.oracle_headers or None,
                             json_body=body) or {}
            return {'status': int(resp.get('status', 0)), 'body': resp.get('body', '') or ''}

        def verify_fn(fld, value) -> bool:
            if not plan.oracle_url:
                return False
            ident = identity_by_field.get(fld)
            if ident is None:
                return False
            rec = self._read_back(plan, ident)
            if rec is None:
                return False
            attr = plan.effect_field or fld
            got = rec.get(attr)
            # Effet confirmé si l'attribut reflète l'injection (véracité ou égalité).
            confirmed = bool(got) if got is not None else False
            if isinstance(value, bool):
                confirmed = (bool(got) == value) and got is not None
            elif got is not None and not isinstance(got, bool):
                confirmed = confirmed or (str(got) == str(value))
            logger.info("investigator_verify", field=fld, identity=ident,
                        attr=attr, got=got, confirmed=confirmed)
            return confirmed

        return execute_fn, verify_fn, plan

    def _read_back(self, plan: ConfirmationPlan, ident: str) -> Optional[Dict]:
        """Relit l'oracle et retrouve l'enregistrement par sa clé d'identité."""
        try:
            resp = self.send('GET', plan.oracle_url, headers=plan.oracle_headers)
            data = json.loads(resp.get('body', '') or 'null')
        except Exception:
            return None
        records = data.get(plan.record_path) if (plan.record_path and isinstance(data, dict)) else data
        if not isinstance(records, list):
            return None
        for rec in records:
            if isinstance(rec, dict) and str(rec.get(plan.identity_field)) == str(ident):
                return rec
        return None
