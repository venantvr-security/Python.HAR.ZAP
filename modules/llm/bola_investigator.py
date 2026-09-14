"""
BOLA Investigator — le jugement de second ordre appliqué à l'accès aux objets.

Le mass-assignment demandait « le champ injecté a-t-il pris effet ? ». Le BOLA
(API1) demande « B peut-il lire l'OBJET de A ? ». Même discipline : on ne se fie
pas au statut 2xx, on CONFIRME par la preuve — l'objet renvoyé à B appartient-il
réellement à quelqu'un d'autre ?

hypothèse → relecture croisée entre sessions → verdict + preuve

Répartition IA / déterministe :
- DÉTERMINISTE (le cœur) : pour chaque objet, chaque session le relit ; le
  propriétaire est celui que nomme le champ de propriété (fourni par APIModel).
  Une session dont l'identité DIFFÈRE du propriétaire mais qui reçoit l'objet
  (2xx) = BOLA confirmé, avec preuve (le champ de propriété nomme autrui).
- IA (optionnelle, repli) : quand il n'y a pas de champ de propriété exploitable
  (réponse opaque), l'IA adjuge si deux sessions distinctes ont bien reçu le même
  objet privé. Sans modèle, ce cas ambigu reste « suspecté », non affirmé.

Les URLs d'objets à tester viennent : du trafic observé, de l'énumération via un
endpoint de liste, et de l'EXTRAPOLATION (route_extrapolator) — car un HAR ne
montre que les objets que l'utilisateur a lui-même consultés.
"""
import json
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from ..utils import get_logger
from .adaptive_idor import _extract_json
from .investigation import mix_adjudicate, Verdict, SUSPECTED, REFUTED, CONFIRMED

logger = get_logger("llm.bola_investigator")

SendFn = Callable[..., Dict]


@dataclass
class Session:
    name: str
    headers: Dict[str, str]
    identity: Optional[str] = None   # principal (ex. username) pour juger la propriété


@dataclass
class BolaFinding:
    object_url: str
    attacker: str
    owner: Optional[str]
    status: int
    confirmed: bool
    reason: str = ""
    source: str = "deterministic"
    severity: str = "High"

    def flat(self) -> Dict:
        v = self.verdict
        return {'source': 'bola', 'risk': self.severity,
                'name': f"BOLA — {self.attacker} reads object owned by "
                        f"{self.owner or 'another user'}",
                'url': self.object_url, 'status': v.status, 'adjudication': v.source}

    @property
    def verdict(self):
        """Vocabulaire commun (modules.llm.investigation)."""
        from .investigation import Verdict, Evidence, CONFIRMED, SUSPECTED
        status = CONFIRMED if (self.confirmed and self.source != "suspected") else SUSPECTED
        return Verdict(status, self.reason, 0.9 if status == CONFIRMED else 0.5,
                       "llm" if self.source == "llm" else "deterministic",
                       Evidence(request=f"GET {self.object_url} as {self.attacker}",
                                response=f"status={self.status}", note=self.reason))


class BolaInvestigator:
    def __init__(self, send: SendFn, api_model=None, client=None):
        self.send = send
        self.api_model = api_model
        self.client = client

    # --- énumération / extrapolation des objets ------------------------------
    def object_urls_from_list(self, list_url: str, item_base: str,
                              id_field: str, headers: Optional[Dict] = None
                              ) -> List[str]:
        """Construit les URLs d'objets à partir d'un endpoint de liste.

        `item_base` = préfixe de l'item (ex. 'https://api/books/v1'), `id_field`
        = clé de l'identifiant dans chaque enregistrement (ex. 'book_title')."""
        resp = self.send('GET', list_url, headers=headers) or {}
        try:
            data = json.loads(resp.get('body', '') or 'null')
        except (ValueError, TypeError):
            return []
        records = data
        if isinstance(data, dict):
            records = next((v for v in data.values() if isinstance(v, list)), [])
        urls = []
        for rec in records or []:
            if isinstance(rec, dict) and rec.get(id_field) is not None:
                urls.append(f"{item_base.rstrip('/')}/{rec[id_field]}")
        return urls

    # --- cœur : confirmation croisée -----------------------------------------
    def probe(self, object_urls: List[str], sessions: List[Session],
              ownership_field: Optional[str] = None) -> List[BolaFinding]:
        findings: List[BolaFinding] = []
        for url in object_urls:
            reads: Dict[str, Dict] = {}
            for s in sessions:
                r = self.send('GET', url, headers=s.headers) or {}
                reads[s.name] = {'status': int(r.get('status', 0)),
                                 'body': r.get('body', '') or '', 'session': s}

            owner = self._owner_of(reads, ownership_field)
            # Porte « est-ce réellement protégé ? » : un BOLA n'est prouvé que si
            # l'objet applique un contrôle d'accès — au moins un principal a été
            # REFUSÉ (401/403). Si TOUT LE MONDE obtient l'objet, ce n'est pas une
            # percée mais une ressource publique (ex. billet de blog avec champ
            # `author`) → on rétrograde en « suspected » au lieu d'affirmer.
            # (Même logique que la matrice d'accès ; elle manquait ici.)
            protected = any(r['status'] in (401, 403) for r in reads.values())
            for s in sessions:
                info = reads[s.name]
                st = info['status']
                if not (200 <= st < 300):
                    continue
                verdict, reason, source = self._adjudicate(s, owner, info, reads,
                                                           ownership_field)
                if not verdict:
                    continue
                reported = (self._body_owner(info['body'], ownership_field)
                            if ownership_field else owner) or owner
                if not protected and source == "deterministic":
                    # Milieu ambigu : lisible par tous ET champ owner ≠ appelant.
                    # Décision MIXTE — l'IA tranche public vs accès cassé ; sans
                    # IA, ça reste « suspecté » (jamais affirmé).
                    source = "suspected"
                    reason += " — no access-control evidence (readable by all; may be public)"
                    v = mix_adjudicate(
                        Verdict(SUSPECTED, reason, 0.5, "deterministic"),
                        {'kind': 'BOLA (object-level authorization)', 'url': url,
                         'reason': 'object readable by all callers but carries an '
                                   f"owner field '{reported}' != caller '{s.identity}'",
                         'evidence': info['body']},
                        self.client)
                    if v.status == REFUTED:
                        logger.info("bola_refuted_by_ai", url=url, attacker=s.name)
                        continue                      # faux positif écarté par l'IA
                    source = "llm" if v.source == "llm" and v.status == CONFIRMED else "suspected"
                    reason = v.reason
                findings.append(BolaFinding(
                    object_url=url, attacker=s.name, owner=reported, status=st,
                    confirmed=True, reason=reason, source=source,
                    severity='Critical' if s.identity in (None, '') else 'High'))
                logger.info("bola_finding", url=url, attacker=s.name,
                            owner=reported, source=source, protected=protected)
        return findings

    @staticmethod
    def _body_owner(body: str, ownership_field: str) -> Optional[str]:
        """Valeur du champ de propriété dans CE corps de réponse précis."""
        try:
            data = json.loads(body or 'null')
        except (ValueError, TypeError):
            return None
        if isinstance(data, dict) and data.get(ownership_field) is not None:
            return str(data[ownership_field])
        return None

    def _owner_of(self, reads: Dict, ownership_field: Optional[str]) -> Optional[str]:
        """Propriétaire de l'objet = valeur du champ de propriété dans une réponse
        2xx (cohérente entre sessions légitimes)."""
        if not ownership_field:
            return None
        for info in reads.values():
            if 200 <= info['status'] < 300:
                try:
                    data = json.loads(info['body'] or 'null')
                except (ValueError, TypeError):
                    continue
                if isinstance(data, dict) and data.get(ownership_field) is not None:
                    return str(data[ownership_field])
        return None

    def _adjudicate(self, s: Session, owner: Optional[str], info: Dict,
                    reads: Dict, ownership_field: Optional[str]):
        """(confirmé, raison, source). Déterministe via le champ de propriété ;
        IA en repli pour le cas opaque."""
        # Propriétaire tel que vu dans la RÉPONSE de CETTE session (pas un owner
        # global). Indispensable pour les API qui renvoient un objet différent
        # selon l'appelant (`/posts/{id}` qui renvoie « le tien ») : dans ce cas
        # l'attaquant voit owner==lui-même → pas de percée, pas de faux positif.
        if ownership_field is not None:
            body_owner = self._body_owner(info['body'], ownership_field)
            if body_owner is not None and str(s.identity) != body_owner:
                return True, (f"received object owned by '{body_owner}' "
                              f"(caller '{s.identity}')"), "deterministic"
            if body_owner is not None:
                return False, "caller is the owner", "deterministic"
            # 2xx mais pas de champ de propriété dans CETTE réponse → indécis,
            # on retombe sur la comparaison inter-sessions ci-dessous.

        # Pas de champ de propriété : compare aux autres sessions. Si une session
        # d'identité différente a reçu le MÊME corps non trivial, c'est suspect.
        body = info['body']
        for other_name, other in reads.items():
            if other_name == s.name:
                continue
            os_ = other['session']
            if os_.identity != s.identity and 200 <= other['status'] < 300 \
                    and other['body'] and other['body'] == body and len(body) > 2:
                if self.client is not None:
                    v = self._adjudicate_llm(body, s.identity, os_.identity)
                    if v is not None:
                        return v, "LLM-adjudicated identical private object", "llm"
                return False, "identical body across sessions (unconfirmed owner)", "suspected"
        return False, "no ownership evidence", "deterministic"

    def _adjudicate_llm(self, body: str, caller_id, other_id) -> Optional[bool]:
        from .prompts import get_prompt
        system, user = get_prompt('bola_adjudicate').render(
            caller_id=repr(caller_id), other_id=repr(other_id), body=repr(body[:600]))
        try:
            resp = self.client.complete(user, system=system)
            data = _extract_json(getattr(resp, 'content', None))
        except Exception as e:
            logger.warning("bola_llm_failed", error=str(e))
            return None
        if isinstance(data, dict) and 'bola' in data:
            return bool(data['bola'])
        return None
