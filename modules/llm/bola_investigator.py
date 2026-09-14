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
            for s in sessions:
                info = reads[s.name]
                st = info['status']
                if not (200 <= st < 300):
                    continue
                verdict, reason, source = self._adjudicate(s, owner, info, reads,
                                                           ownership_field)
                if verdict:
                    findings.append(BolaFinding(
                        object_url=url, attacker=s.name, owner=owner, status=st,
                        confirmed=True, reason=reason, source=source,
                        severity='Critical' if s.identity in (None, '') else 'High'))
                    logger.info("bola_confirmed", url=url, attacker=s.name,
                                owner=owner, source=source)
        return findings

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
        # Cas net : le propriétaire est connu et ce n'est pas cette session.
        if owner is not None and str(s.identity) != owner:
            return True, f"object owner '{owner}' != caller '{s.identity}'", "deterministic"
        if owner is not None:
            return False, "caller is the owner", "deterministic"

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
        prompt = (
            "Two different authenticated users received the SAME object body from an "
            "object-by-id endpoint. Decide if this proves a broken object-level "
            "authorization (one user reading another's private object) rather than a "
            "shared/public resource.\n"
            f"Caller A id: {caller_id!r}, Caller B id: {other_id!r}\n"
            f"Object body: {body[:600]!r}\n"
            'Return JSON {"bola": bool, "reason": str}.')
        try:
            resp = self.client.complete(
                prompt, system="You are a security engineer. Answer only with JSON.")
            data = _extract_json(getattr(resp, 'content', None))
        except Exception as e:
            logger.warning("bola_llm_failed", error=str(e))
            return None
        if isinstance(data, dict) and 'bola' in data:
            return bool(data['bola'])
        return None
