"""
Contrat d'investigation — le vocabulaire commun à TOUS les moteurs.

Le run terrain a montré la même leçon partout : un statut 2xx (ou un marqueur, ou
un champ statique) ne PROUVE pas une vulnérabilité. Chaque moteur doit donc
parler la même langue : émettre une HYPOTHÈSE, la CONFIRMER par une preuve de
second ordre, et rendre un VERDICT explicite.

Trois états, une seule échelle pour toute la plateforme :
- CONFIRMED : preuve directe (relecture, rejeu, marqueur non ambigu).
- SUSPECTED : signal présent mais non confirmé (heuristique, 2xx sans preuve) —
  à ne jamais présenter comme certain ; c'est ce qui évite les faux positifs.
- REFUTED  : testé et infirmé (le contrôle a tenu).

`source` distingue le jugement déterministe de l'IA. `evidence` porte la preuve
(requête/réponse) pour qu'un humain — ou le mode hors-ligne — puisse auditer.

Chaque détecteur (mass-assignment, BOLA, auth, SSRF, rate-limit, …) expose ses
résultats via `Verdict`, et peut router ses hypothèses par un `Confirmer`.
"""
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

CONFIRMED = "confirmed"
SUSPECTED = "suspected"
REFUTED = "refuted"


@dataclass
class Evidence:
    """Preuve auditable d'un verdict : la requête tentée et ce qu'elle a produit."""
    request: str = ""
    response: str = ""
    note: str = ""

    def to_dict(self) -> Dict:
        return {'request': self.request, 'response': self.response, 'note': self.note}


@dataclass
class Verdict:
    status: str                     # CONFIRMED | SUSPECTED | REFUTED
    reason: str = ""
    confidence: float = 0.5
    source: str = "deterministic"   # deterministic | llm
    evidence: Optional[Evidence] = None

    @property
    def confirmed(self) -> bool:
        return self.status == CONFIRMED

    @property
    def actionable(self) -> bool:
        """Ce qu'on remonte comme finding : confirmé, ou suspecté (à marquer)."""
        return self.status in (CONFIRMED, SUSPECTED)

    def to_dict(self) -> Dict:
        return {'status': self.status, 'reason': self.reason,
                'confidence': round(self.confidence, 2), 'source': self.source,
                'evidence': self.evidence.to_dict() if self.evidence else None}


class Confirmer:
    """Interface : transforme une hypothèse en Verdict prouvé.

    Un moteur produit des hypothèses (candidats) ; un Confirmer les tranche par
    une preuve de second ordre. Sous-classer et implémenter `confirm`.
    """

    def confirm(self, hypothesis: Any) -> Verdict:  # pragma: no cover - interface
        raise NotImplementedError


def run_confirmations(hypotheses: List[Any],
                      confirm: Callable[[Any], Verdict]) -> List[Tuple[Any, Verdict]]:
    """Applique une fonction de confirmation à chaque hypothèse et apparie
    (hypothèse, verdict). Point d'entrée commun pour tous les moteurs."""
    return [(h, confirm(h)) for h in hypotheses]


def summarize(verdicts: List[Verdict]) -> Dict[str, int]:
    """Compte par statut — pour les rapports et la gate."""
    out = {CONFIRMED: 0, SUSPECTED: 0, REFUTED: 0}
    for v in verdicts:
        out[v.status] = out.get(v.status, 0) + 1
    return out


# --- Décision mixte déterministe + IA -------------------------------------
# Le déterministe est SOUVERAIN quand il tranche : CONFIRMED (preuve directe) et
# REFUTED (contre-preuve) ne sont JAMAIS révisés par l'IA — la preuve prime sur
# l'opinion. L'IA n'arbitre QUE le SUSPECTED, le milieu ambigu que le
# déterministe n'a pu ni prouver ni infirmer (typiquement : « objet lisible par
# tous ET portant un champ owner — ressource publique ou accès cassé ? »).
# Sans client, le SUSPECTED reste SUSPECTED (repli honnête, jamais affirmé).

def mix_adjudicate(verdict: "Verdict", context: Dict, client=None) -> "Verdict":
    """Applique l'IA au seul verdict SUSPECTED ; renvoie un verdict révisé."""
    if verdict.status != SUSPECTED or client is None:
        return verdict
    from .adaptive_idor import _extract_json
    from .prompts import get_prompt
    system, user = get_prompt('mix_adjudicate').render(
        kind=context.get('kind', '?'), url=context.get('url', ''),
        reason=context.get('reason', ''),
        evidence=str(context.get('evidence', ''))[:700])
    try:
        resp = client.complete(user, system=system)
        data = _extract_json(getattr(resp, 'content', None))
    except Exception:
        return verdict
    if not isinstance(data, dict) or 'decision' not in data:
        return verdict
    decision = str(data.get('decision', '')).lower()
    reason = "AI-adjudicated: " + str(data.get('reason', ''))
    conf = float(data.get('confidence', 0.7))
    if decision == 'real':
        return Verdict(CONFIRMED, reason, conf, "llm", verdict.evidence)
    if decision == 'false_positive':
        return Verdict(REFUTED, reason, conf, "llm", verdict.evidence)
    return Verdict(SUSPECTED, reason, conf, "llm", verdict.evidence)
