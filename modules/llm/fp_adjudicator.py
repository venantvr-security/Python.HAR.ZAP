"""
Adjudicateur de faux positifs.

Les analyses passives (headers manquants, fuites de données par regex, entropie de
token) génèrent beaucoup de bruit : une regex qui « matche » `example@example.com`
ou `0000-0000` n'est pas une vraie fuite. Cet adjudicateur tranche vrai positif vs
faux positif, pour chaque finding, et annote la confiance.

Le LLM juge sur le titre/catégorie/preuve quand une clé est configurée ; sinon un
repli heuristique déterministe repère les valeurs de remplissage évidentes
(placeholders, valeurs d'exemple, répétitions) — tagué `source="offline"`.
"""
import json
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from ..utils import get_logger

logger = get_logger("llm.fp_adjudicator")

_SEVERITY_CONF = {'CRITICAL': 0.95, 'HIGH': 0.85, 'MEDIUM': 0.65, 'LOW': 0.5, 'INFO': 0.4}

# Motifs de valeurs de remplissage : un match regex qui tombe dessus est
# très probablement un faux positif (donnée d'exemple, pas une vraie fuite).
_PLACEHOLDER_HINTS = (
    'example.com', 'example.org', 'test@test', 'user@domain', 'placeholder',
    'lorem', 'ipsum', 'sample', 'your_', 'yourname', 'changeme', 'xxxx',
    'foo@bar', 'john.doe', 'jane.doe', 'notreal', 'dummy', '000-00-0000',
)
_REPEATED_RE = re.compile(r'^(.)\1{6,}$')          # 0000000, aaaaaaa
_SEQ_RE = re.compile(r'0?123456789|1234567890')     # séquences triviales


@dataclass
class FPVerdict:
    is_true_positive: bool
    confidence: float
    reason: str
    source: str = "offline"

    def to_dict(self) -> Dict:
        return {'is_true_positive': self.is_true_positive, 'confidence': round(self.confidence, 2),
                'reason': self.reason, 'source': self.source}


def _attr(issue, name, default=""):
    """Lit un attribut d'un SecurityIssue (objet) ou d'un dict indifféremment."""
    if isinstance(issue, dict):
        return issue.get(name, default)
    return getattr(issue, name, default)


class FalsePositiveAdjudicator:
    """Tranche vrai/faux positif sur un finding passif."""

    def __init__(self, client=None):
        self.client = client

    @property
    def available(self) -> bool:
        return self.client is not None

    def adjudicate(self, issue) -> FPVerdict:
        if self.available:
            v = self._adjudicate_llm(issue)
            if v is not None:
                return v
        return self._adjudicate_offline(issue)

    def _adjudicate_offline(self, issue) -> FPVerdict:
        severity = str(_attr(issue, 'severity', 'MEDIUM')).upper()
        evidence = _attr(issue, 'evidence', {}) or {}
        # On cherche la valeur détectée dans la preuve.
        blob = ' '.join(str(v) for v in (evidence.values() if isinstance(evidence, dict)
                                         else [evidence])).lower()
        matched = str(evidence.get('match') or evidence.get('value') or '') if isinstance(evidence, dict) else ''

        if any(h in blob for h in _PLACEHOLDER_HINTS):
            return FPVerdict(False, 0.85, "Evidence looks like placeholder/sample data", "offline")
        if matched and (_REPEATED_RE.match(matched) or _SEQ_RE.search(matched)):
            return FPVerdict(False, 0.8, "Evidence is a trivial/repeated value", "offline")
        # Sinon on garde le finding ; confiance dérivée de la sévérité.
        return FPVerdict(True, _SEVERITY_CONF.get(severity, 0.6),
                         "No placeholder signal — kept", "offline")

    def _adjudicate_llm(self, issue) -> Optional[FPVerdict]:
        payload = {
            'severity': _attr(issue, 'severity'),
            'category': _attr(issue, 'category'),
            'title': _attr(issue, 'title'),
            'description': _attr(issue, 'description'),
            'evidence': _attr(issue, 'evidence', {}),
        }
        prompt = (
            "Decide if this passive security finding is a TRUE positive or a false "
            "positive (e.g. a regex matching sample/placeholder data, or a header flagged "
            "on a response where it does not apply). "
            'Return JSON {"is_true_positive": bool, "confidence": number(0-1), "reason": str}.\n'
            f"Finding: {json.dumps(payload, default=str)[:1500]}"
        )
        try:
            resp = self.client.complete(
                prompt, system="You are a security engineer. Answer only with the requested JSON.")
            data = _extract_json(getattr(resp, 'content', None))
        except Exception as e:
            logger.warning("fp_adjudicate_llm_failed", error=str(e))
            return None
        if isinstance(data, dict) and 'is_true_positive' in data:
            return FPVerdict(bool(data['is_true_positive']), float(data.get('confidence', 0.5)),
                             str(data.get('reason', '')), "llm")
        return None

    def partition(self, issues: List, min_confidence: float = 0.7) -> Tuple[List, List]:
        """Sépare (vrais positifs gardés, faux positifs écartés).

        Un finding est écarté seulement si l'adjudicateur le juge faux positif
        AVEC une confiance suffisante — on ne masque pas un vrai positif par prudence.
        """
        kept, filtered = [], []
        for issue in issues:
            verdict = self.adjudicate(issue)
            if not verdict.is_true_positive and verdict.confidence >= min_confidence:
                filtered.append((issue, verdict))
            else:
                kept.append((issue, verdict))
        return kept, filtered


def _extract_json(raw: Optional[str]):
    if not raw:
        return None
    raw = raw.strip()
    if raw.startswith('```'):
        raw = raw.split('```', 2)[1]
        if raw.startswith('json'):
            raw = raw[4:]
        raw = raw.strip('`').strip()
    try:
        return json.loads(raw)
    except ValueError:
        start, end = raw.find('{'), raw.rfind('}')
        if start != -1 and end > start:
            try:
                return json.loads(raw[start:end + 1])
            except ValueError:
                return None
    return None
