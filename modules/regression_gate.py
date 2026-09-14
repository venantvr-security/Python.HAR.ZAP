"""
Gate de régression sécurité.

Idée produit : en CI, on ne veut pas échouer sur les vulnérabilités déjà connues
(sinon le pipeline reste rouge en permanence) — on veut échouer uniquement sur une
faille *nouvelle*. Cette gate compare les findings du run courant à une baseline
enregistrée et sépare NOUVEAU / CORRIGÉ / INCHANGÉ.

La comparaison se fait sur une *signature* stable, insensible aux identifiants
concrets : une BOLA sur `/users/{id}` est un seul risque, pas un par id énuméré.
"""
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

# Segments de chemin à normaliser en gabarit (id numérique / UUID / hash long).
_NUM_RE = re.compile(r'^\d+$')
_UUID_RE = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
_HASH_RE = re.compile(r'^[0-9a-f]{16,}$', re.I)


def endpoint_template(url: str) -> str:
    """Réduit une URL à un gabarit d'endpoint : les identifiants deviennent {id}.

    `/v1/users/42/orders/7` -> `/v1/users/{id}/orders/{id}` — deux runs sur des
    ids différents produisent le même gabarit, donc la même signature.
    """
    path = urlparse(url).path if '//' in url or url.startswith('http') else url
    segs = []
    for seg in path.split('/'):
        if _NUM_RE.match(seg) or _UUID_RE.match(seg) or _HASH_RE.match(seg):
            segs.append('{id}')
        else:
            segs.append(seg)
    return '/'.join(segs) or '/'


def finding_signature(finding: Dict) -> str:
    """Signature stable d'un finding normalisé {type, endpoint, detail}."""
    ftype = str(finding.get('type', 'finding')).strip().lower()
    endpoint = endpoint_template(str(finding.get('endpoint', '')))
    detail = str(finding.get('detail', '')).strip().lower()
    return f"{ftype}|{endpoint}|{detail}"


def normalize_diag_findings(all_findings: List[Dict]) -> List[Dict]:
    """Normalise les findings « à plat » de diagnose (source/name/risk/url)."""
    out = []
    for f in all_findings or []:
        out.append({
            'type': f.get('source', 'finding'),
            'endpoint': f.get('url', ''),
            'detail': f.get('name', ''),
            'severity': f.get('risk', 'Low'),
            # Statut d'investigation (confirmé/suspecté) : porté jusqu'à la gate
            # pour n'échouer que sur du nouveau CONFIRMÉ (le suspecté est bruit).
            'status': f.get('status', 'confirmed'),
        })
    return out


def normalize_adaptive(result) -> List[Dict]:
    """Normalise les findings de la campagne adaptative (IDOR / MA / hidden params).

    Ce sont les findings à plus forte valeur (OWASP API #1/#3/#5) : ils doivent
    peser dans la gate.
    """
    out: List[Dict] = []
    if result is None:
        return out
    for f in getattr(result, 'idor', []) or []:
        if getattr(f, 'vulnerable', False):
            out.append({'type': 'idor(API1)', 'endpoint': getattr(f, 'target_url', ''),
                        'detail': '', 'severity': 'High'})
    for f in getattr(result, 'mass_assignment', []) or []:
        for entry in getattr(f, 'accepted_fields', []) or []:
            out.append({'type': 'mass_assignment(API3)', 'endpoint': getattr(f, 'target_url', ''),
                        'detail': entry.get('field', ''), 'severity': 'High',
                        'status': 'confirmed'})
        for entry in getattr(f, 'suspected_fields', []) or []:
            out.append({'type': 'mass_assignment(API3)', 'endpoint': getattr(f, 'target_url', ''),
                        'detail': entry.get('field', ''), 'severity': 'Low',
                        'status': 'suspected'})
    for f in getattr(result, 'hidden_params', []) or []:
        for entry in getattr(f, 'active_params', []) or []:
            out.append({'type': 'hidden_params(API5)', 'endpoint': getattr(f, 'target_url', ''),
                        'detail': entry.get('name', ''), 'severity': 'Medium'})
    return out


@dataclass
class GateResult:
    new: List[Dict] = field(default_factory=list)          # tous les nouveaux
    new_suspected: List[Dict] = field(default_factory=list)  # sous-ensemble non confirmé
    fixed: List[str] = field(default_factory=list)      # signatures disparues
    unchanged: List[str] = field(default_factory=list)
    passed: bool = True
    baseline_updated: bool = False

    @property
    def new_confirmed(self) -> List[Dict]:
        return [n for n in self.new if n.get('status', 'confirmed') != 'suspected']

    def summary(self) -> Dict:
        return {'new': len(self.new), 'new_confirmed': len(self.new_confirmed),
                'new_suspected': len(self.new_suspected), 'fixed': len(self.fixed),
                'unchanged': len(self.unchanged), 'passed': self.passed,
                'baseline_updated': self.baseline_updated}


class RegressionGate:
    """Compare les findings courants à une baseline ; échoue sur du nouveau."""

    def __init__(self, baseline_path: str):
        self.baseline_path = Path(baseline_path)

    def load_baseline(self) -> Set[str]:
        if not self.baseline_path.exists():
            return set()
        try:
            data = json.loads(self.baseline_path.read_text())
            return set(data.get('signatures', []))
        except (OSError, ValueError):
            return set()

    def save_baseline(self, findings: List[Dict], meta: Optional[Dict] = None) -> None:
        signatures = sorted({finding_signature(f) for f in findings})
        payload = {
            'version': 1,
            'generated_at': datetime.now().isoformat(timespec='seconds'),
            'signatures': signatures,
            **(meta or {}),
        }
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_path.write_text(json.dumps(payload, indent=2))

    def evaluate(self, findings: List[Dict], update: bool = False,
                 meta: Optional[Dict] = None, strict: bool = False) -> GateResult:
        """Compare, décide du verdict, et met à jour la baseline si demandé.

        - update=False : la gate échoue s'il y a au moins un nouveau finding
          CONFIRMÉ. Les nouveaux findings SUSPECTÉS (non prouvés) sont remontés
          mais ne cassent pas le build — sauf `strict=True` (échoue sur tout
          nouveau, confirmé ou suspecté).
        - update=True  : on accepte l'état courant comme nouvelle baseline
          (verdict toujours vert).

        Le statut ne fait PAS partie de la signature : un même finding qui passe
        de suspecté à confirmé reste la même signature (pas un « fixed + new »).
        """
        baseline = self.load_baseline()
        by_sig: Dict[str, Dict] = {}
        for f in findings:
            by_sig.setdefault(finding_signature(f), f)
        current = set(by_sig)

        new_sigs = current - baseline
        fixed = sorted(baseline - current)
        unchanged = sorted(current & baseline)

        new = [{**by_sig[s], 'signature': s} for s in sorted(new_sigs)]
        new_suspected = [n for n in new if n.get('status', 'confirmed') == 'suspected']
        failing = new if strict else [n for n in new if n.get('status', 'confirmed') != 'suspected']

        result = GateResult(
            new=new,
            new_suspected=new_suspected,
            fixed=fixed,
            unchanged=unchanged,
            passed=update or not failing,
        )

        if update:
            self.save_baseline(findings, meta)
            result.baseline_updated = True
        return result
