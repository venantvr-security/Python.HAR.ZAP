"""
Consommation d'API tierces non sûre — OWASP API10 (Unsafe Consumption of APIs).

Une application fait confiance aux données d'API tierces/amont. Depuis un HAR on
ne voit pas toujours les appels serveur→tiers, mais on voit les dépendances
tierces présentes dans le trafic. On en tire des signaux défendables :

  1. Appel d'une API tierce en clair (http://)      → interception possible (High).
  2. Redirection suivie vers un hôte tiers           → confiance non validée (Medium).
  3. Inventaire des dépendances tierces              → « valide les données consommées » (info).

IA : le cœur est déterministe (comparaison de domaine enregistrable, schéma d'URL).
L'IA n'intervient que pour classer, en option, si une dépendance paraît sensible
(fournisseur d'auth/paiement) — jugement ; sinon heuristique par mots-clés.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse

# Hôtes first-party évidents à ne pas compter comme « tiers » vis-à-vis de la cible.
_SENSITIVE_DEP = ('auth', 'oauth', 'login', 'pay', 'payment', 'stripe', 'paypal',
                  'billing', 'sso', 'token', 'identity', 'kyc', 'bank')


def registrable_domain(host: str) -> str:
    """eTLD+1 approximé (deux derniers labels). Suffisant pour distinguer un tiers."""
    host = (host or '').split(':')[0].lower()
    labels = [l for l in host.split('.') if l]
    return '.'.join(labels[-2:]) if len(labels) >= 2 else host


@dataclass
class ConsumptionFinding:
    kind: str          # cleartext / redirect / dependency
    severity: str
    title: str
    url: str
    detail: str = ''

    def flat(self) -> Dict:
        return {'source': 'unsafe_consumption', 'risk': self.severity,
                'name': self.title, 'url': self.url}


def analyze_consumption(har_data: Dict, target: str, classifier=None) -> List[ConsumptionFinding]:
    """Détecte la consommation d'API tierces non sûre à partir du HAR."""
    target_dom = registrable_domain(urlparse(target).netloc or target)
    findings: List[ConsumptionFinding] = []
    seen_deps = set()

    for e in (har_data or {}).get('log', {}).get('entries', []) or []:
        req = e.get('request', {})
        url = req.get('url', '')
        if not url:
            continue
        parsed = urlparse(url)
        dom = registrable_domain(parsed.netloc)

        # 2. Redirection vers un hôte tiers — vérifiée même depuis un endpoint
        # first-party (c'est justement le cas à risque : notre API renvoie vers un tiers).
        status = (e.get('response', {}) or {}).get('status', 0)
        if status in (301, 302, 303, 307, 308):
            loc = ''
            for h in (e.get('response', {}) or {}).get('headers', []):
                if h.get('name', '').lower() == 'location':
                    loc = h.get('value', '')
            loc_dom = registrable_domain(urlparse(loc).netloc) if loc else ''
            if loc_dom and loc_dom != target_dom:
                findings.append(ConsumptionFinding('redirect', 'Medium',
                    f"Redirect followed to third-party host ({loc_dom})", url,
                    f'Location: {loc}'))

        if not dom or dom == target_dom:
            continue  # first-party : le reste (cleartext, inventaire) ne s'applique pas

        # 1. Dépendance tierce en clair (pas de TLS).
        if parsed.scheme == 'http':
            findings.append(ConsumptionFinding('cleartext', 'High',
                f"Third-party API consumed over cleartext HTTP ({dom})", url,
                'Upstream data can be tampered in transit (no TLS)'))

        # 3. Inventaire des dépendances tierces (une par domaine).
        if dom not in seen_deps:
            seen_deps.add(dom)
            low = dom.lower()
            sensitive = any(h in low for h in _SENSITIVE_DEP)
            reason = 'sensitive provider (auth/payment)' if sensitive else ''
            if classifier is not None and getattr(classifier, 'available', False):
                v = classifier.classify_owasp(
                    {'alert': f'Third-party dependency {dom}', 'url': url},
                    {'API10:2023': 'Unsafe Consumption of APIs'})
                if v:
                    sensitive, reason = True, v.get('reason', 'LLM: sensitive dependency')
            findings.append(ConsumptionFinding('dependency',
                'Medium' if sensitive else 'Low',
                f"Third-party dependency: {dom}"
                + (f" — {reason}" if reason else ''),
                url, 'Validate and constrain data consumed from this API'))

    return findings


def consumption_findings_flat(findings: List[ConsumptionFinding]) -> List[Dict]:
    return [f.flat() for f in findings]
