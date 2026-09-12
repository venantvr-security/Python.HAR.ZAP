"""
Rapport de couverture honnête.

Un scanner en qui on a confiance dit aussi ce qu'il n'a PAS testé. Ce module
répond à deux questions : quels endpoints observés ont été réellement testés, et
quelles catégories OWASP API ont été activement sondées vs laissées de côté.

IA : AUCUNE, volontairement. La couverture est de la comptabilité — elle doit être
exacte et reproductible, jamais « estimée » par un modèle.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Set

from .regression_gate import endpoint_template

# Les 10 risques OWASP API 2023 et le statut de couverture ACTIVE de HAR-ZAP.
API_CATEGORIES = {
    'API1': 'Broken Object Level Authorization',
    'API2': 'Broken Authentication',
    'API3': 'Broken Object Property Level Authorization',
    'API4': 'Unrestricted Resource Consumption',
    'API5': 'Broken Function Level Authorization',
    'API6': 'Unrestricted Access to Sensitive Business Flows',
    'API7': 'Server-Side Request Forgery',
    'API8': 'Security Misconfiguration',
    'API9': 'Improper Inventory Management',
    'API10': 'Unsafe Consumption of APIs',
}


def har_endpoints(har_data: Dict) -> Set[str]:
    """Ensemble des endpoints observés (gabarit « METHOD /path/{id} »)."""
    out = set()
    for e in (har_data or {}).get('log', {}).get('entries', []) or []:
        req = e.get('request', {})
        url, method = req.get('url', ''), req.get('method', 'GET').upper()
        if url:
            out.add(f"{method} {endpoint_template(url)}")
    return out


@dataclass
class CoverageReport:
    observed: List[str] = field(default_factory=list)
    tested: List[str] = field(default_factory=list)
    untested: List[str] = field(default_factory=list)
    categories_tested: List[str] = field(default_factory=list)
    categories_not_tested: List[str] = field(default_factory=list)

    @property
    def endpoint_pct(self) -> float:
        return round(100.0 * len(self.tested) / max(len(self.observed), 1), 1)

    @property
    def category_pct(self) -> float:
        total = len(self.categories_tested) + len(self.categories_not_tested)
        return round(100.0 * len(self.categories_tested) / max(total, 1), 1)

    def to_dict(self) -> Dict:
        return {'endpoint_coverage_pct': self.endpoint_pct,
                'category_coverage_pct': self.category_pct,
                'observed': len(self.observed), 'tested': len(self.tested),
                'untested': self.untested,
                'categories_tested': sorted(self.categories_tested),
                'categories_not_tested': sorted(self.categories_not_tested)}


def build_coverage(har_data: Dict, tested_endpoints: Set[str],
                   categories_run: Set[str]) -> CoverageReport:
    observed = har_endpoints(har_data)
    tested = observed & set(tested_endpoints)
    untested = observed - tested
    cat_run = {c.split(':')[0] for c in categories_run}  # normalise 'API1:2023' -> 'API1'
    cat_tested = [c for c in API_CATEGORIES if c in cat_run]
    cat_not = [c for c in API_CATEGORIES if c not in cat_run]
    return CoverageReport(
        observed=sorted(observed), tested=sorted(tested), untested=sorted(untested),
        categories_tested=cat_tested, categories_not_tested=cat_not)


def render_cli(rep: CoverageReport) -> str:
    lines = [f"\n{'='*56}", "COVERAGE (what was actually tested)", '='*56,
             f"Endpoints:  {len(rep.tested)}/{len(rep.observed)} tested ({rep.endpoint_pct}%)",
             f"OWASP API:  {len(rep.categories_tested)}/10 categories actively probed "
             f"({rep.category_pct}%)"]
    if rep.categories_not_tested:
        names = ', '.join(f"{c}" for c in rep.categories_not_tested)
        lines.append(f"Not covered: {names}")
    if rep.untested:
        lines.append(f"Untested endpoints ({len(rep.untested)}):")
        for ep in rep.untested[:15]:
            lines.append(f"  · {ep}")
        if len(rep.untested) > 15:
            lines.append(f"  … (+{len(rep.untested) - 15} more)")
    return '\n'.join(lines) + '\n'
