"""
Matrice d'accès multi-rôles — la carte définitive du contrôle d'accès.

L'IDOR à deux sessions répond « user B peut-il lire l'objet de user A ? ». La
matrice généralise : N rôles (anonyme, user, admin…) × tous les endpoints observés
→ une grille « qui atteint quoi ». C'est ce qu'un pentester construit à la main
pour cartographier BOLA (API1) et BFLA (API5).

Principe : les rôles sont fournis par privilège croissant (index 0 = le moins
privilégié). Un endpoint est « possédé » par le rôle le plus privilégié dont le
trafic capturé le contenait. Violation = un rôle MOINS privilégié que le
propriétaire obtient un accès autorisé (2xx) sur cet endpoint — une frontière
d'autorisation franchie.

L'exécuteur HTTP est injecté (`execute_fn(url, method, headers)`), donc testable
hors-ligne et routable à travers ZAP en production.
"""
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .utils import get_logger
from .regression_gate import endpoint_template

logger = get_logger("access.matrix")

# execute_fn(url, method, headers) -> {'status': int, 'content_length': int, 'body': str}
ExecuteFn = Callable[[str, str, Dict], Dict]


@dataclass
class Role:
    name: str
    headers: Dict[str, str] = field(default_factory=dict)
    priv: int = 0  # index de privilège croissant


@dataclass
class Endpoint:
    template: str
    url: str          # échantillon concret (du rôle légitime le moins privilégié)
    method: str
    min_priv: int     # index du rôle le MOINS privilégié l'ayant légitimement utilisé


@dataclass
class Violation:
    endpoint: str
    method: str
    role: str
    requires_role: str   # rôle le moins privilégié censé y avoir accès
    status: int
    severity: str = 'High'

    @property
    def detail(self) -> str:
        return (f"{self.role} reaches {self.method} {self.endpoint} "
                f"(requires {self.requires_role}) — status {self.status}")


@dataclass
class AccessMatrix:
    roles: List[str]
    endpoints: List[str]
    grid: Dict[str, Dict[str, int]] = field(default_factory=dict)  # endpoint -> {role: status}
    violations: List[Violation] = field(default_factory=list)

    def summary(self) -> Dict:
        return {'roles': self.roles, 'endpoints': len(self.endpoints),
                'violations': len(self.violations)}

    def violation_findings(self) -> List[Dict]:
        """Findings « à plat » réutilisables par la sortie findings-first et la gate."""
        return [{'source': 'access_matrix', 'risk': v.severity,
                 'name': f"Access-control break — {v.detail}", 'url': v.endpoint}
                for v in self.violations]


def _entries(har: Dict) -> List[Dict]:
    return (har or {}).get('log', {}).get('entries', []) or []


def build_endpoints(role_hars: List[Tuple[str, Dict]]) -> List[Endpoint]:
    """Union des endpoints de tous les HAR, avec propriétaire = rôle le plus
    privilégié (index le plus haut) l'ayant utilisé. `role_hars` est en privilège
    croissant.
    """
    by_tpl: Dict[str, Endpoint] = {}
    for priv, (_name, har) in enumerate(role_hars):
        for e in _entries(har):
            req = e.get('request', {})
            url, method = req.get('url', ''), req.get('method', 'GET').upper()
            if not url:
                continue
            tpl = f"{method} {endpoint_template(url)}"
            # Itération en privilège croissant : la première insertion fixe le rôle
            # légitime le moins privilégié (le plancher d'autorisation) et sa ressource.
            if tpl not in by_tpl:
                by_tpl[tpl] = Endpoint(tpl, url, method, priv)
    return list(by_tpl.values())


def run_matrix(roles: List[Role], endpoints: List[Endpoint],
               execute_fn: ExecuteFn, max_workers: int = 8) -> AccessMatrix:
    """Construit la grille rôle×endpoint et en déduit les violations.

    Perf : les N×M requêtes (rôle × endpoint) sont indépendantes → exécutées en
    parallèle (pool de threads, I/O-bound). Le calcul des violations se fait
    ensuite de façon séquentielle et ordonnée, donc le résultat reste déterministe.
    """
    from concurrent.futures import ThreadPoolExecutor
    role_names = [r.name for r in roles]
    matrix = AccessMatrix(roles=role_names, endpoints=[e.template for e in endpoints])

    tasks = [(ep, role) for ep in endpoints for role in roles]

    def _call(task):
        ep, role = task
        resp = execute_fn(ep.url, ep.method, role.headers) or {}
        return (ep.template, role.name, int(resp.get('status', 0)))

    results: Dict = {}
    if max_workers > 1 and len(tasks) > 1:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            for tpl, rname, status in ex.map(_call, tasks):
                results[(tpl, rname)] = status
    else:
        for task in tasks:
            tpl, rname, status = _call(task)
            results[(tpl, rname)] = status

    # Calcul déterministe (ordre des endpoints puis des rôles) une fois l'I/O terminé.
    for ep in endpoints:
        cells: Dict[str, int] = {}
        requires_role = roles[ep.min_priv].name if ep.min_priv < len(roles) else '?'
        for role in roles:
            status = results.get((ep.template, role.name), 0)
            cells[role.name] = status
            if 200 <= status < 300 and role.priv < ep.min_priv:
                matrix.violations.append(Violation(
                    endpoint=ep.template, method=ep.method, role=role.name,
                    requires_role=requires_role, status=status,
                    severity='Critical' if role.priv == 0 else 'High'))
                logger.info("access_violation", endpoint=ep.template,
                            role=role.name, requires=requires_role, status=status)
        matrix.grid[ep.template] = cells

    return matrix


def render_matrix_cli(matrix: AccessMatrix, max_rows: int = 40) -> str:
    """Grille compacte en texte : lignes = endpoints, colonnes = rôles."""
    if not matrix.endpoints:
        return "\nACCESS MATRIX: no endpoints.\n"
    roles = matrix.roles
    w = max((len(e) for e in matrix.endpoints), default=10)
    w = min(w, 52)
    head = "endpoint".ljust(w) + "  " + "  ".join(r[:8].center(8) for r in roles)
    lines = [f"\n{'='*len(head)}", "ACCESS MATRIX (rôle × endpoint)", '='*len(head), head, '-'*len(head)]
    for ep in matrix.endpoints[:max_rows]:
        cells = matrix.grid.get(ep, {})
        row = ep[:w].ljust(w) + "  "
        marks = []
        for r in roles:
            st = cells.get(r, 0)
            mark = 'OK' if 200 <= st < 300 else ('--' if st in (401, 403) else str(st or '·'))
            marks.append(mark.center(8))
        lines.append(row + "  ".join(marks))
    if len(matrix.endpoints) > max_rows:
        lines.append(f"… (+{len(matrix.endpoints) - max_rows} more)")
    lines.append('-'*len(head))
    lines.append(f"Violations: {len(matrix.violations)}  (OK = 2xx, -- = denied)")
    for v in matrix.violations[:20]:
        lines.append(f"  ! {v.detail}")
    return '\n'.join(lines) + '\n'
