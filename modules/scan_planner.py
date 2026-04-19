"""
Scan planner — produces a dry-run report of what a scan would do.

A dry-run answers the pentester's « what happens if I click Launch? » *before*
any request is sent:
  - which endpoints will be scanned, and under which ZAP policy
  - how many requests will be emitted (rough upper bound)
  - how long it should take given the configured rate limit
  - which Python attack modules would run
  - which ZAP JS scripts would be loaded

This is the UI-agnostic layer. CLI prints it as text, Streamlit renders it
as a preview panel; both call the same `plan_scan()` and `format_plan()`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


# Estimation grossière du nombre de requêtes émises par cible. Les vraies
# valeurs dépendent des politiques ZAP activées et du nombre de paramètres
# fuzzables. 40 est la médiane observée sur Default + SQL + XSS pour un
# endpoint à un paramètre. En mode « full assault » (toutes politiques
# activées), le volume triple environ. Ces nombres ne cherchent pas la
# précision : ils servent juste à prévenir le pentesteur quand un scan
# devient manifestement trop long ou trop bruyant avant lancement.
REQUESTS_PER_TARGET_DEFAULT = 40
REQUESTS_PER_TARGET_FULL_ASSAULT = 120

# Attack-type → Python module mapping used by the red-team pipeline
REDTEAM_MODULES = {
    'unauth_replay': 'modules.redteam_attacks.UnauthenticatedReplayAttack',
    'mass_assignment': 'modules.redteam_attacks.MassAssignmentTester',
    'hidden_params': 'modules.redteam_attacks.HiddenParameterTester',
    'race_condition': 'modules.redteam_attacks.RaceConditionTester',
}


@dataclass
class ScanPlan:
    targets: List[Dict[str, Any]] = field(default_factory=list)
    scripts_to_load: List[str] = field(default_factory=list)
    python_attacks: List[str] = field(default_factory=list)
    estimated_requests: int = 0
    estimated_duration_s: float = 0.0
    rate_limit: float = 10.0
    full_assault: bool = False
    scope_domains: List[str] = field(default_factory=list)
    exclude_domains: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'targets': self.targets,
            'scripts_to_load': self.scripts_to_load,
            'python_attacks': self.python_attacks,
            'estimated_requests': self.estimated_requests,
            'estimated_duration_s': self.estimated_duration_s,
            'rate_limit': self.rate_limit,
            'full_assault': self.full_assault,
            'scope_domains': self.scope_domains,
            'exclude_domains': self.exclude_domains,
            'warnings': self.warnings,
            'summary': {
                'target_count': len(self.targets),
                'script_count': len(self.scripts_to_load),
                'python_attack_count': len(self.python_attacks),
                'estimated_duration_pretty': _format_duration(self.estimated_duration_s),
            },
        }


def plan_scan(
    har_data: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None,
    scripts_dir: Optional[Path] = None,
) -> ScanPlan:
    """Build a ScanPlan from the HAR and effective config. No network I/O."""
    config = config or {}
    rate_limit = float(config.get('rate_limit', 10.0))
    full_assault = bool(config.get('full_assault', False))
    scope_domains = list(config.get('scope_domains', []) or [])
    exclude_domains = list(config.get('exclude_domains', []) or [])

    targets = _collect_targets(har_data, config)
    scripts = _list_scripts(scripts_dir or Path(__file__).parent.parent / 'scripts')
    python_attacks = _list_python_attacks(config)

    per_target = REQUESTS_PER_TARGET_FULL_ASSAULT if full_assault else REQUESTS_PER_TARGET_DEFAULT
    estimated_requests = per_target * len(targets)
    estimated_duration_s = estimated_requests / rate_limit if rate_limit > 0 else 0.0

    warnings: List[str] = []
    if not targets:
        warnings.append("No fuzzable URLs or API endpoints in HAR — scan would be a no-op.")
    if full_assault:
        warnings.append("FULL ZAP ASSAULT is enabled: request volume x3 vs default.")
    if rate_limit <= 1.0:
        warnings.append(f"Rate limit very low ({rate_limit} req/s) — scan will be slow.")
    if not scope_domains:
        warnings.append("No scope_domains: scan will target every HAR domain (possible out-of-scope requests).")

    return ScanPlan(
        targets=targets,
        scripts_to_load=scripts,
        python_attacks=python_attacks,
        estimated_requests=estimated_requests,
        estimated_duration_s=estimated_duration_s,
        rate_limit=rate_limit,
        full_assault=full_assault,
        scope_domains=scope_domains,
        exclude_domains=exclude_domains,
        warnings=warnings,
    )


def _collect_targets(har_data: Dict[str, Any], config: Dict[str, Any]) -> List[Dict[str, Any]]:
    max_fuzzable = int(config.get('max_fuzzable_urls', 20))
    max_api = int(config.get('max_api_endpoints', 10))

    fuzzable = (har_data.get('fuzzable_urls') or [])[:max_fuzzable]
    apis = (har_data.get('api_endpoints') or [])[:max_api]

    targets = []
    for t in fuzzable:
        targets.append({
            'url': t.get('url', ''),
            'method': t.get('method', 'GET'),
            'params': list(t.get('params') or []),
            'type': 'fuzzable',
            'policy': _policy_for(t),
        })
    for a in apis:
        targets.append({
            'url': a.get('url', ''),
            'method': a.get('method', 'GET'),
            'params': list(a.get('params') or []),
            'type': 'api',
            'policy': 'API-Minimal',
        })
    return targets


def _policy_for(target: Dict[str, Any]) -> str:
    # Heuristique volontairement simple : on devine la politique ZAP adaptée à
    # partir du nom des paramètres. Un paramètre `id`, `user_id`, `sql_query`,
    # … déclenche SQL-Injection ; `file`, `filename`, `path` → Path-Traversal.
    # Le but n'est pas la couverture exhaustive (ZAP la fait déjà) mais
    # d'éviter de lancer une politique coûteuse sur un endpoint qui n'en a
    # clairement pas besoin.
    params = [p.lower() for p in (target.get('params') or [])]
    if any('sql' in p or 'id' in p for p in params):
        return 'SQL-Injection'
    if any('file' in p or 'path' in p for p in params):
        return 'Path-Traversal'
    return 'Default Policy'


def _list_scripts(scripts_dir: Path) -> List[str]:
    out: List[str] = []
    if not scripts_dir.exists():
        return out
    for kind in ('active', 'passive'):
        subdir = scripts_dir / kind
        if subdir.exists():
            for p in sorted(subdir.glob('*.js')):
                out.append(f"{kind}/{p.name}")
    return out


def _list_python_attacks(config: Dict[str, Any]) -> List[str]:
    # If attack_strategies is provided in config, honour the enabled flag
    strategies = config.get('attack_strategies') or []
    if strategies:
        return [s['id'] for s in strategies if s.get('enabled', True) and s.get('id') in REDTEAM_MODULES]
    return list(REDTEAM_MODULES.keys())


def _format_duration(seconds: float) -> str:
    seconds = max(0.0, seconds)
    if seconds < 60:
        return f"{seconds:.0f}s"
    minutes, s = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m{s:02d}s"
    hours, m = divmod(minutes, 60)
    return f"{hours}h{m:02d}m"


def format_plan(plan: ScanPlan, *, colour: bool = False) -> str:
    """Human-readable multiline summary — used by CLI `--dry-run`."""
    def bullet(s: str) -> str:
        return f"  - {s}"

    lines: List[str] = []
    lines.append("=" * 72)
    lines.append("DRY-RUN — what the scan would do")
    lines.append("=" * 72)
    lines.append(f"Targets:         {len(plan.targets)}")
    lines.append(f"JS scripts:      {len(plan.scripts_to_load)}")
    lines.append(f"Python attacks:  {len(plan.python_attacks)}")
    lines.append(f"Rate limit:      {plan.rate_limit} req/s")
    lines.append(f"Full assault:    {plan.full_assault}")
    lines.append(f"Estimated reqs:  {plan.estimated_requests}")
    lines.append(f"Estimated time:  {_format_duration(plan.estimated_duration_s)}")

    if plan.scope_domains:
        lines.append(f"Scope domains:   {', '.join(plan.scope_domains)}")
    if plan.exclude_domains:
        lines.append(f"Exclude domains: {', '.join(plan.exclude_domains)}")

    if plan.warnings:
        lines.append("")
        lines.append("Warnings:")
        for w in plan.warnings:
            lines.append(bullet(w))

    if plan.targets:
        lines.append("")
        lines.append(f"First {min(10, len(plan.targets))} targets:")
        for t in plan.targets[:10]:
            lines.append(bullet(f"[{t['type']}] {t['method']} {t['url']}  → policy={t['policy']}"))

    if plan.scripts_to_load:
        lines.append("")
        lines.append("Scripts loaded:")
        for s in plan.scripts_to_load:
            lines.append(bullet(s))

    if plan.python_attacks:
        lines.append("")
        lines.append("Python attacks enabled:")
        for a in plan.python_attacks:
            lines.append(bullet(a))

    lines.append("=" * 72)
    return "\n".join(lines)
