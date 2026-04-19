"""
UI layer for the advanced attack modules so they can run from Streamlit —
previously these were CLI-only. Each runner wraps an existing attack tester,
executes it against the uploaded HAR, and returns a structured result +
a short verdict string ready for the UI.

Keeping this module decoupled from `app.py` means it can also be reused by
the FastAPI layer (see web/api/routes/attacks.py) and by tests.
"""
from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any, Callable, Dict, List, Optional

# Canonical list of advanced attack keys used by the UI selector.
ADVANCED_ATTACKS: List[str] = [
    "jwt",
    "cors",
    "cache_poisoning",
    "http_smuggling",
    "timing",
    "graphql",
    "websocket",
]

ATTACK_LABELS: Dict[str, str] = {
    "jwt": "🔑 JWT attacks",
    "cors": "🌐 CORS misconfig",
    "cache_poisoning": "💾 Cache poisoning",
    "http_smuggling": "🧵 HTTP request smuggling",
    "timing": "⏱️ Blind timing",
    "graphql": "📊 GraphQL",
    "websocket": "🔌 WebSocket (CSWSH)",
}


def _to_dict(item: Any) -> Dict[str, Any]:
    if is_dataclass(item):
        return asdict(item)
    if isinstance(item, dict):
        return item
    return {"value": str(item)}


def _count_vulnerable(results: List[Dict[str, Any]]) -> int:
    return sum(1 for r in results if r.get("vulnerable"))


def run_jwt(har_data: Dict, config: Optional[Dict] = None, zap_client: Any = None) -> Dict:
    from modules.jwt_attacks import JWTAttackTester
    tester = JWTAttackTester(har_data, config=config, zap_client=zap_client)
    raw = tester.run_tests()
    results = [_to_dict(r) for r in raw]
    vuln = _count_vulnerable(results)
    return {
        "attack": "jwt",
        "findings": results,
        "verdict": _verdict(len(results), vuln),
        "summary": f"{len(results)} JWT test(s), {vuln} vulnerable",
    }


def run_cors(har_data: Dict, config: Optional[Dict] = None, zap_client: Any = None) -> Dict:
    from modules.cors_tester import CORSTester
    tester = CORSTester(har_data, config=config, zap_client=zap_client)
    raw = tester.run_tests()
    results = [_to_dict(r) for r in raw]
    vuln = _count_vulnerable(results)
    return {
        "attack": "cors",
        "findings": results,
        "verdict": _verdict(len(results), vuln),
        "summary": f"{len(results)} CORS test(s), {vuln} vulnerable",
    }


def run_cache_poisoning(har_data: Dict, config: Optional[Dict] = None, zap_client: Any = None) -> Dict:
    from modules.cache_poisoning import CachePoisoningTester
    tester = CachePoisoningTester(har_data, config=config, zap_client=zap_client)
    raw = tester.run_tests()
    results = [_to_dict(r) for r in raw]
    vuln = _count_vulnerable(results)
    return {
        "attack": "cache_poisoning",
        "findings": results,
        "verdict": _verdict(len(results), vuln),
        "summary": f"{len(results)} cache-poison test(s), {vuln} vulnerable",
    }


def run_http_smuggling(har_data: Dict, config: Optional[Dict] = None, zap_client: Any = None) -> Dict:
    from modules.http_smuggling import HTTPSmugglingTester
    tester = HTTPSmugglingTester(har_data, config=config, zap_client=zap_client)
    raw = tester.run_tests()
    results = [_to_dict(r) for r in raw]
    vuln = _count_vulnerable(results)
    variants = sorted({r.get("variant") for r in results if r.get("variant")})
    return {
        "attack": "http_smuggling",
        "findings": results,
        "verdict": _verdict(len(results), vuln),
        "summary": f"{len(results)} smuggling test(s) across {len(variants)} variants, {vuln} vulnerable",
        "variants": variants,
    }


def run_timing(har_data: Dict, config: Optional[Dict] = None, zap_client: Any = None) -> Dict:
    from modules.timing_analysis import TimingAnalyzer
    tester = TimingAnalyzer(har_data, config=config, zap_client=zap_client)
    raw = tester.run_tests(parallel=False)
    results = [_to_dict(r) for r in raw]
    vuln = sum(1 for r in results if r.get("verdict") == "LIKELY_VULNERABLE" or r.get("vulnerable"))
    inconclusive = sum(1 for r in results if r.get("verdict") == "INCONCLUSIVE")
    return {
        "attack": "timing",
        "findings": results,
        "verdict": _verdict(len(results), vuln),
        "summary": f"{len(results)} timing test(s), {vuln} likely vulnerable, {inconclusive} inconclusive",
    }


def run_graphql(har_data: Dict, config: Optional[Dict] = None, zap_client: Any = None) -> Dict:
    from modules.graphql_scanner import GraphQLScanner
    scanner = GraphQLScanner(har_data, config=config, zap_client=zap_client)
    # Prefer sync wrapper when available, otherwise run the coroutine manually.
    if hasattr(scanner, "scan_all_sync"):
        raw = scanner.scan_all_sync()
    else:
        import asyncio
        raw = asyncio.run(scanner.scan_all())
    results = (raw or {}).get("vulnerabilities", []) or []
    endpoints = (raw or {}).get("endpoints", []) or []
    return {
        "attack": "graphql",
        "endpoints": endpoints,
        "findings": results,
        "verdict": _verdict(len(endpoints), len(results)),
        "summary": f"{len(endpoints)} GraphQL endpoint(s), {len(results)} issue(s)",
    }


def run_websocket(har_data: Dict, config: Optional[Dict] = None, zap_client: Any = None) -> Dict:
    from modules.websocket_scanner import WebSocketScanner
    scanner = WebSocketScanner(har_data, config=config, zap_client=zap_client)
    if hasattr(scanner, "scan_all_sync"):
        raw = scanner.scan_all_sync()
    else:
        import asyncio
        raw = asyncio.run(scanner.scan_all())
    results = (raw or {}).get("vulnerabilities", []) or []
    endpoints = (raw or {}).get("endpoints", []) or []
    return {
        "attack": "websocket",
        "endpoints": endpoints,
        "findings": results,
        "verdict": _verdict(len(endpoints), len(results)),
        "summary": f"{len(endpoints)} WS endpoint(s), {len(results)} issue(s)",
    }


RUNNERS: Dict[str, Callable[..., Dict]] = {
    "jwt": run_jwt,
    "cors": run_cors,
    "cache_poisoning": run_cache_poisoning,
    "http_smuggling": run_http_smuggling,
    "timing": run_timing,
    "graphql": run_graphql,
    "websocket": run_websocket,
}


def run(attack_key: str, har_data: Dict, config: Optional[Dict] = None, zap_client: Any = None) -> Dict:
    """Dispatch to the matching runner. Raises KeyError on unknown attack."""
    runner = RUNNERS.get(attack_key)
    if runner is None:
        raise KeyError(f"unknown advanced attack: {attack_key}")
    return runner(har_data, config=config, zap_client=zap_client)


def _verdict(total: int, vuln: int) -> str:
    """Uniform verdict phrase shared by every attack for the UI banner.

    Quatre états, car le pentesteur doit distinguer :
    - NO_TARGETS     : aucune cible éligible dans le HAR (pas de JWT, pas de
                       WebSocket, etc.) — ce n'est PAS un succès, l'attaque n'a
                       tout simplement pas tourné.
    - NOT_VULNERABLE : au moins une cible testée, aucune vulnérable.
    - VULNERABLE     : toutes les cibles testées sont vulnérables (rare, signe
                       d'un défaut systémique — à investiguer).
    - PARTIAL        : mélange — le cas le plus fréquent en pratique.
    """
    if total == 0:
        return "NO_TARGETS"
    if vuln == 0:
        return "NOT_VULNERABLE"
    if vuln == total:
        return "VULNERABLE"
    return "PARTIAL"


def verdict_color(verdict: str) -> str:
    """Map verdict to Streamlit delta_color for st.metric (normal/inverse/off)."""
    return {
        "VULNERABLE": "inverse",
        "PARTIAL": "inverse",
        "NOT_VULNERABLE": "off",
        "NO_TARGETS": "off",
    }.get(verdict, "off")
