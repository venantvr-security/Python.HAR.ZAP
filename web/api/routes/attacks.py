"""
Advanced Attack Routes

All attacks routed through ZAP Orchestrator for unified execution and alerting.
"""
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional, List, Dict
import asyncio

router = APIRouter()


class AttackRequest(BaseModel):
    strategy: str
    target_url: Optional[str] = None
    use_zap: Optional[bool] = True  # Always True - ZAP is the orchestrator


class PipelineRequest(BaseModel):
    strategies: Optional[List[str]] = None  # None = all enabled strategies
    run_discovery: Optional[bool] = True
    run_fuzzing: Optional[bool] = False


@router.get("/strategies")
async def list_strategies(request: Request):
    """List available attack strategies"""
    config = request.app.state.shared['config'] or {}
    strategies = config.get('attack_strategies', [])
    return {"strategies": strategies}


@router.post("/pipeline")
async def run_pipeline(request: Request, pipeline: PipelineRequest):
    """Run full ZAP orchestrated pipeline: HAR → Context → Discovery → Scans → Alerts"""
    har_service = request.app.state.shared['har_service']
    zap_service = request.app.state.shared['zap_service']
    config = request.app.state.shared['config'] or {}

    if not har_service.current_har:
        raise HTTPException(status_code=400, detail="No HAR loaded. Upload HAR first.")

    if not zap_service or not zap_service.is_running:
        raise HTTPException(status_code=400, detail="ZAP not running. Start ZAP first.")

    try:
        from modules.zap_orchestrator import ZAPOrchestrator

        orchestrator = ZAPOrchestrator(
            zap_url=zap_service.zap_url,
            api_key=zap_service.api_key,
            har_data=har_service.current_har,
            config=config
        )

        results = orchestrator.run_pipeline(strategies=pipeline.strategies)

        if pipeline.run_fuzzing:
            fuzzing_results = orchestrator.run_fuzzing()
            results['fuzzing'] = fuzzing_results

        return {
            "status": "completed",
            "orchestrator": "ZAP",
            "results": results
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/run")
async def run_attack(request: Request, attack: AttackRequest):
    """Run a single attack strategy via ZAP Orchestrator"""
    har_service = request.app.state.shared['har_service']
    zap_service = request.app.state.shared['zap_service']
    config = request.app.state.shared['config'] or {}

    if not har_service.current_har:
        raise HTTPException(status_code=400, detail="No HAR loaded. Upload HAR first.")

    strategies = {s['id']: s for s in config.get('attack_strategies', [])}
    if attack.strategy not in strategies:
        raise HTTPException(status_code=400, detail=f"Unknown strategy: {attack.strategy}")

    strategy = strategies[attack.strategy]
    if not strategy.get('enabled', True):
        raise HTTPException(status_code=400, detail=f"Strategy disabled: {attack.strategy}")

    har_data = har_service.current_har

    # Always use ZAP Orchestrator when ZAP is running
    if zap_service and zap_service.is_running:
        try:
            from modules.zap_orchestrator import ZAPOrchestrator

            orchestrator = ZAPOrchestrator(
                zap_url=zap_service.zap_url,
                api_key=zap_service.api_key,
                har_data=har_data,
                config=config
            )

            results = orchestrator.run_single_strategy(attack.strategy)
            return {
                "strategy": attack.strategy,
                "status": "completed",
                "routed_via_zap": True,
                "orchestrator": "ZAP",
                "results": results
            }
        except Exception as e:
            # Fallback to legacy module execution
            pass

    # Legacy fallback when ZAP not available
    module_name = strategy['module']
    zap_client = None
    if attack.use_zap and zap_service and zap_service.is_running:
        zap_client = zap_service.get_http_client()

    try:
        results = await run_attack_module(module_name, har_data, config, attack.target_url, zap_client)
        return {
            "strategy": attack.strategy,
            "status": "completed",
            "routed_via_zap": zap_client is not None,
            "orchestrator": "legacy",
            "results": results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def run_attack_module(module_name: str, har_data: Dict, config: Dict, target_url: str = None, zap_client=None) -> Dict:
    """Execute attack module and return results

    Args:
        zap_client: ZAPHttpClient instance to route requests through ZAP
    """
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

    results = {"findings": [], "summary": {}, "routed_via_zap": zap_client is not None}

    if module_name == "redteam_attacks":
        from modules.redteam_attacks import RedTeamOrchestrator
        orchestrator = RedTeamOrchestrator(har_data, config, zap_client=zap_client)
        report = orchestrator.generate_report()
        results["findings"] = report.get("critical_findings", [])
        results["summary"] = report.get("summary", {})

    elif module_name == "jwt_attacks":
        from modules.jwt_attacks import JWTAttacker
        attacker = JWTAttacker(har_data, config, zap_client=zap_client)
        tokens = attacker.extract_jwts()
        results["findings"] = [{"type": "jwt_found", "data": t} for t in tokens[:10]]
        results["summary"] = {"tokens_found": len(tokens)}

    elif module_name == "cors_tester":
        from modules.cors_tester import CORSTester
        tester = CORSTester(har_data, config, zap_client=zap_client)
        cors_results = tester.test_all()
        results["findings"] = cors_results.get("vulnerabilities", [])
        results["summary"] = cors_results.get("summary", {})

    elif module_name == "cache_poisoning":
        from modules.cache_poisoning import CachePoisonTester
        tester = CachePoisonTester(har_data, config, zap_client=zap_client)
        poison_results = tester.test_all()
        results["findings"] = poison_results.get("vulnerabilities", [])
        results["summary"] = poison_results.get("summary", {})

    elif module_name == "http_smuggling":
        from modules.http_smuggling import HTTPSmugglingTester
        tester = HTTPSmugglingTester(har_data, config, zap_client=zap_client)
        smuggle_results = tester.test_all()
        results["findings"] = smuggle_results.get("vulnerabilities", [])
        results["summary"] = smuggle_results.get("summary", {})

    elif module_name == "timing_analysis":
        from modules.timing_analysis import TimingAnalyzer
        analyzer = TimingAnalyzer(har_data, config, zap_client=zap_client)
        timing_results = analyzer.analyze_all()
        results["findings"] = timing_results.get("anomalies", [])
        results["summary"] = timing_results.get("summary", {})

    elif module_name == "graphql_scanner":
        from modules.graphql_scanner import GraphQLScanner
        scanner = GraphQLScanner(har_data, config, zap_client=zap_client)
        gql_results = scanner.scan_all()
        results["findings"] = gql_results.get("vulnerabilities", [])
        results["summary"] = gql_results.get("summary", {})

    elif module_name == "websocket_scanner":
        from modules.websocket_scanner import WebSocketScanner
        scanner = WebSocketScanner(har_data, config, zap_client=zap_client)
        ws_results = scanner.scan_all_sync()
        results["findings"] = ws_results.get("vulnerabilities", [])
        results["summary"] = ws_results.get("summary", {})

    elif module_name == "passive_analysis":
        from modules.passive_analysis import PassiveAnalyzer
        analyzer = PassiveAnalyzer(har_data, zap_client=zap_client)
        analyzer.run_all_checks()
        passive_results = analyzer.generate_summary()
        results["findings"] = analyzer.get_critical_issues()
        results["summary"] = passive_results

    else:
        results["summary"] = {"error": f"Module {module_name} not implemented"}

    return results
