"""
LLM Analysis Routes

API endpoints for LLM-powered security analysis.
Single-call analysis with caching.
"""
import os
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional, List, Dict

router = APIRouter()


class AnalysisRequest(BaseModel):
    force_refresh: Optional[bool] = False
    strategies: Optional[List[str]] = None


class SpecificAnalysisRequest(BaseModel):
    prompt_name: str
    force_refresh: Optional[bool] = False


@router.get("/status")
async def llm_status(request: Request):
    """Check LLM service status and configuration."""
    config = request.app.state.shared.get('config', {})
    llm_config = config.get('llm', {})

    return {
        "enabled": llm_config.get('enabled', False),
        "provider": llm_config.get('provider', 'anthropic'),
        "model": llm_config.get('model', 'unknown'),
        "cache_enabled": llm_config.get('cache', {}).get('enabled', True),
        "api_key_configured": bool(os.environ.get('HARZAP_LLM_API_KEY'))
    }


@router.get("/prompts")
async def list_prompts():
    """List available prompt templates."""
    from modules.llm.prompts import list_prompts
    return {"prompts": list_prompts()}


@router.post("/analyze")
async def analyze_har(request: Request, analysis: AnalysisRequest):
    """
    Analyze loaded HAR with LLM.
    Returns comprehensive security plan.
    Single LLM call, results cached by HAR hash.
    """
    har_service = request.app.state.shared.get('har_service')
    config = request.app.state.shared.get('config', {})

    if not har_service or not har_service.current_har:
        raise HTTPException(status_code=400, detail="No HAR loaded. Upload HAR first.")

    if not config.get('llm', {}).get('enabled', False):
        raise HTTPException(status_code=400, detail="LLM integration not enabled in config.")

    if not os.environ.get('HARZAP_LLM_API_KEY'):
        raise HTTPException(
            status_code=400,
            detail="HARZAP_LLM_API_KEY environment variable not set."
        )

    try:
        from modules.llm import LLMSecurityAnalyzer

        analyzer = LLMSecurityAnalyzer.from_config(config)
        plan = analyzer.analyze(
            har_service.current_har,
            force_refresh=analysis.force_refresh
        )

        response = plan.to_dict()

        # Filter strategies if requested
        if analysis.strategies:
            response['strategies'] = [
                s for s in response['strategies']
                if s['attack_type'] in analysis.strategies
            ]

        return {
            "status": "success",
            "plan": response,
            "cached": plan.metadata.get('cached', False)
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/plan/{har_hash}")
async def get_cached_plan(request: Request, har_hash: str):
    """Get cached analysis plan by HAR hash."""
    config = request.app.state.shared.get('config', {})

    try:
        from modules.llm import LLMCache

        cache_config = config.get('llm', {}).get('cache', {})
        cache = LLMCache(
            cache_dir=cache_config.get('directory', './.llm_cache'),
            ttl_hours=cache_config.get('ttl_hours', 24)
        )

        plan = cache.get(har_hash)
        if not plan:
            raise HTTPException(status_code=404, detail="Plan not found or expired")

        return {"status": "success", "plan": plan.to_dict()}

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/cache")
async def clear_cache(request: Request):
    """Clear LLM response cache."""
    config = request.app.state.shared.get('config', {})

    try:
        from modules.llm import LLMCache

        cache_config = config.get('llm', {}).get('cache', {})
        cache = LLMCache(cache_dir=cache_config.get('directory', './.llm_cache'))
        cache.clear()

        return {"status": "success", "message": "Cache cleared"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/enrich-attacks")
async def enrich_attacks(request: Request, analysis: AnalysisRequest):
    """
    Analyze HAR and return enriched attack configurations.
    Shows which strategies are applicable and their payloads.
    """
    har_service = request.app.state.shared.get('har_service')
    config = request.app.state.shared.get('config', {})

    if not har_service or not har_service.current_har:
        raise HTTPException(status_code=400, detail="No HAR loaded")

    if not config.get('llm', {}).get('enabled', False):
        raise HTTPException(status_code=400, detail="LLM integration not enabled")

    try:
        from modules.llm import LLMSecurityAnalyzer
        from modules.llm.strategies import (
            MassAssignmentStrategy,
            IDORStrategy,
            FuzzerVocabularyStrategy,
            RaceConditionStrategy,
            PassiveRegexStrategy,
            BusinessLogicStrategy
        )

        analyzer = LLMSecurityAnalyzer.from_config(config)
        plan = analyzer.analyze(
            har_service.current_har,
            force_refresh=analysis.force_refresh
        )

        enriched = {
            'har_hash': plan.har_hash,
            'domain': plan.domain_analysis,
            'strategies': {}
        }

        strategy_classes = {
            'mass_assignment': MassAssignmentStrategy,
            'idor': IDORStrategy,
            'fuzzer': FuzzerVocabularyStrategy,
            'race_condition': RaceConditionStrategy,
            'passive_analysis': PassiveRegexStrategy,
            'business_logic': BusinessLogicStrategy
        }

        for name, cls in strategy_classes.items():
            strategy = cls(plan, config)
            if strategy.is_applicable():
                enriched['strategies'][name] = {
                    'applicable': True,
                    'priority': strategy.get_priority(),
                    'targets_count': len(strategy.get_targets()),
                    'payloads_count': len(strategy.get_enriched_payloads()),
                    'payloads_preview': strategy.get_enriched_payloads()[:5],
                    'rationale': strategy.get_rationale()
                }
            else:
                enriched['strategies'][name] = {'applicable': False}

        return {"status": "success", "enriched": enriched}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/context")
async def get_har_context(request: Request):
    """Get extracted HAR context (privacy-safe, for debugging)."""
    har_service = request.app.state.shared.get('har_service')

    if not har_service or not har_service.current_har:
        raise HTTPException(status_code=400, detail="No HAR loaded")

    try:
        from modules.llm import HARContextExtractor

        extractor = HARContextExtractor(har_service.current_har)
        context = extractor.extract()

        return {
            "status": "success",
            "context": {
                "har_hash": context.har_hash,
                "endpoints": context.endpoints,
                "param_names": context.param_names,
                "json_keys": context.json_keys[:100],
                "domains": context.domains,
                "methods": context.methods_used,
                "auth_types": context.auth_types,
                "id_patterns": context.id_patterns[:20],
                "request_flows": context.request_flows
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class ZAPEnrichRequest(BaseModel):
    export_wordlists: Optional[bool] = True
    wordlist_dir: Optional[str] = "./wordlists/llm"
    force_refresh: Optional[bool] = False


class AddPatternsRequest(BaseModel):
    pattern_type: str
    patterns: List[Dict]
    merge: Optional[bool] = True


@router.post("/enrich-zap")
async def enrich_zap(request: Request, enrich_req: ZAPEnrichRequest):
    """
    Full pipeline: HAR → LLM → ZAP enrichment.
    Enriches dictionaries and optionally exports wordlists.
    """
    har_service = request.app.state.shared.get('har_service')
    config = request.app.state.shared.get('config', {})

    if not har_service or not har_service.current_har:
        raise HTTPException(status_code=400, detail="No HAR loaded")

    if not config.get('llm', {}).get('enabled', False):
        raise HTTPException(status_code=400, detail="LLM integration not enabled")

    if not os.environ.get('HARZAP_LLM_API_KEY'):
        raise HTTPException(status_code=400, detail="HARZAP_LLM_API_KEY not set")

    try:
        from modules.llm import LLMSecurityAnalyzer, LLMZAPEnricher
        from modules.dictionary_manager import DictionaryManager

        # Analyze HAR
        analyzer = LLMSecurityAnalyzer.from_config(config)
        plan = analyzer.analyze(
            har_service.current_har,
            force_refresh=enrich_req.force_refresh
        )

        # Create enricher
        enricher = LLMZAPEnricher(plan, config)

        result = {
            "status": "success",
            "domain": enricher.domain,
            "confidence": enricher.confidence,
            "har_hash": plan.har_hash,
            "enrichments": {}
        }

        # Enrich dictionaries
        dict_manager = DictionaryManager()
        counts = enricher.enrich_dictionary_manager(dict_manager)
        result["enrichments"]["dictionaries"] = counts

        # Export wordlists
        if enrich_req.export_wordlists:
            exported = enricher.export_wordlists(enrich_req.wordlist_dir)
            result["enrichments"]["wordlists"] = exported

        # Include other enrichments
        result["custom_regex_count"] = len(enricher.get_passive_scanner_patterns())
        result["race_targets_count"] = len(enricher.get_race_condition_targets())
        result["business_logic_count"] = len(enricher.get_business_logic_tests())

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# PATTERN STORE ENDPOINTS
# =============================================================================

@router.get("/patterns/sessions")
async def list_pattern_sessions():
    """List all pattern sessions."""
    from modules.llm import PatternStore
    store = PatternStore()
    return {"sessions": store.list_sessions()}


@router.get("/patterns/sessions/{session_id}")
async def get_pattern_session(session_id: str):
    """Get a specific session."""
    from modules.llm import PatternStore
    store = PatternStore()
    session = store.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"session": session.to_dict()}


@router.get("/patterns/current")
async def get_current_session():
    """Get the current (latest) session."""
    from modules.llm import PatternStore
    store = PatternStore()
    session = store.get_current_session()
    if not session:
        raise HTTPException(status_code=404, detail="No current session")
    return {"session": session.to_dict()}


@router.get("/patterns/sessions/{session_id}/{pattern_type}")
async def get_patterns(session_id: str, pattern_type: str):
    """GET patterns from a session."""
    from modules.llm import PatternStore
    store = PatternStore()
    patterns = store.get_patterns(session_id, pattern_type)
    return {"pattern_type": pattern_type, "patterns": patterns, "count": len(patterns)}


@router.post("/patterns/sessions/{session_id}/{pattern_type}")
async def add_patterns(session_id: str, pattern_type: str, req: AddPatternsRequest):
    """ADD patterns to a session."""
    from modules.llm import PatternStore
    store = PatternStore()
    try:
        added = store.add_patterns(session_id, pattern_type, req.patterns, req.merge)
        return {"status": "success", "added": added}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/patterns/sessions/{session_id}/persist")
async def persist_session(session_id: str):
    """PERSIST - Ensure all patterns are saved and return file paths."""
    from modules.llm import PatternStore
    store = PatternStore()
    try:
        files = store.persist_session(session_id)
        return {"status": "success", "files": files}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/patterns/sessions/{session_id}/push")
async def push_to_zap(session_id: str):
    """PUSH patterns to ZAP export directory for Docker mounting."""
    from modules.llm import PatternStore
    store = PatternStore()
    try:
        exported = store.push_to_zap_export(session_id)
        mount_paths = store.get_zap_mount_paths()
        return {"status": "success", "exported": exported, "mount_paths": mount_paths}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/patterns/zap-mount")
async def get_zap_mount_paths():
    """Get Docker mount paths for ZAP container."""
    from modules.llm import PatternStore
    store = PatternStore()
    return store.get_zap_mount_paths()


@router.post("/patterns/merge")
async def merge_all_sessions():
    """Merge patterns from all sessions."""
    from modules.llm import PatternStore
    store = PatternStore()
    counts = store.merge_all_sessions()
    return {"status": "success", "merged_counts": counts}


@router.post("/enrich-and-store")
async def enrich_and_store(request: Request, enrich_req: ZAPEnrichRequest):
    """
    Full pipeline: HAR → LLM → PatternStore → ZAP export.
    Creates a persistent session with all enriched patterns.
    """
    har_service = request.app.state.shared.get('har_service')
    config = request.app.state.shared.get('config', {})

    if not har_service or not har_service.current_har:
        raise HTTPException(status_code=400, detail="No HAR loaded")

    if not config.get('llm', {}).get('enabled', False):
        raise HTTPException(status_code=400, detail="LLM integration not enabled")

    if not os.environ.get('HARZAP_LLM_API_KEY'):
        raise HTTPException(status_code=400, detail="HARZAP_LLM_API_KEY not set")

    try:
        from modules.llm import LLMSecurityAnalyzer, LLMZAPEnricher, PatternStore

        # Analyze HAR
        analyzer = LLMSecurityAnalyzer.from_config(config)
        plan = analyzer.analyze(
            har_service.current_har,
            force_refresh=enrich_req.force_refresh
        )

        # Create enricher and get domain enrichment
        enricher = LLMZAPEnricher(plan, config)
        domain_enrichment = enricher.get_domain_enrichment()

        # Store to pattern store
        store = PatternStore()
        session_id = store.store_from_enrichment(domain_enrichment, plan.har_hash)

        # Get session info
        session = store.get_session(session_id)
        files = store.persist_session(session_id)
        mount_paths = store.get_zap_mount_paths()

        return {
            "status": "success",
            "session_id": session_id,
            "domain": enricher.domain,
            "confidence": enricher.confidence,
            "har_hash": plan.har_hash,
            "patterns_stored": {
                pt: len(store.get_patterns(session_id, pt))
                for pt in store.PATTERN_TYPES
            },
            "files": files,
            "zap_mount": mount_paths
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
