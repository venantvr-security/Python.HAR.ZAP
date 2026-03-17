"""
Payload Enrichment Routes

Extract patterns from HAR and enrich with ZAP fuzzer payloads.
"""
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional, List

router = APIRouter()


class ExtractRequest(BaseModel):
    pattern_types: Optional[List[str]] = None  # None = all patterns


class PreviewRequest(BaseModel):
    pattern_type: str
    include_zap: Optional[bool] = True
    include_custom: Optional[bool] = True
    limit: Optional[int] = 100


class FuzzRequest(BaseModel):
    url: str
    param: str
    pattern_type: str
    payloads: Optional[List[str]] = None  # Override auto payloads


@router.get("/patterns")
async def list_patterns(request: Request):
    """List available extraction patterns from config."""
    config = request.app.state.shared['config'] or {}
    patterns = config.get('extraction_patterns', {})
    mapping = config.get('payload_mapping', {})

    return {
        "patterns": [
            {
                "id": name,
                "regex": regex,
                "zap_categories": mapping.get(name, {}).get('zap_categories', []),
                "custom_count": len(mapping.get(name, {}).get('custom', []))
            }
            for name, regex in patterns.items()
        ]
    }


@router.post("/extract")
async def extract_patterns(request: Request, req: ExtractRequest = None):
    """Extract patterns from loaded HAR."""
    har_service = request.app.state.shared['har_service']
    config = request.app.state.shared['config'] or {}

    if not har_service or not har_service.current_har:
        raise HTTPException(status_code=400, detail="No HAR loaded. Upload HAR first.")

    try:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

        from modules.pattern_extractor import PatternExtractor

        extractor = PatternExtractor(har_service.current_har, config)
        extractor.extract_from_har()
        summary = extractor.get_summary()

        # Filter by requested patterns if specified
        if req and req.pattern_types:
            summary['patterns'] = {
                k: v for k, v in summary['patterns'].items()
                if k in req.pattern_types
            }

        return {
            "status": "completed",
            "extraction": summary
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/zap-lists")
async def list_zap_payloads(request: Request):
    """List available ZAP payload categories."""
    zap_service = request.app.state.shared['zap_service']
    config = request.app.state.shared['config'] or {}

    try:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

        from modules.zap_enricher import ZAPPayloadEnricher

        zap = zap_service.zap if zap_service and zap_service.is_running else None
        enricher = ZAPPayloadEnricher(zap=zap, config=config)
        lists = enricher.get_available_lists()

        return {
            "zap_connected": zap is not None,
            "categories": lists
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/preview")
async def preview_payloads(request: Request, req: PreviewRequest):
    """Preview enriched payloads without fuzzing."""
    config = request.app.state.shared['config'] or {}
    zap_service = request.app.state.shared['zap_service']

    try:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

        from modules.zap_enricher import ZAPPayloadEnricher

        zap = zap_service.zap if zap_service and zap_service.is_running else None
        enricher = ZAPPayloadEnricher(zap=zap, config=config)

        preview = enricher.preview_payloads(
            pattern_type=req.pattern_type,
            limit=req.limit or 100,
            include_zap=req.include_zap,
            include_custom=req.include_custom
        )

        return {
            "status": "completed",
            "preview": preview
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/fuzz")
async def fuzz_with_enriched(request: Request, req: FuzzRequest):
    """Execute fuzzing with enriched payloads via ZAP."""
    har_service = request.app.state.shared['har_service']
    zap_service = request.app.state.shared['zap_service']
    config = request.app.state.shared['config'] or {}

    if not har_service or not har_service.current_har:
        raise HTTPException(status_code=400, detail="No HAR loaded. Upload HAR first.")

    if not zap_service or not zap_service.is_running:
        raise HTTPException(status_code=400, detail="ZAP not running. Start ZAP first.")

    try:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

        from modules.zap_enricher import ZAPPayloadEnricher
        from modules.zap_fuzzer import ZAPFuzzer

        # Get payloads
        if req.payloads:
            payloads = req.payloads
        else:
            enricher = ZAPPayloadEnricher(zap=zap_service.zap, config=config)
            payload_set = enricher.load_payloads_for_pattern(req.pattern_type)
            payloads = payload_set.combined

        if not payloads:
            raise HTTPException(status_code=400, detail=f"No payloads for pattern: {req.pattern_type}")

        # Run fuzzing
        fuzzer = ZAPFuzzer(
            zap=zap_service.zap,
            wordlists={'enriched': payloads},
            config=config
        )

        result = fuzzer.fuzz_with_payloads(
            url=req.url,
            param=req.param,
            payloads=payloads,
            payload_type=req.pattern_type
        )

        return {
            "status": "completed",
            "fuzz_result": result
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/injection-points")
async def get_injection_points(request: Request, pattern_type: Optional[str] = None):
    """Get identified injection points from HAR."""
    har_service = request.app.state.shared['har_service']
    config = request.app.state.shared['config'] or {}

    if not har_service or not har_service.current_har:
        raise HTTPException(status_code=400, detail="No HAR loaded. Upload HAR first.")

    try:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

        from modules.pattern_extractor import PatternExtractor

        extractor = PatternExtractor(har_service.current_har, config)
        extractor.extract_from_har()

        if pattern_type:
            points = extractor.get_injection_points_by_pattern(pattern_type)
        else:
            points = extractor.identify_injection_points()

        return {
            "status": "completed",
            "count": len(points),
            "injection_points": [
                {
                    "url": p.url[:100],
                    "method": p.method,
                    "location": p.location,
                    "param": p.param_name,
                    "value": p.original_value,
                    "pattern_type": p.pattern_type.value
                }
                for p in points[:50]
            ]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
