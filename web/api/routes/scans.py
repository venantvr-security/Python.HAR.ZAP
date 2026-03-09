"""
Scan Management API Routes

Endpoints for scan lifecycle and results.
"""
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional, List

router = APIRouter()


class ScanRequest(BaseModel):
    url: str
    scan_type: Optional[str] = "active"  # spider, active, full
    policy: Optional[str] = None
    max_duration: Optional[int] = 300


@router.post("")
async def start_scan(request: Request, scan_request: ScanRequest):
    """Start a new scan"""
    zap_service = request.app.state.shared['zap_service']

    if not zap_service.is_running:
        raise HTTPException(status_code=400, detail="ZAP not running")

    result = zap_service.start_scan(
        url=scan_request.url,
        scan_type=scan_request.scan_type,
        policy=scan_request.policy
    )

    if not result:
        raise HTTPException(status_code=500, detail="Failed to start scan")

    return {
        "scan_id": result.get('scan_id'),
        "spider_id": result.get('spider_id'),
        "url": scan_request.url,
        "scan_type": scan_request.scan_type,
        "status": "started"
    }


@router.get("")
async def list_scans(request: Request):
    """List all active scans"""
    zap_service = request.app.state.shared['zap_service']

    if not zap_service.is_running:
        return {"scans": []}

    return {"scans": zap_service.get_active_scans()}


@router.get("/{scan_id}")
async def get_scan(request: Request, scan_id: str):
    """Get scan status and progress"""
    zap_service = request.app.state.shared['zap_service']

    if not zap_service.is_running:
        raise HTTPException(status_code=400, detail="ZAP not running")

    return {
        "scan_id": scan_id,
        **zap_service.get_scan_progress(scan_id)
    }


@router.get("/{scan_id}/results")
async def get_scan_results(request: Request, scan_id: str, risk: Optional[str] = None):
    """Get scan results/alerts"""
    zap_service = request.app.state.shared['zap_service']

    if not zap_service.is_running:
        raise HTTPException(status_code=400, detail="ZAP not running")

    progress = zap_service.get_scan_progress(scan_id)
    alerts = zap_service.get_alerts(risk)

    return {
        "scan_id": scan_id,
        "progress": progress['progress'],
        "state": progress['state'],
        "alerts": alerts
    }


@router.delete("/{scan_id}")
@router.post("/{scan_id}/stop")
async def stop_scan(request: Request, scan_id: str):
    """Stop an active scan"""
    zap_service = request.app.state.shared['zap_service']

    if not zap_service.is_running:
        raise HTTPException(status_code=400, detail="ZAP not running")

    success = zap_service.stop_scan(scan_id)

    if not success:
        raise HTTPException(status_code=500, detail="Failed to stop scan")

    return {"scan_id": scan_id, "status": "stopped"}


@router.post("/clear")
async def clear_session(request: Request):
    """Clear ZAP session (alerts, history)"""
    zap_service = request.app.state.shared['zap_service']

    if not zap_service.is_running:
        raise HTTPException(status_code=400, detail="ZAP not running")

    success = zap_service.clear_session()

    if not success:
        raise HTTPException(status_code=500, detail="Failed to clear session")

    return {"status": "cleared"}
