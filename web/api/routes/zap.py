"""
ZAP Control API Routes

Endpoints for ZAP container lifecycle management.
"""
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional

router = APIRouter()


class ZAPStartRequest(BaseModel):
    port: Optional[int] = 8080
    image: Optional[str] = "ghcr.io/zaproxy/zaproxy:stable"


@router.get("/status")
async def get_zap_status(request: Request):
    """Get ZAP container status"""
    zap_service = request.app.state.shared['zap_service']
    return zap_service.get_status()


@router.post("/start")
async def start_zap(request: Request, config: ZAPStartRequest = None):
    """Start ZAP Docker container"""
    zap_service = request.app.state.shared['zap_service']
    app_config = request.app.state.shared['config']

    if zap_service.is_running:
        return {"status": "already_running", **zap_service.get_status()}

    start_config = app_config.copy()
    if config:
        if config.port:
            start_config['zap_port'] = config.port
        if config.image:
            start_config['zap_image'] = config.image

    try:
        result = zap_service.start(start_config)
        return {"status": "started", **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stop")
async def stop_zap(request: Request):
    """Stop ZAP Docker container"""
    zap_service = request.app.state.shared['zap_service']

    if not zap_service.is_running:
        return {"status": "not_running"}

    try:
        zap_service.stop()
        return {"status": "stopped"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/logs")
async def get_zap_logs(request: Request, lines: int = 50):
    """Get ZAP container logs"""
    zap_service = request.app.state.shared['zap_service']

    if not zap_service.is_running:
        raise HTTPException(status_code=400, detail="ZAP not running")

    return {"logs": zap_service.get_logs(lines)}


@router.get("/alerts")
async def get_zap_alerts(request: Request, risk: Optional[str] = None):
    """Get ZAP alerts, optionally filtered by risk"""
    zap_service = request.app.state.shared['zap_service']

    if not zap_service.is_running:
        raise HTTPException(status_code=400, detail="ZAP not running")

    alerts = zap_service.get_alerts(risk)
    return {
        "total": len(alerts),
        "alerts": alerts
    }
