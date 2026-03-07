"""
TOR/Proxy API Routes

Endpoints for TOR proxy configuration and control.
"""
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional

router = APIRouter()


class TORConfig(BaseModel):
    host: Optional[str] = "127.0.0.1"
    port: Optional[int] = 9050
    control_port: Optional[int] = 9051
    control_password: Optional[str] = ""


@router.get("/tor/status")
async def get_tor_status(request: Request):
    """Get TOR connection status"""
    tor_service = request.app.state.shared['tor_service']
    return tor_service.get_status()


@router.post("/tor/enable")
async def enable_tor(request: Request, config: TORConfig = None):
    """Enable TOR proxy routing"""
    tor_service = request.app.state.shared['tor_service']
    zap_service = request.app.state.shared['zap_service']

    # Update TOR service config if provided
    if config:
        tor_service.host = config.host
        tor_service.port = config.port
        tor_service.control_port = config.control_port
        tor_service.control_password = config.control_password

    # Check TOR connection
    if not tor_service.check_connection():
        raise HTTPException(
            status_code=503,
            detail=f"Cannot connect to TOR at {tor_service.host}:{tor_service.port}"
        )

    # Configure ZAP proxy if running
    if zap_service.is_running:
        # Get ZAP's advanced config
        try:
            import sys
            from pathlib import Path
            sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

            from modules.advanced_zap_config import AdvancedZAPConfig
            from zapv2 import ZAPv2

            zap_config_data = zap_service._zap_config
            zap = ZAPv2(
                apikey=zap_config_data['api_key'],
                proxies={'http': zap_config_data['zap_url'],
                         'https': zap_config_data['zap_url']}
            )

            advanced_config = AdvancedZAPConfig(zap)
            tor_service.configure_zap_proxy(advanced_config)

        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to configure ZAP: {e}")

    return {
        "status": "enabled",
        "host": tor_service.host,
        "port": tor_service.port,
        "exit_ip": tor_service.get_exit_ip()
    }


@router.post("/tor/disable")
async def disable_tor(request: Request):
    """Disable TOR proxy routing"""
    tor_service = request.app.state.shared['tor_service']
    zap_service = request.app.state.shared['zap_service']

    if zap_service.is_running:
        try:
            import sys
            from pathlib import Path
            sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

            from modules.advanced_zap_config import AdvancedZAPConfig
            from zapv2 import ZAPv2

            zap_config_data = zap_service._zap_config
            zap = ZAPv2(
                apikey=zap_config_data['api_key'],
                proxies={'http': zap_config_data['zap_url'],
                         'https': zap_config_data['zap_url']}
            )

            advanced_config = AdvancedZAPConfig(zap)
            tor_service.disable_zap_proxy(advanced_config)

        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to disable proxy: {e}")

    return {"status": "disabled"}


@router.post("/tor/new-circuit")
async def request_new_circuit(request: Request):
    """Request a new TOR circuit"""
    tor_service = request.app.state.shared['tor_service']

    if not tor_service.check_connection():
        raise HTTPException(status_code=503, detail="TOR not connected")

    success = tor_service.new_circuit()

    if not success:
        raise HTTPException(
            status_code=500,
            detail="Failed to request new circuit. Check control port and password."
        )

    return {
        "status": "new_circuit_requested",
        "exit_ip": tor_service.get_exit_ip()
    }


@router.get("/tor/ip")
async def get_exit_ip(request: Request):
    """Get current TOR exit IP"""
    tor_service = request.app.state.shared['tor_service']

    if not tor_service.check_connection():
        raise HTTPException(status_code=503, detail="TOR not connected")

    exit_ip = tor_service.get_exit_ip()

    if not exit_ip:
        raise HTTPException(status_code=500, detail="Failed to get exit IP")

    return {"exit_ip": exit_ip}
