"""
WebSocket Handlers for Real-Time Monitoring

Provides live updates for scan progress and alerts.
"""
import asyncio
from typing import Dict, Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()

# Active WebSocket connections
active_connections: Dict[str, Set[WebSocket]] = {
    'scans': set(),
    'alerts': set()
}


class ConnectionManager:
    """Manage WebSocket connections"""

    def __init__(self):
        self.scan_connections: Dict[str, Set[WebSocket]] = {}
        self.alert_connections: Set[WebSocket] = set()

    async def connect_scan(self, websocket: WebSocket, scan_id: str):
        await websocket.accept()
        if scan_id not in self.scan_connections:
            self.scan_connections[scan_id] = set()
        self.scan_connections[scan_id].add(websocket)

    async def connect_alerts(self, websocket: WebSocket):
        await websocket.accept()
        self.alert_connections.add(websocket)

    def disconnect_scan(self, websocket: WebSocket, scan_id: str):
        if scan_id in self.scan_connections:
            self.scan_connections[scan_id].discard(websocket)

    def disconnect_alerts(self, websocket: WebSocket):
        self.alert_connections.discard(websocket)

    async def broadcast_scan_progress(self, scan_id: str, data: dict):
        if scan_id in self.scan_connections:
            dead = set()
            for connection in self.scan_connections[scan_id]:
                try:
                    await connection.send_json(data)
                except Exception:
                    dead.add(connection)
            self.scan_connections[scan_id] -= dead

    async def broadcast_alert(self, data: dict):
        dead = set()
        for connection in self.alert_connections:
            try:
                await connection.send_json(data)
            except Exception:
                dead.add(connection)
        self.alert_connections -= dead


manager = ConnectionManager()


@router.websocket("/scans/{scan_id}")
async def scan_progress_websocket(websocket: WebSocket, scan_id: str):
    """
    WebSocket endpoint for real-time scan progress.

    Sends updates every 2 seconds with:
    - progress: int (0-100)
    - state: str (running, completed, error)
    - alerts: dict (high, medium, low, info counts)
    """
    await manager.connect_scan(websocket, scan_id)

    try:
        zap_service = websocket.app.state.shared['zap_service']

        while True:
            if not zap_service.is_running:
                await websocket.send_json({
                    "error": "ZAP not running",
                    "state": "stopped"
                })
                break

            progress_data = zap_service.get_scan_progress(scan_id)
            await websocket.send_json({
                "scan_id": scan_id,
                **progress_data
            })

            # Stop if scan completed
            if progress_data.get('progress', 0) >= 100:
                await websocket.send_json({
                    "scan_id": scan_id,
                    "state": "completed",
                    "progress": 100
                })
                break

            await asyncio.sleep(2)

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"error": str(e)})
        except Exception:
            pass
    finally:
        manager.disconnect_scan(websocket, scan_id)


@router.websocket("/alerts")
async def alerts_websocket(websocket: WebSocket):
    """
    WebSocket endpoint for live alert stream.

    Sends new alerts as they are detected.
    """
    await manager.connect_alerts(websocket)

    try:
        zap_service = websocket.app.state.shared['zap_service']
        seen_alerts = set()

        while True:
            if not zap_service.is_running:
                await websocket.send_json({
                    "type": "status",
                    "message": "ZAP not running"
                })
                await asyncio.sleep(5)
                continue

            alerts = zap_service.get_alerts()

            # Send only new alerts
            for alert in alerts:
                alert_id = f"{alert.get('url')}:{alert.get('alert')}:{alert.get('param')}"
                if alert_id not in seen_alerts:
                    seen_alerts.add(alert_id)
                    await websocket.send_json({
                        "type": "new_alert",
                        "alert": alert
                    })

            # Send periodic summary
            await websocket.send_json({
                "type": "summary",
                "total": len(alerts),
                "high": len([a for a in alerts if a.get('risk') == 'High']),
                "medium": len([a for a in alerts if a.get('risk') == 'Medium']),
                "low": len([a for a in alerts if a.get('risk') == 'Low']),
                "info": len([a for a in alerts if a.get('risk') == 'Informational'])
            })

            await asyncio.sleep(3)

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"error": str(e)})
        except Exception:
            pass
    finally:
        manager.disconnect_alerts(websocket)


@router.websocket("/status")
async def status_websocket(websocket: WebSocket):
    """
    WebSocket endpoint for overall system status.

    Sends periodic status updates for ZAP and TOR.
    """
    await websocket.accept()

    try:
        while True:
            zap_service = websocket.app.state.shared['zap_service']
            tor_service = websocket.app.state.shared['tor_service']

            status = {
                "type": "status",
                "zap": zap_service.get_status() if zap_service else {"running": False},
                "tor": tor_service.get_status() if tor_service else {"connected": False}
            }

            await websocket.send_json(status)
            await asyncio.sleep(5)

    except WebSocketDisconnect:
        pass
    except Exception:
        pass
