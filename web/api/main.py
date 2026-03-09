"""
FastAPI Backend for HAR-ZAP

Provides REST API, WebSocket endpoints, and web interface for ZAP control.
"""
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict

from fastapi import FastAPI, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse
import markdown

from .routes import zap, scans, config, docs, tor
from .websockets import scan_monitor

# Paths
BASE_DIR = Path(__file__).parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

# Templates
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Shared state
state: Dict = {
    'zap_service': None,
    'tor_service': None,
    'doc_service': None,
    'config': None
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan - initialize services"""
    import sys
    sys.path.insert(0, str(BASE_DIR.parent))

    from modules.config_loader import load_config
    from web.services import ZAPService, TORService, DocService

    state['config'] = load_config()
    state['zap_service'] = ZAPService(state['config'])
    state['tor_service'] = TORService.from_config(state['config'])
    state['doc_service'] = DocService()

    yield

    if state['zap_service'] and state['zap_service'].is_running:
        state['zap_service'].stop()


app = FastAPI(
    title="HAR-ZAP",
    description="DAST Security Platform",
    version="2.0.0",
    lifespan=lifespan
)

# Static files
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routers
app.include_router(zap.router, prefix="/api/v1/zap", tags=["ZAP"])
app.include_router(scans.router, prefix="/api/v1/scans", tags=["Scans"])
app.include_router(config.router, prefix="/api/v1/config", tags=["Config"])
app.include_router(docs.router, prefix="/api/v1/docs", tags=["Docs"])
app.include_router(tor.router, prefix="/api/v1/proxy", tags=["TOR"])
app.include_router(scan_monitor.router, prefix="/api/v1/ws", tags=["WebSocket"])

app.state.shared = state


# Page routes

@app.get("/")
async def dashboard(request: Request):
    """Dashboard page"""
    zap_svc = state['zap_service']
    tor_svc = state['tor_service']

    zap_status = zap_svc.get_status() if zap_svc else {'running': False}
    tor_status = tor_svc.get_status() if tor_svc else {'connected': False}
    active_scans = zap_svc.get_active_scans() if zap_svc and zap_status.get('running') else []
    alerts = zap_svc.get_alerts()[:10] if zap_svc and zap_status.get('running') else []
    high_alerts = len([a for a in alerts if a.get('risk') == 'High'])

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "active": "dashboard",
        "zap_status": zap_status,
        "tor_status": tor_status,
        "tor_host": tor_svc.host if tor_svc else "127.0.0.1",
        "tor_port": tor_svc.port if tor_svc else 9050,
        "active_scans": active_scans,
        "alerts": alerts,
        "high_alerts": high_alerts
    })


@app.get("/wizard")
async def wizard(request: Request, step: int = 0):
    """Onboarding wizard page"""
    doc_svc = state['doc_service']
    zap_svc = state['zap_service']
    tor_svc = state['tor_service']

    steps = doc_svc.get_wizard_steps() if doc_svc else []
    current_step = max(0, min(step, len(steps) - 1)) if steps else 0
    step_data = steps[current_step].copy() if steps else {'title': 'No steps', 'content': ''}

    # Convert markdown to HTML
    if step_data.get('content'):
        step_data['content'] = markdown.markdown(
            step_data['content'],
            extensions=['fenced_code', 'tables']
        )

    zap_status = zap_svc.get_status() if zap_svc else {'running': False}
    tor_status = tor_svc.get_status() if tor_svc else {'connected': False}

    return templates.TemplateResponse("wizard.html", {
        "request": request,
        "active": "wizard",
        "steps": steps,
        "current_step": current_step,
        "step": step_data,
        "zap_status": zap_status,
        "tor_status": tor_status
    })


@app.get("/tor")
async def tor_config(request: Request):
    """TOR configuration page"""
    zap_svc = state['zap_service']
    tor_svc = state['tor_service']

    zap_status = zap_svc.get_status() if zap_svc else {'running': False}
    tor_status = tor_svc.get_status() if tor_svc else {'connected': False}

    return templates.TemplateResponse("tor.html", {
        "request": request,
        "active": "tor",
        "zap_status": zap_status,
        "tor_status": tor_status,
        "tor_host": tor_svc.host if tor_svc else "127.0.0.1",
        "tor_port": tor_svc.port if tor_svc else 9050,
        "control_port": tor_svc.control_port if tor_svc else 9051
    })


@app.post("/tor/configure")
async def tor_configure(
    host: str = Form(...),
    port: int = Form(...),
    control_port: int = Form(...),
    control_password: str = Form("")
):
    """Update TOR configuration"""
    tor_svc = state['tor_service']

    if tor_svc:
        tor_svc.host = host
        tor_svc.port = port
        tor_svc.control_port = control_port
        if control_password:
            tor_svc.control_password = control_password

    return RedirectResponse(url="/tor", status_code=303)


@app.get("/scans")
async def scans_page(request: Request):
    """Scans page"""
    zap_svc = state['zap_service']

    zap_status = zap_svc.get_status() if zap_svc else {'running': False}
    active_scans = zap_svc.get_active_scans() if zap_svc and zap_status.get('running') else []
    all_alerts = zap_svc.get_alerts() if zap_svc and zap_status.get('running') else []

    alerts_summary = {
        'high': len([a for a in all_alerts if a.get('risk') == 'High']),
        'medium': len([a for a in all_alerts if a.get('risk') == 'Medium']),
        'low': len([a for a in all_alerts if a.get('risk') == 'Low']),
        'info': len([a for a in all_alerts if a.get('risk') == 'Informational'])
    }

    return templates.TemplateResponse("scans.html", {
        "request": request,
        "active": "scans",
        "zap_status": zap_status,
        "active_scans": active_scans,
        "alerts": alerts_summary,
        "recent_alerts": all_alerts[:20]
    })


@app.get("/documentation")
@app.get("/documentation/{doc_id:path}")
async def docs_page(request: Request, doc_id: str = None):
    """Documentation page"""
    doc_svc = state['doc_service']

    docs_list = doc_svc.list_docs() if doc_svc else []
    current_doc = None

    if doc_id and doc_svc:
        content = doc_svc.get_doc(doc_id)
        if content:
            current_doc = {
                'id': doc_id,
                'title': doc_id.replace('_', ' ').title(),
                'content': markdown.markdown(content, extensions=['fenced_code', 'tables'])
            }

    return templates.TemplateResponse("docs.html", {
        "request": request,
        "active": "docs",
        "docs": docs_list,
        "current_doc": current_doc
    })


@app.get("/health")
async def health():
    """Health check"""
    return {
        "status": "healthy",
        "zap_running": state['zap_service'].is_running if state['zap_service'] else False,
        "tor_connected": state['tor_service'].check_connection() if state['tor_service'] else False
    }
