"""
Documentation API Routes

Endpoints for documentation and onboarding wizard.
"""
from fastapi import APIRouter, HTTPException, Request
from typing import Optional

router = APIRouter()


@router.get("")
async def list_docs(request: Request):
    """List all available documentation files"""
    doc_service = request.app.state.shared['doc_service']
    return {"docs": doc_service.list_docs()}


@router.get("/wizard/steps")
async def get_wizard_steps(request: Request):
    """Get onboarding wizard steps with content"""
    doc_service = request.app.state.shared['doc_service']
    steps = doc_service.get_wizard_steps()

    return {
        "total": len(steps),
        "steps": steps
    }


@router.get("/wizard/steps/{step_id}")
async def get_wizard_step(request: Request, step_id: str):
    """Get a specific wizard step"""
    doc_service = request.app.state.shared['doc_service']
    step = doc_service.get_wizard_step(step_id)

    if not step:
        raise HTTPException(status_code=404, detail=f"Step '{step_id}' not found")

    return step


@router.get("/search")
async def search_docs(request: Request, q: str):
    """Search documentation content"""
    if len(q) < 2:
        raise HTTPException(status_code=400, detail="Query must be at least 2 characters")

    doc_service = request.app.state.shared['doc_service']
    results = doc_service.search_docs(q)

    return {
        "query": q,
        "results": results,
        "count": len(results)
    }


@router.get("/toc/{path:path}")
async def get_doc_toc(request: Request, path: str):
    """Get table of contents for a document"""
    doc_service = request.app.state.shared['doc_service']
    toc = doc_service.get_toc(path)

    if not toc:
        raise HTTPException(status_code=404, detail=f"Document '{path}' not found")

    return {
        "path": path,
        "toc": toc
    }


@router.get("/{path:path}")
async def get_doc(request: Request, path: str, section: Optional[str] = None):
    """Get documentation content"""
    doc_service = request.app.state.shared['doc_service']
    content = doc_service.get_doc(path)

    if not content:
        raise HTTPException(status_code=404, detail=f"Document '{path}' not found")

    if section:
        content = doc_service.get_section(content, section)
        if not content:
            raise HTTPException(status_code=404, detail=f"Section '{section}' not found")

    return {
        "path": path,
        "section": section,
        "content": content
    }
