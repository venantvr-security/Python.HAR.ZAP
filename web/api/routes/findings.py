"""
Unified findings API — single place to list findings from every source,
fetch one by fingerprint, export an evidence bundle zip, and mark false
positives.
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel

from modules.findings_bundle import build_bundle, suggested_filename
from modules.findings_store import get_store as get_findings_store
from modules.fp_store import get_store as get_fp_store

router = APIRouter()


class FalsePositiveRequest(BaseModel):
    reason: str = ""


@router.get("")
async def list_findings(
    source: Optional[str] = Query(None, description="zap | idor | redteam | passive | advanced | llm"),
    severity: Optional[str] = Query(None),
    attack_type: Optional[str] = Query(None),
    include_false_positives: bool = Query(False),
):
    """Return every finding known to the session, filtered to taste."""
    store = get_findings_store()
    return {
        "items": store.list_all(
            source=source,
            severity=severity,
            attack_type=attack_type,
            include_false_positives=include_false_positives,
        ),
        "summary": store.summary(),
    }


@router.get("/summary")
async def findings_summary():
    """Counts grouped by source and severity — useful for dashboards."""
    return get_findings_store().summary()


@router.get("/{fingerprint}")
async def get_finding(fingerprint: str):
    """Fetch one unified finding by fingerprint."""
    item = get_findings_store().get(fingerprint)
    if not item:
        raise HTTPException(status_code=404, detail="Finding not found")
    return item


@router.get("/{fingerprint}/bundle.zip")
async def download_bundle(fingerprint: str):
    """Zip with finding.json, request.http, response.http, curl.sh, evidence."""
    store = get_findings_store()
    finding = store.get(fingerprint)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    raw = finding.get("raw") or {}
    har_request = raw.get("har_request") if isinstance(raw, dict) else None
    content = build_bundle(finding, har_request=har_request)
    return Response(
        content=content,
        media_type="application/zip",
        headers={
            "Content-Disposition": f"attachment; filename=\"{suggested_filename(finding)}\""
        },
    )


@router.post("/{fingerprint}/false-positive")
async def mark_false_positive(fingerprint: str, body: FalsePositiveRequest):
    """Mark a finding as a false positive — persisted via modules.fp_store."""
    store = get_findings_store()
    finding = store.get(fingerprint)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    fp_store = get_fp_store()
    alert_raw = finding.get("raw") or {
        "pluginId": finding.get("attack_type", "0"),
        "url": finding.get("url", ""),
        "evidence": finding.get("evidence", ""),
    }
    fp_store.mark(alert_raw, reason=body.reason)
    return {"fingerprint": fingerprint, "marked": True}


@router.delete("/{fingerprint}/false-positive")
async def unmark_false_positive(fingerprint: str):
    """Remove the false-positive flag for this fingerprint."""
    fp_store = get_fp_store()
    # fp_store stores with the alert-fingerprint which equals our `fingerprint`
    removed = fp_store.unmark(fingerprint)
    if not removed:
        raise HTTPException(status_code=404, detail="Not marked as false-positive")
    return {"fingerprint": fingerprint, "unmarked": True}


@router.delete("")
async def clear_findings():
    """Flush all findings — use between scans when you want a clean slate."""
    get_findings_store().clear()
    return {"cleared": True}
