"""
Webhooks API — register outbound receivers for scan/finding events and
trigger a signed test call.
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from modules.webhook_sender import (
    SUPPORTED_EVENTS,
    emit,
    get_store as get_webhook_store,
)

router = APIRouter()


class WebhookCreate(BaseModel):
    url: str
    secret: str = Field(..., description="HMAC-SHA256 shared secret; never echoed back")
    events: Optional[List[str]] = None
    description: str = ""


@router.get("")
async def list_webhooks():
    return {"items": get_webhook_store().list(reveal_secrets=False)}


@router.post("")
async def create_webhook(body: WebhookCreate):
    try:
        hook = get_webhook_store().add(
            url=body.url,
            secret=body.secret,
            events=body.events,
            description=body.description,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return hook.to_dict(reveal_secret=False)


@router.delete("/{hook_id}")
async def delete_webhook(hook_id: str):
    if not get_webhook_store().remove(hook_id):
        raise HTTPException(status_code=404, detail="Webhook not found")
    return {"deleted": hook_id}


@router.post("/{hook_id}/test")
async def test_webhook(hook_id: str):
    """Send a signed `scan.completed` with a dummy payload to verify the wire-up."""
    store = get_webhook_store()
    hook = store.get(hook_id)
    if not hook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    reports = emit(
        "scan.completed",
        {"ok": True, "summary": "webhook test", "webhook_id": hook_id},
        store=store,
    )
    return {"reports": reports}


@router.get("/supported-events")
async def supported_events():
    return {"events": list(SUPPORTED_EVENTS)}
