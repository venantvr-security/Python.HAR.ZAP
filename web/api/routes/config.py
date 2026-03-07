"""
Configuration API Routes

Endpoints for viewing and updating configuration.
"""
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Dict, List, Optional, Any

router = APIRouter()


class ConfigUpdate(BaseModel):
    key: str
    value: Any


class PolicyUpdate(BaseModel):
    name: str
    enabled: bool
    threshold: Optional[str] = "Medium"
    scanners: Optional[List[int]] = None


@router.get("")
async def get_config(request: Request):
    """Get current configuration"""
    config = request.app.state.shared['config']

    # Filter sensitive data
    safe_config = {k: v for k, v in config.items()
                   if 'password' not in k.lower() and 'key' not in k.lower()}

    return {"config": safe_config}


@router.put("")
async def update_config(request: Request, updates: List[ConfigUpdate]):
    """Update configuration values"""
    config = request.app.state.shared['config']

    # Protected keys that cannot be changed at runtime
    protected = {'zap_port', 'zap_image', 'api_key'}

    updated = []
    for update in updates:
        if update.key in protected:
            continue
        config[update.key] = update.value
        updated.append(update.key)

    return {"updated": updated}


@router.get("/policies")
async def get_scan_policies(request: Request):
    """Get scan policies"""
    config = request.app.state.shared['config']
    return {"policies": config.get('scan_policies', [])}


@router.put("/policies/{name}")
async def update_policy(request: Request, name: str, policy: PolicyUpdate):
    """Update a scan policy"""
    config = request.app.state.shared['config']
    policies = config.get('scan_policies', [])

    for p in policies:
        if p.get('name') == name:
            p['enabled'] = policy.enabled
            if policy.threshold:
                p['threshold'] = policy.threshold
            if policy.scanners:
                p['scanners'] = policy.scanners
            return {"status": "updated", "policy": p}

    raise HTTPException(status_code=404, detail=f"Policy '{name}' not found")


@router.get("/scope")
async def get_scope(request: Request):
    """Get scope configuration"""
    config = request.app.state.shared['config']
    return {
        "scope_domains": config.get('scope_domains', []),
        "exclude_domains": config.get('exclude_domains', []),
        "allowed_methods": config.get('allowed_methods', [])
    }


@router.put("/scope")
async def update_scope(request: Request, scope: Dict[str, List[str]]):
    """Update scope configuration"""
    config = request.app.state.shared['config']

    if 'scope_domains' in scope:
        config['scope_domains'] = scope['scope_domains']
    if 'exclude_domains' in scope:
        config['exclude_domains'] = scope['exclude_domains']
    if 'allowed_methods' in scope:
        config['allowed_methods'] = scope['allowed_methods']

    return {"status": "updated", "scope": scope}


@router.get("/payloads")
async def get_payloads(request: Request):
    """Get available payload categories"""
    config = request.app.state.shared['config']
    payloads = config.get('red_team_payloads', {})

    return {
        "categories": list(payloads.keys()),
        "counts": {k: len(v) for k, v in payloads.items()}
    }


@router.get("/payloads/{category}")
async def get_payload_category(request: Request, category: str):
    """Get payloads for a specific category"""
    config = request.app.state.shared['config']
    payloads = config.get('red_team_payloads', {})

    if category not in payloads:
        raise HTTPException(status_code=404, detail=f"Category '{category}' not found")

    return {
        "category": category,
        "payloads": payloads[category]
    }
