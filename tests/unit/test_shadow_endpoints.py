"""Tests de la détection d'endpoints fantômes (API9)."""
from modules.shadow_endpoints import find_shadow_endpoints, shadow_findings_flat


def _har(items):
    return {"log": {"entries": [{"request": {"method": m, "url": u}} for m, u in items]}}


SPEC = [{'method': 'GET', 'path': '/v1/users/{id}'}, {'method': 'GET', 'path': '/v1/orders'}]


def test_flags_undocumented():
    har = _har([("GET", "https://x/v1/users/42"),        # documenté
                ("GET", "https://x/v1/admin/debug"),      # fantôme + sensible
                ("GET", "https://x/v1/public/info")])     # fantôme banal
    sh = find_shadow_endpoints(har, SPEC)
    tpls = {f.endpoint for f in sh}
    assert "GET /v1/users/{id}" not in tpls           # documenté -> pas fantôme
    assert "GET /v1/admin/debug" in tpls and "GET /v1/public/info" in tpls

def test_sensitivity_heuristic():
    har = _har([("GET", "https://x/v1/admin/debug"), ("GET", "https://x/v1/public/info")])
    sh = {f.endpoint: f for f in find_shadow_endpoints(har, SPEC)}
    assert sh["GET /v1/admin/debug"].sensitive and sh["GET /v1/admin/debug"].severity == 'High'
    assert not sh["GET /v1/public/info"].sensitive

def test_flat_findings():
    har = _har([("GET", "https://x/v1/admin/debug")])
    flat = shadow_findings_flat(find_shadow_endpoints(har, SPEC))
    assert flat[0]['source'] == 'shadow_endpoint' and flat[0]['risk'] == 'High'
