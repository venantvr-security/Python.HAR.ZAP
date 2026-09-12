"""Tests du rapport de couverture (déterministe)."""
from modules.coverage import build_coverage, har_endpoints, CoverageReport


def _har(paths):
    return {"log": {"entries": [{"request": {"method": "GET", "url": u}} for u in paths]}}


HAR = _har(["https://x/v1/users/42", "https://x/v1/orders/7", "https://x/v1/health"])


def test_endpoint_coverage():
    rep = build_coverage(HAR, {"GET /v1/users/{id}"}, {"API1:2023"})
    assert rep.observed and rep.endpoint_pct == round(100/3, 1)
    assert "GET /v1/health" in rep.untested

def test_category_coverage():
    rep = build_coverage(HAR, set(), {"API1", "API5:2023"})
    assert set(rep.categories_tested) == {"API1", "API5"}
    assert "API10" in rep.categories_not_tested and rep.category_pct == 20.0

def test_ids_collapse():
    assert har_endpoints(_har(["https://x/u/1", "https://x/u/2"])) == {"GET /u/{id}"}

def test_render():
    out = __import__('modules.coverage', fromlist=['render_cli']).render_cli(
        build_coverage(HAR, {"GET /v1/health"}, {"API8"}))
    assert "COVERAGE" in out and "Not covered" in out
