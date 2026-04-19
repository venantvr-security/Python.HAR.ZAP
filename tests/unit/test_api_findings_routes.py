"""End-to-end tests for /api/v1/findings and /api/v1/webhooks routes.

Uses FastAPI's TestClient against a minimal app that mounts just the two
routers — avoids the heavy lifespan of the full app.
"""
import io
import zipfile

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from modules.findings_store import reset_for_tests as reset_findings
from modules.fp_store import reset_for_tests as reset_fp
from modules.webhook_sender import reset_for_tests as reset_webhooks
from web.api.routes import findings as findings_route
from web.api.routes import webhooks as webhooks_route


@pytest.fixture
def client(tmp_path):
    reset_fp(path=tmp_path / "fp.json")
    reset_findings()
    reset_webhooks(path=tmp_path / "hooks.json")

    app = FastAPI()
    app.include_router(findings_route.router, prefix="/api/v1/findings")
    app.include_router(webhooks_route.router, prefix="/api/v1/webhooks")
    return TestClient(app)


def _seed_findings():
    from modules.findings_store import get_store
    s = get_store()
    s.ingest_zap_alerts([{
        "pluginId": 40012, "alert": "SQLi", "url": "https://x/a",
        "risk": "High", "evidence": "' OR 1=1", "method": "POST",
    }])
    s.ingest_advanced("jwt", [{
        "url": "https://x/login", "vulnerable": True, "severity": "HIGH",
        "attack_type": "none_algo",
    }])
    return s


class TestFindingsList:
    def test_empty(self, client):
        r = client.get("/api/v1/findings")
        assert r.status_code == 200
        assert r.json()["items"] == []

    def test_list_after_seed(self, client):
        _seed_findings()
        r = client.get("/api/v1/findings")
        data = r.json()
        assert len(data["items"]) == 2
        assert data["summary"]["total"] == 2

    def test_filter_by_source(self, client):
        _seed_findings()
        r = client.get("/api/v1/findings?source=zap")
        assert len(r.json()["items"]) == 1


class TestFindingsDetail:
    def test_get_by_fingerprint(self, client):
        store = _seed_findings()
        fp = store.list_all()[0]["fingerprint"]
        r = client.get(f"/api/v1/findings/{fp}")
        assert r.status_code == 200
        assert r.json()["fingerprint"] == fp

    def test_404_for_unknown(self, client):
        r = client.get("/api/v1/findings/deadbeef")
        assert r.status_code == 404


class TestFindingsBundle:
    def test_bundle_zip(self, client):
        store = _seed_findings()
        fp = store.list_all()[0]["fingerprint"]
        r = client.get(f"/api/v1/findings/{fp}/bundle.zip")
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/zip"
        zf = zipfile.ZipFile(io.BytesIO(r.content))
        names = set(zf.namelist())
        assert {"finding.json", "curl.sh", "request.http"}.issubset(names)

    def test_bundle_404(self, client):
        assert client.get("/api/v1/findings/deadbeef/bundle.zip").status_code == 404


class TestFalsePositive:
    def test_mark_and_hidden_from_list(self, client):
        store = _seed_findings()
        fp = store.list_all()[0]["fingerprint"]
        r = client.post(f"/api/v1/findings/{fp}/false-positive", json={"reason": "WAF"})
        assert r.status_code == 200
        assert r.json()["marked"] is True
        # Should no longer appear in default listing
        items = client.get("/api/v1/findings").json()["items"]
        assert all(f["fingerprint"] != fp for f in items)

    def test_include_false_positives_flag(self, client):
        store = _seed_findings()
        fp = store.list_all()[0]["fingerprint"]
        client.post(f"/api/v1/findings/{fp}/false-positive", json={"reason": ""})
        items = client.get("/api/v1/findings?include_false_positives=true").json()["items"]
        assert any(f["fingerprint"] == fp for f in items)

    def test_unmark(self, client):
        store = _seed_findings()
        fp = store.list_all()[0]["fingerprint"]
        client.post(f"/api/v1/findings/{fp}/false-positive", json={"reason": ""})
        r = client.delete(f"/api/v1/findings/{fp}/false-positive")
        assert r.status_code == 200


class TestClearFindings:
    def test_clear(self, client):
        _seed_findings()
        assert client.delete("/api/v1/findings").status_code == 200
        assert client.get("/api/v1/findings").json()["items"] == []


class TestWebhooks:
    def test_list_empty(self, client):
        assert client.get("/api/v1/webhooks").json()["items"] == []

    def test_create_and_list(self, client):
        r = client.post(
            "/api/v1/webhooks",
            json={"url": "https://recv.test/", "secret": "s3cr3t", "events": ["*"]},
        )
        assert r.status_code == 200
        items = client.get("/api/v1/webhooks").json()["items"]
        assert len(items) == 1
        assert items[0]["secret"].startswith("•")

    def test_invalid_event_rejected(self, client):
        r = client.post(
            "/api/v1/webhooks",
            json={"url": "https://recv.test/", "secret": "s", "events": ["foo.bar"]},
        )
        assert r.status_code == 400

    def test_delete(self, client):
        created = client.post(
            "/api/v1/webhooks",
            json={"url": "https://recv.test/", "secret": "s"},
        ).json()
        r = client.delete(f"/api/v1/webhooks/{created['id']}")
        assert r.status_code == 200

    def test_supported_events(self, client):
        events = client.get("/api/v1/webhooks/supported-events").json()["events"]
        assert "finding.discovered" in events

    def test_test_endpoint(self, client, monkeypatch):
        created = client.post(
            "/api/v1/webhooks",
            json={"url": "https://recv.test/", "secret": "s", "events": ["scan.completed"]},
        ).json()

        captured = []

        def fake_transport(url, body, headers, timeout):
            captured.append((url, headers))
            return 200

        monkeypatch.setattr(
            "modules.webhook_sender._default_http_post", fake_transport
        )
        r = client.post(f"/api/v1/webhooks/{created['id']}/test")
        assert r.status_code == 200
        assert captured and captured[0][0] == "https://recv.test/"
