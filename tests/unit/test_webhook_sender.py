"""Tests for the webhook sender + store."""
import hashlib
import hmac
import json

import pytest

from modules.webhook_sender import (
    EVENT_HEADER,
    ID_HEADER,
    SIGNATURE_HEADER,
    SUPPORTED_EVENTS,
    WebhookStore,
    emit,
    reset_for_tests,
    sign,
)


@pytest.fixture
def store(tmp_path):
    return reset_for_tests(path=tmp_path / "webhooks.json")


class TestWebhookStore:
    def test_add_lists(self, store):
        hook = store.add("https://recv.test/h", "s3cr3t", events=["finding.discovered"])
        assert hook.id
        listed = store.list(reveal_secrets=False)
        assert len(listed) == 1
        assert listed[0]["secret"].startswith("•")

    def test_add_with_bad_event_raises(self, store):
        with pytest.raises(ValueError):
            store.add("https://recv.test/h", "s", events=["not.a.real.event"])

    def test_remove(self, store):
        hook = store.add("https://recv.test/h", "s")
        assert store.remove(hook.id) is True
        assert store.remove(hook.id) is False

    def test_persistence_across_instances(self, tmp_path):
        path = tmp_path / "webhooks.json"
        s1 = WebhookStore(path=path)
        s1.add("https://recv.test/h", "s3cr3t")
        s2 = WebhookStore(path=path)
        assert len(s2.list()) == 1

    def test_for_event_matches_wildcard(self, store):
        store.add("https://recv.test/", "s", events=["*"])
        assert len(store.for_event("finding.discovered")) == 1

    def test_for_event_matches_exact(self, store):
        store.add("https://recv.test/a", "s", events=["finding.discovered"])
        store.add("https://recv.test/b", "s", events=["scan.completed"])
        assert len(store.for_event("finding.discovered")) == 1


class TestSign:
    def test_hmac_matches_manual(self):
        body = b'{"x": 1}'
        secret = "top-secret"
        expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        assert sign(secret, body) == expected


class TestEmit:
    def test_no_hooks_no_reports(self, store):
        reports = emit("scan.completed", {"ok": True}, store=store, transport=lambda *a, **k: 200)
        assert reports == []

    def test_delivers_to_matching_hook(self, store):
        store.add("https://recv.test/x", "s", events=["*"])

        calls = []

        def fake_transport(url, body, headers, timeout):
            calls.append((url, body, headers))
            return 200

        reports = emit("finding.discovered", {"fp": "abc"}, store=store, transport=fake_transport)
        assert len(reports) == 1
        assert reports[0]["status"] == 200
        assert reports[0]["attempts"] == 1
        url, body, headers = calls[0]
        assert url == "https://recv.test/x"
        assert SIGNATURE_HEADER in headers
        assert headers[EVENT_HEADER] == "finding.discovered"
        assert ID_HEADER in headers
        payload = json.loads(body.decode())
        assert payload["event"] == "finding.discovered"
        assert payload["payload"]["fp"] == "abc"
        # Signature verifiable with the webhook secret
        sig = headers[SIGNATURE_HEADER].split("=", 1)[1]
        assert sig == sign("s", body)

    def test_skips_disabled_event_filter(self, store):
        store.add("https://recv.test/a", "s", events=["scan.completed"])
        reports = emit("finding.discovered", {}, store=store, transport=lambda *a, **k: 200)
        assert reports == []

    def test_retries_on_failure_then_gives_up(self, store):
        store.add("https://recv.test/a", "s", events=["*"])

        def flaky(*a, **k):
            raise RuntimeError("boom")

        reports = emit("finding.discovered", {}, store=store, transport=flaky, max_retries=2, timeout=0.01)
        assert reports[0]["attempts"] == 2
        assert "boom" in reports[0]["error"]

    def test_non_2xx_counts_as_error(self, store):
        store.add("https://recv.test/a", "s", events=["*"])
        reports = emit("finding.discovered", {}, store=store, transport=lambda *a, **k: 500,
                       max_retries=1)
        assert reports[0]["status"] == 500
        assert reports[0]["error"] == "http 500"


class TestSupportedEvents:
    def test_contains_key_events(self):
        assert "finding.discovered" in SUPPORTED_EVENTS
        assert "scan.completed" in SUPPORTED_EVENTS
        assert "*" in SUPPORTED_EVENTS
