"""Tests for fp_store — false-positive persistence."""
import json
from pathlib import Path

import pytest

from modules.fp_store import FalsePositiveStore, fingerprint, reset_for_tests


@pytest.fixture
def store(tmp_path) -> FalsePositiveStore:
    return reset_for_tests(path=tmp_path / ".harzap_false_positives.json")


class TestFingerprint:
    def test_stable_across_calls(self):
        alert = {"pluginId": "40012", "url": "https://x/a?q=1", "evidence": "<script>"}
        assert fingerprint(alert) == fingerprint(alert)

    def test_ignores_query_string(self):
        a = {"pluginId": "40012", "url": "https://x/a?q=1", "evidence": "e"}
        b = {"pluginId": "40012", "url": "https://x/a?q=2", "evidence": "e"}
        assert fingerprint(a) == fingerprint(b)

    def test_differs_on_plugin_id(self):
        a = {"pluginId": "40012", "url": "https://x/a", "evidence": "e"}
        b = {"pluginId": "40014", "url": "https://x/a", "evidence": "e"}
        assert fingerprint(a) != fingerprint(b)

    def test_differs_on_path(self):
        a = {"pluginId": "1", "url": "https://x/a", "evidence": "e"}
        b = {"pluginId": "1", "url": "https://x/b", "evidence": "e"}
        assert fingerprint(a) != fingerprint(b)

    def test_differs_on_evidence(self):
        a = {"pluginId": "1", "url": "https://x/a", "evidence": "<script>"}
        b = {"pluginId": "1", "url": "https://x/a", "evidence": "' OR 1=1"}
        assert fingerprint(a) != fingerprint(b)


class TestFalsePositiveStore:
    def test_mark_and_is_fp(self, store):
        alert = {"pluginId": "40012", "url": "https://x/a", "evidence": "e", "alert": "XSS"}
        assert not store.is_fp(alert)
        fp = store.mark(alert, reason="WAF intercepts")
        assert store.is_fp(alert)
        assert fp == fingerprint(alert)

    def test_persistence_survives_reload(self, tmp_path):
        path = tmp_path / "fp.json"
        s1 = FalsePositiveStore(path=path)
        alert = {"pluginId": "40012", "url": "https://x/a", "alert": "X"}
        s1.mark(alert, reason="test")

        s2 = FalsePositiveStore(path=path)
        assert s2.is_fp(alert)

    def test_unmark(self, store):
        alert = {"pluginId": "40012", "url": "https://x/a", "alert": "X"}
        fp = store.mark(alert)
        assert store.unmark(fp) is True
        assert not store.is_fp(alert)

    def test_unmark_unknown(self, store):
        assert store.unmark("0000000000000000") is False

    def test_list_all(self, store):
        store.mark({"pluginId": "1", "url": "https://x/a", "alert": "X"}, reason="r1")
        store.mark({"pluginId": "2", "url": "https://x/b", "alert": "Y"}, reason="r2")
        lst = store.list_all()
        assert len(lst) == 2
        assert all("fingerprint" in e for e in lst)

    def test_filter_alerts(self, store):
        fp = {"pluginId": "1", "url": "https://x/a", "alert": "X"}
        safe = {"pluginId": "2", "url": "https://x/b", "alert": "Y"}
        store.mark(fp)
        filtered = store.filter_alerts([fp, safe])
        assert filtered == [safe]

    def test_annotate_alerts(self, store):
        fp = {"pluginId": "1", "url": "https://x/a", "alert": "X"}
        safe = {"pluginId": "2", "url": "https://x/b", "alert": "Y"}
        store.mark(fp)
        annotated = store.annotate_alerts([fp, safe])
        assert annotated[0]["is_false_positive"] is True
        assert annotated[1]["is_false_positive"] is False
        assert "fingerprint" in annotated[0]

    def test_annotate_does_not_mutate_input(self, store):
        alert = {"pluginId": "1", "url": "https://x/a", "alert": "X"}
        store.mark(alert)
        store.annotate_alerts([alert])
        assert "is_false_positive" not in alert
        assert "fingerprint" not in alert

    def test_file_is_readable_json(self, tmp_path):
        path = tmp_path / "fp.json"
        store = FalsePositiveStore(path=path)
        store.mark({"pluginId": "1", "url": "https://x/a", "alert": "X"}, reason="r")
        data = json.loads(path.read_text())
        assert data["version"] == 1
        assert len(data["entries"]) == 1
        assert data["entries"][0]["reason"] == "r"

    def test_missing_file_starts_empty(self, tmp_path):
        store = FalsePositiveStore(path=tmp_path / "nonexistent.json")
        assert store.list_all() == []

    def test_corrupt_file_starts_empty(self, tmp_path):
        path = tmp_path / "fp.json"
        path.write_text("not json")
        store = FalsePositiveStore(path=path)
        assert store.list_all() == []
