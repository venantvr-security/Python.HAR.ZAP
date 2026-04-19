"""Tests for the unified findings store."""
import pytest

from modules.findings_store import FindingsStore, reset_for_tests
from modules.fp_store import reset_for_tests as reset_fp_store


@pytest.fixture
def store(tmp_path):
    reset_fp_store(path=tmp_path / "fp.json")
    return reset_for_tests()


def _zap_alert(url="https://x/a", risk="High", plugin=40012):
    return {
        "pluginId": plugin,
        "alert": "SQL Injection",
        "url": url,
        "risk": risk,
        "evidence": "' OR 1=1 --",
        "description": "blah",
        "method": "POST",
    }


class TestIngestZap:
    def test_single_alert(self, store):
        store.ingest_zap_alerts([_zap_alert()])
        items = store.list_all()
        assert len(items) == 1
        assert items[0]["source"] == "zap"
        assert items[0]["severity"] == "HIGH"
        assert items[0]["url"] == "https://x/a"

    def test_dedup_by_fingerprint(self, store):
        store.ingest_zap_alerts([_zap_alert(), _zap_alert()])
        assert len(store.list_all()) == 1

    def test_multiple_alerts(self, store):
        store.ingest_zap_alerts([_zap_alert(url="https://x/a"), _zap_alert(url="https://x/b")])
        assert len(store.list_all()) == 2


class TestIngestAdvanced:
    def test_from_dataclass_like(self, store):
        advanced = [{"url": "https://x/jwt", "vulnerable": True, "severity": "HIGH",
                     "attack_type": "none_algo", "evidence": {"alg": "none"}}]
        store.ingest_advanced("jwt", advanced)
        items = store.list_all()
        assert len(items) == 1
        assert items[0]["source"] == "advanced"
        assert items[0]["attack_type"] == "jwt"

    def test_non_vulnerable_becomes_low(self, store):
        store.ingest_advanced("cors", [{"url": "https://x/", "vulnerable": False, "severity": None}])
        assert store.list_all()[0]["severity"] == "LOW"


class TestIngestIdor:
    def test_vulnerable_is_high(self, store):
        class FakeIDOR:
            status = "VULNERABLE"
            url = "https://x/admin/42"
            method = "GET"
            confidence = 0.9
        store.ingest_idor_results([FakeIDOR()])
        items = store.list_all()
        assert items[0]["severity"] == "HIGH"
        assert items[0]["source"] == "idor"


class TestIngestPassive:
    def test_passive_severity_normalisation(self, store):
        store.ingest_passive([{"severity": "MEDIUM", "category": "csp", "description": "CSP missing",
                               "evidence": {"url": "https://x/"}, "remediation": "..."}])
        items = store.list_all()
        assert items[0]["severity"] == "MEDIUM"
        assert items[0]["source"] == "passive"
        assert items[0]["url"] == "https://x/"


class TestIngestRedteam:
    def test_red_team_item(self, store):
        store.ingest_redteam([{"attack_name": "mass_assignment", "url": "https://x/profile",
                               "vulnerable": True, "severity": "HIGH", "evidence": "role=admin"}])
        items = store.list_all()
        assert items[0]["source"] == "redteam"
        assert items[0]["attack_type"] == "mass_assignment"


class TestFiltering:
    def test_filter_by_source(self, store):
        store.ingest_zap_alerts([_zap_alert()])
        store.ingest_advanced("jwt", [{"url": "https://x/", "vulnerable": True}])
        assert len(store.list_all(source="zap")) == 1
        assert len(store.list_all(source="advanced")) == 1

    def test_filter_by_severity(self, store):
        store.ingest_zap_alerts([_zap_alert(risk="High"), _zap_alert(url="https://x/b", risk="Low")])
        assert len(store.list_all(severity="High")) == 1
        assert len(store.list_all(severity="Low")) == 1

    def test_hide_false_positives_by_default(self, store):
        from modules.fp_store import get_store as get_fp_store
        alert = _zap_alert()
        store.ingest_zap_alerts([alert])
        get_fp_store().mark(alert)
        assert len(store.list_all()) == 0
        assert len(store.list_all(include_false_positives=True)) == 1


class TestSummary:
    def test_counts(self, store):
        store.ingest_zap_alerts([_zap_alert(risk="High"), _zap_alert(url="https://x/b", risk="Low")])
        store.ingest_advanced("jwt", [{"url": "https://x/jwt", "vulnerable": True, "severity": "HIGH"}])
        s = store.summary()
        assert s["total"] == 3
        assert s["by_source"]["zap"] == 2
        assert s["by_source"]["advanced"] == 1
        assert s["by_severity"]["HIGH"] == 2

    def test_fp_count_in_summary(self, store):
        from modules.fp_store import get_store as get_fp_store
        alert = _zap_alert()
        store.ingest_zap_alerts([alert])
        get_fp_store().mark(alert)
        assert store.summary()["false_positives"] == 1


class TestGetAndClear:
    def test_get_by_fingerprint(self, store):
        store.ingest_zap_alerts([_zap_alert()])
        fp = store.list_all()[0]["fingerprint"]
        assert store.get(fp)["source"] == "zap"

    def test_get_missing_returns_none(self, store):
        assert store.get("0000000000") is None

    def test_clear(self, store):
        store.ingest_zap_alerts([_zap_alert()])
        store.clear()
        assert store.list_all() == []
