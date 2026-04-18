"""Tests for correlator module."""
from modules.correlator import correlate_alerts, correlation_summary


def _har(entries):
    return {"log": {"entries": entries}}


def _entry(url, method="GET", status=200):
    return {
        "request": {"url": url, "method": method, "headers": []},
        "response": {"status": status},
    }


class TestCorrelator:
    def test_exact_match(self):
        alerts = [{"url": "https://x.com/users/42", "risk": "High"}]
        har = _har([_entry("https://x.com/users/42")])
        out = correlate_alerts(alerts, har)
        assert out[0].match_confidence == "exact"
        assert out[0].har_entry_index == 0
        assert out[0].har_response_status == 200

    def test_normalized_match_strips_query(self):
        alerts = [{"url": "https://x.com/users/42?utm=foo"}]
        har = _har([_entry("https://x.com/users/42?page=1")])
        out = correlate_alerts(alerts, har)
        assert out[0].match_confidence == "normalized"
        assert out[0].har_entry_index == 0

    def test_path_match(self):
        alerts = [{"url": "https://y.com/users/42"}]
        har = _har([_entry("https://x.com/users/42")])
        out = correlate_alerts(alerts, har)
        assert out[0].match_confidence == "path"

    def test_domain_match(self):
        alerts = [{"url": "https://x.com/unseen"}]
        har = _har([_entry("https://x.com/other")])
        out = correlate_alerts(alerts, har)
        assert out[0].match_confidence == "domain"

    def test_no_match(self):
        alerts = [{"url": "https://unknown.com/foo"}]
        har = _har([_entry("https://x.com/bar")])
        out = correlate_alerts(alerts, har)
        assert out[0].match_confidence == "none"
        assert out[0].har_entry_index is None

    def test_empty_url_returns_none(self):
        out = correlate_alerts([{"url": ""}], _har([_entry("https://x.com/a")]))
        assert out[0].match_confidence == "none"

    def test_to_dict_preserves_alert_and_adds_correlation(self):
        alerts = [{"url": "https://x.com/a", "alert": "XSS", "risk": "High"}]
        har = _har([_entry("https://x.com/a")])
        out = correlate_alerts(alerts, har)
        d = out[0].to_dict()
        assert d["alert"] == "XSS"
        assert d["correlation"]["har_entry_index"] == 0
        assert d["correlation"]["confidence"] == "exact"
        assert d["correlation"]["response_status"] == 200

    def test_summary_counts(self):
        alerts = [
            {"url": "https://x.com/a"},
            {"url": "https://x.com/a"},
            {"url": "https://y.com/"},
            {"url": ""},
        ]
        har = _har([_entry("https://x.com/a")])
        out = correlate_alerts(alerts, har)
        s = correlation_summary(out)
        assert s["exact"] == 2
        assert s["none"] >= 1
