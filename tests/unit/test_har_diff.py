"""Tests for har_diff module."""
import json

from modules.har_diff import diff_hars


def _har(entries):
    return {"log": {"entries": entries}}


def _entry(url, method="GET", status=200, body=None):
    entry = {
        "request": {"url": url, "method": method, "headers": []},
        "response": {"status": status},
    }
    if body is not None:
        entry["request"]["postData"] = {
            "mimeType": "application/json",
            "text": json.dumps(body),
        }
    return entry


class TestHarDiff:
    def test_only_in_a(self):
        a = _har([_entry("https://x.com/only-a")])
        b = _har([_entry("https://x.com/shared")])
        diff = diff_hars(a, b)
        assert "GET /only-a" in diff.only_in_a
        assert "GET /shared" in diff.only_in_b

    def test_shared(self):
        a = _har([_entry("https://x.com/u/1")])
        b = _har([_entry("https://x.com/u/1")])
        diff = diff_hars(a, b)
        assert "GET /u/1" in diff.shared

    def test_status_delta(self):
        a = _har([_entry("https://x.com/admin", status=403)])
        b = _har([_entry("https://x.com/admin", status=200)])
        diff = diff_hars(a, b)
        assert any(d["status_a"] == 403 and d["status_b"] == 200 for d in diff.status_deltas)

    def test_param_delta_json(self):
        a = _har([_entry("https://x.com/api", method="POST", body={"name": "alice"})])
        b = _har([_entry("https://x.com/api", method="POST", body={"name": "admin", "role": "admin"})])
        diff = diff_hars(a, b)
        assert diff.param_deltas, diff.param_deltas
        d = diff.param_deltas[0]
        assert "role" in d["params_only_b"]

    def test_idor_candidate_numeric_id(self):
        a = _har([_entry("https://x.com/users/42", status=200)])
        b = _har([])
        diff = diff_hars(a, b)
        assert any("/users/42" in c["endpoint"] for c in diff.idor_candidates)

    def test_idor_candidate_uuid(self):
        uid = "550e8400-e29b-41d4-a716-446655440000"
        a = _har([_entry(f"https://x.com/accounts/{uid}", status=200)])
        diff = diff_hars(a, _har([]))
        assert any("/accounts/" in c["endpoint"] for c in diff.idor_candidates)

    def test_no_idor_candidate_for_static_path(self):
        a = _har([_entry("https://x.com/about", status=200)])
        diff = diff_hars(a, _har([]))
        assert not diff.idor_candidates

    def test_to_dict_structure(self):
        a = _har([_entry("https://x.com/a")])
        b = _har([_entry("https://x.com/b")])
        d = diff_hars(a, b).to_dict()
        assert "summary" in d
        assert d["summary"]["only_a"] == 1
        assert d["summary"]["only_b"] == 1
