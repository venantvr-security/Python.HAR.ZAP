"""Tests for the curl reproduction helpers on Reporter."""
from modules.reporter import Reporter


class TestGenerateCurl:
    def test_get_uses_url(self):
        curl = Reporter.generate_curl({"url": "https://x/", "method": "GET"})
        assert curl.startswith("curl")
        assert "'https://x/'" in curl
        assert "-X" not in curl  # GET is implicit

    def test_post_adds_method(self):
        curl = Reporter.generate_curl({
            "url": "https://x/api", "method": "POST",
            "param": "id", "attack": "1",
        })
        assert "-X POST" in curl
        assert "--data-raw 'id=1'" in curl

    def test_injects_get_payload_when_no_har(self):
        curl = Reporter.generate_curl({
            "url": "https://x/?a=1", "method": "GET",
            "param": "x", "attack": "<svg>",
        })
        assert "x=<svg>" in curl

    def test_uses_har_request_headers_when_available(self):
        curl = Reporter.generate_curl({
            "url": "https://x/",
            "method": "GET",
            "correlation": {
                "request_url": "https://api.example.com/users",
                "request_method": "GET",
            },
            "har_request": {
                "url": "https://api.example.com/users",
                "method": "GET",
                "headers": [
                    {"name": "Authorization", "value": "Bearer token-abc"},
                    {"name": "X-Trace", "value": "it's-here"},
                    {"name": "Content-Length", "value": "10"},  # must be skipped
                ],
            },
        })
        assert "'https://api.example.com/users'" in curl
        assert "Authorization: Bearer token-abc" in curl
        assert "it'\\''s-here" in curl  # escaped single quote
        assert "Content-Length" not in curl

    def test_post_body_from_har(self):
        curl = Reporter.generate_curl({
            "url": "https://x/",
            "method": "POST",
            "har_request": {
                "url": "https://x/api",
                "method": "POST",
                "headers": [{"name": "Content-Type", "value": "application/json"}],
                "postData": {"text": '{"a":1}'},
            },
        })
        assert "--data-raw '{\"a\":1}'" in curl


class TestEnrichFindings:
    def test_adds_curl_reproduce_per_alert(self, tmp_path):
        rep = Reporter(output_dir=str(tmp_path))
        alerts = [
            {"url": "https://x/a", "method": "GET"},
            {"url": "https://x/b", "method": "POST", "param": "q", "attack": "1"},
        ]
        enriched = rep.enrich_findings(alerts)
        assert len(enriched) == 2
        assert all("curl_reproduce" in a for a in enriched)
        assert enriched[0]["curl_reproduce"].startswith("curl")

    def test_enrichment_does_not_mutate_input(self, tmp_path):
        rep = Reporter(output_dir=str(tmp_path))
        alerts = [{"url": "https://x/a", "method": "GET"}]
        rep.enrich_findings(alerts)
        assert "curl_reproduce" not in alerts[0]
