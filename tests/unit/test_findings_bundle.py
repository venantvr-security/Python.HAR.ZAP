"""Tests for findings_bundle.build_bundle."""
import io
import json
import zipfile

from modules.findings_bundle import build_bundle, render_http_request, render_http_response, suggested_filename


class TestRenderHttpRequest:
    def test_missing_returns_hint(self):
        out = render_http_request(None)
        assert "not available" in out

    def test_method_url_headers_body(self):
        out = render_http_request({
            "method": "POST",
            "url": "https://x/",
            "headers": [{"name": "H", "value": "v"}],
            "postData": {"text": "payload"},
        })
        assert "POST https://x/" in out
        assert "H: v" in out
        assert "payload" in out


class TestRenderHttpResponse:
    def test_status_headers(self):
        out = render_http_response({
            "status": 200,
            "statusText": "OK",
            "headers": [{"name": "X", "value": "1"}],
            "content": {"text": "body"},
        })
        assert "HTTP/1.1 200" in out
        assert "X: 1" in out
        assert "body" in out

    def test_missing_returns_hint(self):
        assert "not available" in render_http_response(None)

    def test_truncates_large_body(self):
        big = "a" * 80_000
        out = render_http_response({"status": 200, "statusText": "OK",
                                    "content": {"text": big}, "headers": []})
        assert "[truncated]" in out


class TestBuildBundle:
    def _finding(self, **over):
        base = {
            "fingerprint": "abc123",
            "source": "zap",
            "attack_type": "xss",
            "severity": "HIGH",
            "url": "https://x/",
            "method": "GET",
            "evidence": "<script>alert(1)</script>",
            "description": "XSS",
            "solution": "sanitize",
            "curl_reproduce": "curl 'https://x/?q=<script>'",
            "raw": {},
        }
        base.update(over)
        return base

    def test_zip_contains_expected_files(self):
        data = build_bundle(self._finding())
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = set(zf.namelist())
        assert {"README.txt", "finding.json", "request.http", "response.http",
                "curl.sh", "evidence.txt"}.issubset(names)

    def test_finding_json_round_trips(self):
        data = build_bundle(self._finding())
        zf = zipfile.ZipFile(io.BytesIO(data))
        payload = json.loads(zf.read("finding.json"))
        assert payload["fingerprint"] == "abc123"
        assert payload["source"] == "zap"

    def test_curl_present(self):
        data = build_bundle(self._finding(curl_reproduce="curl 'https://x/'"))
        zf = zipfile.ZipFile(io.BytesIO(data))
        content = zf.read("curl.sh").decode()
        assert "curl 'https://x/'" in content

    def test_script_output_written_when_given(self):
        data = build_bundle(self._finding(), script_output="line1\nline2")
        zf = zipfile.ZipFile(io.BytesIO(data))
        assert "line1" in zf.read("script_output.txt").decode()

    def test_script_output_absent_by_default(self):
        data = build_bundle(self._finding())
        zf = zipfile.ZipFile(io.BytesIO(data))
        assert "script_output.txt" not in zf.namelist()

    def test_uses_har_request_param(self):
        data = build_bundle(
            self._finding(),
            har_request={"method": "POST", "url": "https://x/api",
                         "headers": [{"name": "Authorization", "value": "Bearer t"}],
                         "postData": {"text": "{}"}},
        )
        zf = zipfile.ZipFile(io.BytesIO(data))
        req = zf.read("request.http").decode()
        assert "POST https://x/api" in req
        assert "Authorization: Bearer t" in req


class TestSuggestedFilename:
    def test_format(self):
        name = suggested_filename({"fingerprint": "abc", "source": "zap"})
        assert name == "harzap-zap-abc.zip"

    def test_fallbacks(self):
        name = suggested_filename({})
        assert name.endswith(".zip")
