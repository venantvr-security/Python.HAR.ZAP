"""
Build an evidence bundle (zip) from a unified finding.

Bundle content:
  finding.json         — full unified finding payload
  request.http         — raw HTTP request reconstructed from HAR entry if available
  response.http        — raw HTTP response header block + body preview if available
  curl.sh              — ready-to-run cURL command
  script_output.txt    — output of the ZAP JS script that raised the finding (if any)
  evidence.txt         — textual evidence string

No binary screenshot is attached yet (the platform does not capture any) —
the future extension point is documented in the bundle's README.txt.
"""
from __future__ import annotations

import io
import json
import zipfile
from typing import Any, Dict, List, Optional


def _header_block(headers: List[Dict[str, Any]]) -> str:
    lines = []
    for h in headers or []:
        name = h.get("name", "")
        value = h.get("value", "")
        if name:
            lines.append(f"{name}: {value}")
    return "\r\n".join(lines)


def render_http_request(har_request: Optional[Dict[str, Any]]) -> str:
    if not har_request:
        return "# HAR request not available for this finding\n"
    method = har_request.get("method", "GET")
    url = har_request.get("url", "/")
    # Keep it readable; not a strict RFC 7230 framing
    lines = [f"{method} {url}"]
    if har_request.get("headers"):
        lines.append(_header_block(har_request["headers"]))
    body = (har_request.get("postData") or {}).get("text")
    if body:
        lines.append("")
        lines.append(body)
    return "\r\n".join(lines) + "\r\n"


def render_http_response(har_response: Optional[Dict[str, Any]]) -> str:
    if not har_response:
        return "# HAR response not available for this finding\n"
    status = har_response.get("status", "")
    status_text = har_response.get("statusText", "")
    lines = [f"HTTP/1.1 {status} {status_text}".rstrip()]
    if har_response.get("headers"):
        lines.append(_header_block(har_response["headers"]))
    body = (har_response.get("content") or {}).get("text")
    if body:
        lines.append("")
        lines.append(body if len(body) < 50_000 else body[:50_000] + "\n[truncated]")
    return "\r\n".join(lines) + "\r\n"


_README = """\
HAR-ZAP evidence bundle
=======================

Files in this bundle
- finding.json       full unified finding payload (source, severity, raw alert)
- request.http       reconstructed HTTP request from HAR (headers + body)
- response.http      response status + headers + body (truncated at 50 KB)
- curl.sh            one-line cURL command to replay the finding
- script_output.txt  ZAP JS script output (only when the finding came from a
                      script in scripts/active/ or scripts/passive/)
- evidence.txt       textual evidence extracted from the finding

Extensions (future):
- evidence.png for screenshot-based findings
- proof.mp4 for DOM-based XSS timings

Reproduce locally
  bash curl.sh
"""


def build_bundle(
    finding: Dict[str, Any],
    *,
    har_request: Optional[Dict[str, Any]] = None,
    har_response: Optional[Dict[str, Any]] = None,
    script_output: Optional[str] = None,
) -> bytes:
    """Return the raw bytes of a zip bundle for this finding."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("README.txt", _README)
        zf.writestr("finding.json", json.dumps(finding, indent=2, default=str))
        zf.writestr("request.http", render_http_request(har_request or (finding.get("raw") or {}).get("har_request")))
        zf.writestr("response.http", render_http_response(har_response))
        zf.writestr("curl.sh", (finding.get("curl_reproduce") or "# no curl_reproduce").rstrip() + "\n")
        if script_output:
            zf.writestr("script_output.txt", script_output)
        evidence = finding.get("evidence") or ""
        zf.writestr("evidence.txt", (evidence if isinstance(evidence, str) else json.dumps(evidence, default=str)))
    return buf.getvalue()


def suggested_filename(finding: Dict[str, Any]) -> str:
    fp = finding.get("fingerprint", "finding")
    source = finding.get("source", "src")
    return f"harzap-{source}-{fp}.zip"
