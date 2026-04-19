"""
Correlator — link ZAP alerts back to the HAR entries that triggered them.

A ZAP alert carries a URL but not the HAR entry that seeded the scan. During
a pentest, knowing *which captured request* led to a finding is critical:
- it proves the finding is in-scope (you recorded it yourself),
- it lets you rebuild the attack from the original request,
- it turns a flat alert list into a finding-by-endpoint story.

The correlation is best-effort: exact-URL match first, then normalized URL
(strip query), then path-only, then domain. The confidence drops with each
fallback so the UI can colour-code accordingly.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse


@dataclass
class CorrelatedAlert:
    alert: Dict[str, Any]
    har_entry_index: Optional[int] = None
    matched_endpoint: Optional[str] = None
    match_confidence: str = "none"          # exact | normalized | path | domain | none
    har_request: Optional[Dict[str, Any]] = None
    har_response_status: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        result = dict(self.alert)
        result["correlation"] = {
            "har_entry_index": self.har_entry_index,
            "matched_endpoint": self.matched_endpoint,
            "confidence": self.match_confidence,
            "request_method": (self.har_request or {}).get("method"),
            "request_url": (self.har_request or {}).get("url"),
            "response_status": self.har_response_status,
        }
        return result


def _normalize(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def _path_only(url: str) -> str:
    return urlparse(url).path or "/"


def _domain(url: str) -> str:
    return urlparse(url).netloc


def _index_har(har_data: Dict[str, Any]) -> Dict[str, List[int]]:
    """Build lookup indexes: exact URL, normalized URL, path, domain → entry indices."""
    index = {"exact": {}, "normalized": {}, "path": {}, "domain": {}}
    entries = (har_data or {}).get("log", {}).get("entries", [])
    for i, entry in enumerate(entries):
        url = entry.get("request", {}).get("url", "")
        if not url:
            continue
        index["exact"].setdefault(url, []).append(i)
        index["normalized"].setdefault(_normalize(url), []).append(i)
        index["path"].setdefault(_path_only(url), []).append(i)
        index["domain"].setdefault(_domain(url), []).append(i)
    return index


def correlate_alerts(alerts: Iterable[Dict[str, Any]], har_data: Dict[str, Any]) -> List[CorrelatedAlert]:
    """Correlate each alert with the best-matching HAR entry."""
    idx = _index_har(har_data)
    entries = (har_data or {}).get("log", {}).get("entries", [])
    out: List[CorrelatedAlert] = []

    for alert in alerts:
        url = alert.get("url") or alert.get("uri") or ""
        hit_index: Optional[int] = None
        confidence = "none"

        if not url:
            out.append(CorrelatedAlert(alert=alert))
            continue

        # Cascade de correspondance du plus strict au plus large. On s'arrête
        # dès qu'un niveau matche — le résultat porte son propre niveau de
        # confiance pour que l'UI puisse colorer le lien vers le HAR :
        # exact > normalized (query string ignorée) > path > domain.
        for key, lookup, conf in (
            (url, "exact", "exact"),
            (_normalize(url), "normalized", "normalized"),
            (_path_only(url), "path", "path"),
            (_domain(url), "domain", "domain"),
        ):
            hits = idx[lookup].get(key)
            if hits:
                hit_index = hits[0]
                confidence = conf
                break

        req: Optional[Dict[str, Any]] = None
        status: Optional[int] = None
        if hit_index is not None:
            entry = entries[hit_index]
            req = entry.get("request")
            status = entry.get("response", {}).get("status")

        out.append(CorrelatedAlert(
            alert=alert,
            har_entry_index=hit_index,
            matched_endpoint=url,
            match_confidence=confidence,
            har_request=req,
            har_response_status=status,
        ))

    return out


def correlation_summary(correlated: List[CorrelatedAlert]) -> Dict[str, int]:
    """Count matches by confidence level — useful for a UI summary line."""
    counts: Dict[str, int] = {"exact": 0, "normalized": 0, "path": 0, "domain": 0, "none": 0}
    for c in correlated:
        counts[c.match_confidence] = counts.get(c.match_confidence, 0) + 1
    return counts
