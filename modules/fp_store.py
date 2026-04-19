"""
False-positive store — small JSON-backed registry of alert fingerprints the
pentester has confirmed as non-exploitable.

Design principles:
- Persistence is a single JSON file at the project root (`.harzap_false_positives.json`)
  so it survives Streamlit restarts and CLI runs without needing a database.
- A fingerprint is stable across scans: pluginId + URL path + evidence hash.
  We intentionally drop query strings to avoid regenerating FPs for equivalent
  alerts that differ only by `?cb=random`.
- Returns plain dicts / strings so callers stay framework-agnostic.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

DEFAULT_PATH = Path(os.environ.get("HARZAP_FP_FILE", "./.harzap_false_positives.json"))


@dataclass
class FPEntry:
    fingerprint: str
    plugin_id: str
    url_path: str
    alert_name: str
    reason: str = ""
    marked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "plugin_id": self.plugin_id,
            "url_path": self.url_path,
            "alert_name": self.alert_name,
            "reason": self.reason,
            "marked_at": self.marked_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FPEntry":
        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})


def fingerprint(alert: Dict[str, Any]) -> str:
    """Stable fingerprint — same alert across runs ⇒ same fingerprint."""
    plugin_id = str(alert.get("pluginId") or alert.get("plugin_id") or "0")
    url = alert.get("url") or ""
    path = urlparse(url).path or "/"
    raw_evidence = alert.get("evidence") or ""
    if not isinstance(raw_evidence, str):
        raw_evidence = repr(raw_evidence)
    evidence = raw_evidence.strip()[:128]
    payload = f"{plugin_id}|{path}|{evidence}".encode("utf-8")
    return hashlib.sha1(payload).hexdigest()[:16]


class FalsePositiveStore:
    def __init__(self, path: Path = DEFAULT_PATH):
        self.path = Path(path)
        self._entries: Dict[str, FPEntry] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        for raw in data.get("entries", []):
            entry = FPEntry.from_dict(raw)
            self._entries[entry.fingerprint] = entry

    def _save(self) -> None:
        self.path.write_text(
            json.dumps(
                {"version": 1, "entries": [e.to_dict() for e in self._entries.values()]},
                indent=2,
            ),
            encoding="utf-8",
        )

    def mark(self, alert: Dict[str, Any], reason: str = "") -> str:
        fp = fingerprint(alert)
        url_path = urlparse(alert.get("url") or "").path or "/"
        entry = FPEntry(
            fingerprint=fp,
            plugin_id=str(alert.get("pluginId") or alert.get("plugin_id") or "0"),
            url_path=url_path,
            alert_name=alert.get("alert") or alert.get("name") or "unknown",
            reason=reason,
        )
        self._entries[fp] = entry
        self._save()
        return fp

    def unmark(self, fp: str) -> bool:
        if fp in self._entries:
            del self._entries[fp]
            self._save()
            return True
        return False

    def is_fp(self, alert: Dict[str, Any]) -> bool:
        return fingerprint(alert) in self._entries

    def list_all(self) -> List[Dict[str, Any]]:
        return [e.to_dict() for e in self._entries.values()]

    def filter_alerts(self, alerts: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return a new list with FPs removed — does not mutate input."""
        return [a for a in alerts if not self.is_fp(a)]

    def annotate_alerts(self, alerts: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Same set, but each alert gets `is_false_positive: bool` — useful for UI."""
        out = []
        for a in alerts:
            enriched = dict(a)
            enriched["is_false_positive"] = self.is_fp(a)
            enriched["fingerprint"] = fingerprint(a)
            out.append(enriched)
        return out


_singleton: Optional[FalsePositiveStore] = None


def get_store() -> FalsePositiveStore:
    """Process-wide singleton — avoids re-reading the JSON on every call."""
    global _singleton
    if _singleton is None:
        _singleton = FalsePositiveStore()
    return _singleton


def reset_for_tests(path: Optional[Path] = None) -> FalsePositiveStore:
    """Reset the singleton with an optional custom path (tests only)."""
    global _singleton
    _singleton = FalsePositiveStore(path=path or DEFAULT_PATH)
    return _singleton
