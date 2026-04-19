"""
Unified findings store — merges ZAP alerts, IDOR results, red-team findings,
passive issues, and advanced-attack outputs behind one schema.

Why:
- Today callers must cross `/api/scans/{id}/results`, `/api/zap/alerts`, and
  `/api/attacks/*` to know what was found. A pentester scripting a workflow
  needs a single place to fetch the whole picture.
- The same schema is reused for false-positive marking, curl reproduction,
  bundle export, and outbound webhooks.

Contract of a unified finding:
{
  "fingerprint": str,          # stable, sha1-based, safe across runs
  "source": str,               # zap | idor | redteam | passive | advanced | llm
  "attack_type": str,          # sqli | xss | idor | jwt | cors | ...
  "severity": str,             # CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL
  "url": str,
  "method": str,
  "evidence": str,
  "description": str,
  "solution": str,
  "curl_reproduce": str,
  "har_entry_index": int | None,
  "created_at": str (ISO-8601),
  "is_false_positive": bool,
  "raw": dict                  # the original payload
}
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Dict, Iterable, List, Optional

from modules.fp_store import fingerprint as _alert_fingerprint, get_store as _get_fp_store

SEVERITY_MAP = {
    "High": "HIGH",
    "Medium": "MEDIUM",
    "Low": "LOW",
    "Informational": "INFORMATIONAL",
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFORMATIONAL",
    "INFORMATIONAL": "INFORMATIONAL",
}


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm_severity(value: Any) -> str:
    if not value:
        return "INFORMATIONAL"
    return SEVERITY_MAP.get(str(value), str(value).upper())


def _finding_from_zap_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "fingerprint": alert.get("fingerprint") or _alert_fingerprint(alert),
        "source": "zap",
        "attack_type": str(alert.get("alert") or alert.get("name") or "zap_alert"),
        "severity": _norm_severity(alert.get("risk")),
        "url": alert.get("url", ""),
        "method": (alert.get("method") or (alert.get("correlation") or {}).get("request_method") or "GET"),
        "evidence": alert.get("evidence", "") or "",
        "description": alert.get("description", "") or "",
        "solution": alert.get("solution", "") or "",
        "curl_reproduce": alert.get("curl_reproduce") or "",
        "har_entry_index": (alert.get("correlation") or {}).get("har_entry_index"),
        "raw": alert,
    }


def _finding_from_idor(result: Any) -> Dict[str, Any]:
    # Accept both IDORResult dataclass-ish and plain dict
    url = getattr(result, "url", None) or (result.get("url") if isinstance(result, dict) else "") or ""
    method = getattr(result, "method", None) or (result.get("method") if isinstance(result, dict) else "GET") or "GET"
    confidence = getattr(result, "confidence", None) or (result.get("confidence") if isinstance(result, dict) else 0)
    status = getattr(result, "status", None) or (result.get("status") if isinstance(result, dict) else "UNKNOWN")
    status_str = getattr(status, "value", None) or str(status)

    payload = {
        "url": url, "method": method, "confidence": confidence,
        "status": status_str,
        "pluginId": "IDOR",
    }
    return {
        "fingerprint": _alert_fingerprint(payload),
        "source": "idor",
        "attack_type": "idor",
        "severity": "HIGH" if status_str == "VULNERABLE" else "LOW",
        "url": url,
        "method": method,
        "evidence": f"confidence={confidence}",
        "description": f"IDOR {status_str}",
        "solution": "Enforce authorisation checks per-resource, not only per-authentication.",
        "curl_reproduce": "",
        "har_entry_index": None,
        "raw": result if isinstance(result, dict) else getattr(result, "__dict__", {}),
    }


def _finding_from_advanced(item: Dict[str, Any], attack_key: str) -> Dict[str, Any]:
    return {
        "fingerprint": _alert_fingerprint({
            "pluginId": attack_key,
            "url": item.get("url", ""),
            "evidence": (item.get("evidence") or {}).__repr__() if isinstance(item.get("evidence"), dict) else item.get("evidence", ""),
        }),
        "source": "advanced",
        "attack_type": attack_key,
        "severity": _norm_severity(item.get("severity") or ("HIGH" if item.get("vulnerable") else "LOW")),
        "url": item.get("url", ""),
        "method": item.get("method", "GET"),
        "evidence": str(item.get("evidence", ""))[:500],
        "description": item.get("attack_type") or item.get("vulnerability_type") or attack_key,
        "solution": item.get("remediation", "") or "",
        "curl_reproduce": item.get("curl_reproduce", "") or "",
        "har_entry_index": None,
        "raw": item,
    }


def _finding_from_redteam(item: Any) -> Dict[str, Any]:
    data = item if isinstance(item, dict) else getattr(item, "__dict__", {})
    return {
        "fingerprint": _alert_fingerprint({
            "pluginId": data.get("attack_name") or data.get("name", "redteam"),
            "url": data.get("url", ""),
            "evidence": str(data.get("evidence", ""))[:128],
        }),
        "source": "redteam",
        "attack_type": data.get("attack_name") or data.get("name") or "redteam",
        "severity": _norm_severity(data.get("severity", "HIGH" if data.get("vulnerable") else "LOW")),
        "url": data.get("url", ""),
        "method": data.get("method", ""),
        "evidence": str(data.get("evidence", "")),
        "description": data.get("description", ""),
        "solution": data.get("remediation", ""),
        "curl_reproduce": data.get("curl_reproduce", ""),
        "har_entry_index": None,
        "raw": data,
    }


def _finding_from_passive(issue: Any) -> Dict[str, Any]:
    data = issue if isinstance(issue, dict) else getattr(issue, "__dict__", {})
    return {
        "fingerprint": _alert_fingerprint({
            "pluginId": f"passive:{data.get('category', 'misc')}",
            "url": (data.get("evidence") or {}).get("url", "") if isinstance(data.get("evidence"), dict) else "",
            "evidence": str(data.get("evidence", ""))[:128],
        }),
        "source": "passive",
        "attack_type": data.get("category") or "passive",
        "severity": _norm_severity(data.get("severity")),
        "url": (data.get("evidence") or {}).get("url", "") if isinstance(data.get("evidence"), dict) else "",
        "method": "GET",
        "evidence": str(data.get("evidence", ""))[:500],
        "description": data.get("description", "") or data.get("title", ""),
        "solution": data.get("remediation", ""),
        "curl_reproduce": "",
        "har_entry_index": None,
        "raw": data,
    }


class FindingsStore:
    """In-memory store with dedup by fingerprint and FP-aware listing."""

    def __init__(self) -> None:
        self._findings: Dict[str, Dict[str, Any]] = {}
        self._lock = RLock()

    def clear(self) -> None:
        with self._lock:
            self._findings.clear()

    def _upsert(self, finding: Dict[str, Any]) -> str:
        finding.setdefault("created_at", _iso_now())
        fp = finding["fingerprint"]
        with self._lock:
            existing = self._findings.get(fp)
            if existing:
                # Déduplication par fingerprint : si la même vulnérabilité est
                # réinjestée (scan rejoué, enrichissement LLM, route advanced),
                # on préserve l'horodatage de première détection et on écrase
                # le payload avec les données les plus récentes. Cela évite de
                # bruiter la timeline du pentesteur tout en gardant l'évidence
                # la plus fraîche.
                finding["created_at"] = existing.get("created_at", finding["created_at"])
            self._findings[fp] = finding
        return fp

    def ingest_zap_alerts(self, alerts: Iterable[Dict[str, Any]]) -> List[str]:
        return [self._upsert(_finding_from_zap_alert(a)) for a in alerts]

    def ingest_idor_results(self, results: Iterable[Any]) -> List[str]:
        return [self._upsert(_finding_from_idor(r)) for r in results]

    def ingest_redteam(self, results: Iterable[Any]) -> List[str]:
        return [self._upsert(_finding_from_redteam(r)) for r in results]

    def ingest_passive(self, issues: Iterable[Any]) -> List[str]:
        return [self._upsert(_finding_from_passive(i)) for i in issues]

    def ingest_advanced(self, attack_key: str, findings: Iterable[Dict[str, Any]]) -> List[str]:
        return [self._upsert(_finding_from_advanced(f, attack_key)) for f in findings]

    def get(self, fingerprint: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            item = self._findings.get(fingerprint)
            return self._with_fp_flag(item) if item else None

    def list_all(
        self,
        *,
        source: Optional[str] = None,
        severity: Optional[str] = None,
        attack_type: Optional[str] = None,
        include_false_positives: bool = False,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._findings.values())
        items = [self._with_fp_flag(i) for i in items]

        def keep(f: Dict[str, Any]) -> bool:
            if source and f["source"] != source:
                return False
            if severity and f["severity"] != _norm_severity(severity):
                return False
            if attack_type and f["attack_type"] != attack_type:
                return False
            if not include_false_positives and f.get("is_false_positive"):
                return False
            return True

        return [f for f in items if keep(f)]

    def summary(self) -> Dict[str, Any]:
        items = self.list_all(include_false_positives=True)
        by_source: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        fp_count = 0
        for f in items:
            by_source[f["source"]] = by_source.get(f["source"], 0) + 1
            by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
            if f.get("is_false_positive"):
                fp_count += 1
        return {
            "total": len(items),
            "false_positives": fp_count,
            "by_source": by_source,
            "by_severity": by_severity,
            "grouped_by_type": self.group_by_type(),
        }

    def group_by_type(self) -> Dict[str, Dict[str, Any]]:
        """Regroupe les findings par `attack_type` pour détecter le systémique.

        Exemple concret : 10 alertes « Missing CSP » sur 10 pages d'un même
        site = 1 seul vrai défaut systémique. Sans ce regroupement, le
        rapport remonte 10 items et noie le signal. On expose count +
        severities + urls uniques + un flag `systemic` quand le même type
        touche plus de 3 URLs distinctes.
        """
        items = self.list_all(include_false_positives=False)
        groups: Dict[str, Dict[str, Any]] = {}
        for f in items:
            key = f"{f['source']}:{f['attack_type']}"
            slot = groups.setdefault(key, {
                'attack_type': f['attack_type'],
                'source': f['source'],
                'count': 0,
                'severities': {},
                'urls': set(),
                'fingerprints': [],
            })
            slot['count'] += 1
            slot['severities'][f['severity']] = slot['severities'].get(f['severity'], 0) + 1
            if f.get('url'):
                slot['urls'].add(f['url'])
            slot['fingerprints'].append(f['fingerprint'])
        for key, slot in groups.items():
            slot['urls'] = sorted(slot['urls'])
            slot['systemic'] = len(slot['urls']) > 3
        return groups

    @staticmethod
    def _with_fp_flag(finding: Dict[str, Any]) -> Dict[str, Any]:
        # Le flag `is_false_positive` n'est jamais stocké dans le finding :
        # il est recalculé à la volée depuis `fp_store`. Ça permet à un
        # utilisateur de marquer ou démarquer une alerte sans muter les
        # findings déjà ingérés — et le flag reste cohérent même après un
        # rejeu de scan qui régénérerait le même fingerprint.
        fp_store = _get_fp_store()
        out = dict(finding)
        out["is_false_positive"] = fp_store.is_fp(out.get("raw") or {})
        return out


_singleton: Optional[FindingsStore] = None


def get_store() -> FindingsStore:
    global _singleton
    if _singleton is None:
        _singleton = FindingsStore()
    return _singleton


def reset_for_tests() -> FindingsStore:
    global _singleton
    _singleton = FindingsStore()
    return _singleton
