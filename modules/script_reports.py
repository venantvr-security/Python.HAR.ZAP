"""
Script reports — collect the outputs of ZAP JavaScript scripts after a scan.

The existing `script_manager` loads and enables scripts but never reads back
what they wrote to `scriptVars`. Without this, the pentester has no idea
whether a script tested anything, found anything, or even ran.

This module queries ZAP after the scan for each loaded script and packages
the output into a uniform dict per script, ready for UI rendering.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from zapv2 import ZAPv2


@dataclass
class ScriptReport:
    name: str
    script_type: str                    # active | passive
    enabled: bool
    has_error: bool = False
    error_message: Optional[str] = None
    raw_output: Optional[str] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.script_type,
            "enabled": self.enabled,
            "has_error": self.has_error,
            "error_message": self.error_message,
            "raw_output": self.raw_output,
            "findings": self.findings,
            "finding_count": len(self.findings),
        }


def _parse_output(raw: Optional[str]) -> List[Dict[str, Any]]:
    """Scripts may emit structured JSON lines or plain text — try JSON first.

    Les scripts ZAP écrivent dans `scriptVars.output` via `print()` ou
    `script.setScriptVar()`. Certains auteurs émettent du JSON ligne-par-ligne
    (idéal pour l'UI structurée), d'autres du texte libre. On tente JSON
    d'abord, on retombe en `{"message": line}` sinon — comme ça la boîte noire
    devient au pire une liste de messages horodatables, jamais un mur de
    texte opaque.
    """
    if not raw:
        return []
    findings: List[Dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                findings.append(obj)
                continue
        except json.JSONDecodeError:
            pass
        findings.append({"message": line})
    return findings


def collect_reports(zap: ZAPv2, scripts_dir: Optional[Path] = None) -> List[ScriptReport]:
    """Iterate over active+passive scripts on disk and retrieve their ZAP output."""
    if scripts_dir is None:
        scripts_dir = Path(__file__).parent.parent / "scripts"

    reports: List[ScriptReport] = []
    listed = _list_zap_scripts(zap)

    for script_type in ("active", "passive"):
        type_dir = scripts_dir / script_type
        if not type_dir.exists():
            continue
        for script_file in type_dir.glob("*.js"):
            name = script_file.stem
            info = listed.get(name, {})
            raw = _script_var(zap, name, "output")
            err_flag = bool(info.get("error"))
            err_msg = info.get("error_message") if err_flag else None
            reports.append(ScriptReport(
                name=name,
                script_type=script_type,
                enabled=info.get("enabled", False),
                has_error=err_flag,
                error_message=err_msg,
                raw_output=raw,
                findings=_parse_output(raw),
            ))
    return reports


def _list_zap_scripts(zap: ZAPv2) -> Dict[str, Dict[str, Any]]:
    """Map script_name → metadata from ZAP (engine, enabled, error, ...)."""
    try:
        listed = zap.script.list_scripts or []
    except Exception:
        return {}
    result: Dict[str, Dict[str, Any]] = {}
    for entry in listed:
        name = entry.get("name")
        if not name:
            continue
        result[name] = {
            "engine": entry.get("engine"),
            "enabled": entry.get("enabled") == "true",
            "error": entry.get("error") == "true",
            "error_message": entry.get("errorDetails") or entry.get("lastErrorDetails"),
        }
    return result


def _script_var(zap: ZAPv2, script_name: str, var_key: str) -> Optional[str]:
    try:
        return zap.script.script_var(scriptname=script_name, varkey=var_key)
    except Exception:
        return None


def summary(reports: List[ScriptReport]) -> Dict[str, int]:
    """One-liner stats for the UI header."""
    return {
        "total": len(reports),
        "enabled": sum(1 for r in reports if r.enabled),
        "errored": sum(1 for r in reports if r.has_error),
        "with_findings": sum(1 for r in reports if r.findings),
        "total_findings": sum(len(r.findings) for r in reports),
    }
