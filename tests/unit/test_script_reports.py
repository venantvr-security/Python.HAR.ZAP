"""Tests for script_reports module."""
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from modules.script_reports import (
    ScriptReport,
    _parse_output,
    collect_reports,
    summary,
)


class TestParseOutput:
    def test_empty_returns_empty_list(self):
        assert _parse_output(None) == []
        assert _parse_output("") == []

    def test_plain_text_lines(self):
        out = _parse_output("line1\nline2")
        assert out == [{"message": "line1"}, {"message": "line2"}]

    def test_json_lines(self):
        raw = '{"alert":"XSS","url":"/x"}\n{"alert":"SQLi"}'
        out = _parse_output(raw)
        assert out[0]["alert"] == "XSS"
        assert out[1]["alert"] == "SQLi"

    def test_mixed_json_and_text(self):
        raw = '{"a":1}\nplain text'
        out = _parse_output(raw)
        assert out[0] == {"a": 1}
        assert out[1] == {"message": "plain text"}


class TestCollectReports:
    def test_collects_from_disk_and_zap(self, tmp_path):
        (tmp_path / "active").mkdir()
        (tmp_path / "passive").mkdir()
        (tmp_path / "active" / "jwt_scanner.js").write_text("// test")
        (tmp_path / "passive" / "info_leak.js").write_text("// test")

        zap = MagicMock()
        zap.script.list_scripts = [
            {"name": "jwt_scanner", "enabled": "true", "error": "false"},
            {"name": "info_leak", "enabled": "true", "error": "false"},
        ]
        zap.script.script_var.return_value = '{"alert":"found"}'

        reports = collect_reports(zap, scripts_dir=tmp_path)
        assert len(reports) == 2
        assert {r.name for r in reports} == {"jwt_scanner", "info_leak"}
        jwt = next(r for r in reports if r.name == "jwt_scanner")
        assert jwt.enabled is True
        assert jwt.findings and jwt.findings[0]["alert"] == "found"

    def test_errored_script_flagged(self, tmp_path):
        (tmp_path / "active").mkdir()
        (tmp_path / "active" / "broken.js").write_text("// test")

        zap = MagicMock()
        zap.script.list_scripts = [
            {"name": "broken", "enabled": "false", "error": "true", "errorDetails": "syntax error"},
        ]
        zap.script.script_var.return_value = None

        reports = collect_reports(zap, scripts_dir=tmp_path)
        assert len(reports) == 1
        assert reports[0].has_error is True
        assert reports[0].error_message == "syntax error"

    def test_missing_scripts_dir(self, tmp_path):
        zap = MagicMock()
        reports = collect_reports(zap, scripts_dir=tmp_path / "does-not-exist")
        assert reports == []

    def test_script_var_exception_returns_none(self, tmp_path):
        (tmp_path / "active").mkdir()
        (tmp_path / "active" / "x.js").write_text("// test")
        zap = MagicMock()
        zap.script.list_scripts = []
        zap.script.script_var.side_effect = Exception("ZAP down")

        reports = collect_reports(zap, scripts_dir=tmp_path)
        assert reports[0].raw_output is None
        assert reports[0].findings == []

    def test_to_dict_shape(self):
        r = ScriptReport(name="n", script_type="active", enabled=True, findings=[{"a": 1}])
        d = r.to_dict()
        assert d["finding_count"] == 1
        assert d["name"] == "n"

    def test_summary_counts(self):
        reports = [
            ScriptReport(name="a", script_type="active", enabled=True, findings=[{"a": 1}]),
            ScriptReport(name="b", script_type="active", enabled=False),
            ScriptReport(name="c", script_type="passive", enabled=True, has_error=True),
        ]
        s = summary(reports)
        assert s["total"] == 3
        assert s["enabled"] == 2
        assert s["errored"] == 1
        assert s["with_findings"] == 1
        assert s["total_findings"] == 1
