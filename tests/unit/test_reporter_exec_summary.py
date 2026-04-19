"""Tests for the executive-summary HTML wiring in Reporter.save_html_report."""
from unittest.mock import MagicMock

from modules.reporter import Reporter


def _alert(risk="High", name="SQL Injection", url="https://x/a", plugin_id="40018"):
    return {
        "risk": risk,
        "alert": name,
        "url": url,
        "pluginId": plugin_id,
        "description": "desc",
    }


class TestExecSummaryHtml:
    def test_renders_block_for_no_alerts(self, tmp_path):
        rep = Reporter(output_dir=str(tmp_path))
        out = rep.save_html_report(zap_client=None, alerts=[])
        assert out is not None
        html = open(out).read()
        assert "Executive Summary" in html
        assert "LOW" in html or "risk_level" in html.lower() or "No critical" in html

    def test_block_prepended_to_zap_html(self, tmp_path):
        zap = MagicMock()
        zap.core.htmlreport.return_value = "<html><head></head><body><h1>ZAP Report</h1></body></html>"
        rep = Reporter(output_dir=str(tmp_path))
        alerts = [_alert(risk="High", name="SQLi")]
        out = rep.save_html_report(zap_client=zap, alerts=alerts)
        assert out is not None
        html = open(out).read()
        # Summary must appear between <body> and the existing <h1>
        body_idx = html.find("<body")
        end_body = html.find(">", body_idx) + 1
        h1_idx = html.find("<h1>ZAP Report")
        assert end_body < html.find("Executive Summary") < h1_idx

    def test_top_issues_rendered(self, tmp_path):
        rep = Reporter(output_dir=str(tmp_path))
        alerts = [_alert(name="XSS"), _alert(name="XSS"), _alert(name="SQLi")]
        out = rep.save_html_report(zap_client=None, alerts=alerts)
        html = open(out).read()
        # XSS should appear once with count 2
        assert "XSS" in html
        assert "2 occurrence" in html

    def test_risk_level_critical_for_high_findings(self, tmp_path):
        rep = Reporter(output_dir=str(tmp_path))
        alerts = [_alert(risk="High")]
        out = rep.save_html_report(zap_client=None, alerts=alerts)
        html = open(out).read()
        assert "CRITICAL" in html

    def test_immediate_actions_mention_high_count(self, tmp_path):
        rep = Reporter(output_dir=str(tmp_path))
        alerts = [_alert(risk="High"), _alert(risk="High")]
        out = rep.save_html_report(zap_client=None, alerts=alerts)
        html = open(out).read()
        assert "2 high-severity" in html

    def test_zap_failure_returns_none_without_alerts(self, tmp_path):
        zap = MagicMock()
        zap.core.htmlreport.side_effect = Exception("boom")
        rep = Reporter(output_dir=str(tmp_path))
        out = rep.save_html_report(zap_client=zap)
        assert out is None

    def test_save_all_reports_emits_html_even_without_zap(self, tmp_path):
        rep = Reporter(output_dir=str(tmp_path))
        saved = rep.save_all_reports([_alert()], formats=["html"])
        assert "html" in saved
