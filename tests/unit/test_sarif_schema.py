"""Validate the SARIF output against the SARIF 2.1.0 structural expectations.

We don't ship the full OASIS JSON schema as a dependency (it's large and the
schema itself has known quirks), but we check the properties GitHub Advanced
Security actually requires in practice:

- `$schema` present and points at sarif-schema-2.1.0
- `version` == "2.1.0"
- `runs` is a non-empty list
- Each run has `tool.driver.{name,version,rules}`
- Each result has `ruleId`, `message.text`, `locations` with `physicalLocation`
- `level` in {none, note, warning, error}
- Unique rule IDs (GitHub dedupes per ruleId)
"""
import json
import tempfile
from pathlib import Path

import pytest

from modules.reporter import Reporter


VALID_LEVELS = {"none", "note", "warning", "error"}


@pytest.fixture
def alerts():
    return [
        {"pluginId": 40012, "alert": "SQLi", "url": "https://x/a", "risk": "High",
         "description": "Injection", "evidence": "' OR 1=1"},
        {"pluginId": 40018, "alert": "XSS", "url": "https://x/b", "risk": "Medium",
         "description": "Reflected XSS", "evidence": "<script>"},
        {"pluginId": 40018, "alert": "XSS", "url": "https://x/c", "risk": "Medium",
         "description": "Reflected XSS", "evidence": "<script>"},
        {"pluginId": 10010, "alert": "Cookie No HttpOnly", "url": "https://x/",
         "risk": "Low", "description": "Cookie flag", "evidence": ""},
    ]


class TestSarifSchema:
    def _load_sarif(self, alerts):
        with tempfile.TemporaryDirectory() as tmp:
            rep = Reporter(output_dir=tmp)
            path = rep.save_sarif_report(alerts)
            return json.loads(Path(path).read_text())

    def test_top_level_fields(self, alerts):
        sarif = self._load_sarif(alerts)
        assert sarif["version"] == "2.1.0"
        assert "sarif-schema-2.1.0" in sarif["$schema"]
        assert isinstance(sarif["runs"], list)
        assert len(sarif["runs"]) >= 1

    def test_tool_driver_has_required_fields(self, alerts):
        run = self._load_sarif(alerts)["runs"][0]
        driver = run["tool"]["driver"]
        assert driver["name"]
        assert driver["version"]
        assert isinstance(driver["rules"], list)

    def test_rule_ids_are_unique(self, alerts):
        run = self._load_sarif(alerts)["runs"][0]
        rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
        assert len(rule_ids) == len(set(rule_ids)), f"duplicate rule ids: {rule_ids}"

    def test_each_rule_has_required_shape(self, alerts):
        run = self._load_sarif(alerts)["runs"][0]
        for rule in run["tool"]["driver"]["rules"]:
            assert rule.get("id")
            assert rule.get("name")
            assert "shortDescription" in rule
            assert "text" in rule["shortDescription"]

    def test_each_result_has_required_shape(self, alerts):
        run = self._load_sarif(alerts)["runs"][0]
        for result in run["results"]:
            assert result.get("ruleId")
            assert "message" in result and "text" in result["message"]
            assert result.get("level") in VALID_LEVELS
            assert "locations" in result and result["locations"]
            loc = result["locations"][0]
            assert "physicalLocation" in loc
            assert "artifactLocation" in loc["physicalLocation"]
            assert "uri" in loc["physicalLocation"]["artifactLocation"]

    def test_results_reference_declared_rules(self, alerts):
        run = self._load_sarif(alerts)["runs"][0]
        declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
        for result in run["results"]:
            assert result["ruleId"] in declared, (
                f"result references undeclared ruleId {result['ruleId']}"
            )

    def test_empty_alerts_produces_valid_empty_sarif(self):
        sarif = self._load_sarif([])
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []
