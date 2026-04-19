"""Tests for modules/ui_advanced — the dispatcher for advanced attacks."""
from dataclasses import dataclass
from unittest.mock import MagicMock, patch

import pytest

from modules import ui_advanced


@dataclass
class FakeResult:
    url: str = "https://x/a"
    vulnerable: bool = False
    attack_type: str = "demo"


class TestVerdict:
    def test_no_targets(self):
        assert ui_advanced._verdict(0, 0) == "NO_TARGETS"

    def test_not_vulnerable(self):
        assert ui_advanced._verdict(5, 0) == "NOT_VULNERABLE"

    def test_vulnerable_all(self):
        assert ui_advanced._verdict(3, 3) == "VULNERABLE"

    def test_partial(self):
        assert ui_advanced._verdict(5, 2) == "PARTIAL"


class TestVerdictColor:
    def test_vulnerable_is_inverse(self):
        assert ui_advanced.verdict_color("VULNERABLE") == "inverse"

    def test_safe_is_off(self):
        assert ui_advanced.verdict_color("NOT_VULNERABLE") == "off"

    def test_unknown_is_off(self):
        assert ui_advanced.verdict_color("WHATEVER") == "off"


class TestToDict:
    def test_dataclass_is_asdicted(self):
        r = FakeResult(vulnerable=True)
        d = ui_advanced._to_dict(r)
        assert d["vulnerable"] is True
        assert d["attack_type"] == "demo"

    def test_dict_passthrough(self):
        d = ui_advanced._to_dict({"a": 1})
        assert d == {"a": 1}

    def test_fallback_to_str(self):
        d = ui_advanced._to_dict(42)
        assert d == {"value": "42"}


class TestRunners:
    """Each runner should call its module, normalise output, compute verdict."""

    def test_run_jwt(self):
        with patch("modules.jwt_attacks.JWTAttackTester") as MockTester:
            instance = MagicMock()
            instance.run_tests.return_value = [FakeResult(vulnerable=True)]
            MockTester.return_value = instance

            result = ui_advanced.run_jwt({"log": {"entries": []}})
            assert result["attack"] == "jwt"
            assert result["verdict"] == "VULNERABLE"
            assert len(result["findings"]) == 1
            assert result["findings"][0]["vulnerable"] is True

    def test_run_cors(self):
        with patch("modules.cors_tester.CORSTester") as MockTester:
            MockTester.return_value.run_tests.return_value = []
            result = ui_advanced.run_cors({"log": {"entries": []}})
            assert result["attack"] == "cors"
            assert result["verdict"] == "NO_TARGETS"

    def test_run_cache_poisoning(self):
        with patch("modules.cache_poisoning.CachePoisoningTester") as MockTester:
            MockTester.return_value.run_tests.return_value = [
                FakeResult(vulnerable=False), FakeResult(vulnerable=True),
            ]
            result = ui_advanced.run_cache_poisoning({"log": {"entries": []}})
            assert result["attack"] == "cache_poisoning"
            assert result["verdict"] == "PARTIAL"

    def test_run_http_smuggling_counts_variants(self):
        with patch("modules.http_smuggling.HTTPSmugglingTester") as MockTester:
            MockTester.return_value.run_tests.return_value = [
                {"url": "u1", "variant": "CL.TE", "vulnerable": False},
                {"url": "u2", "variant": "TE.CL", "vulnerable": True},
            ]
            result = ui_advanced.run_http_smuggling({"log": {"entries": []}})
            assert set(result["variants"]) == {"CL.TE", "TE.CL"}
            assert result["verdict"] == "PARTIAL"

    def test_run_timing_counts_verdicts(self):
        with patch("modules.timing_analysis.TimingAnalyzer") as MockAnalyzer:
            MockAnalyzer.return_value.run_tests.return_value = [
                {"verdict": "LIKELY_VULNERABLE", "vulnerable": True},
                {"verdict": "INCONCLUSIVE", "vulnerable": False},
                {"verdict": "NOT_VULNERABLE", "vulnerable": False},
            ]
            result = ui_advanced.run_timing({"log": {"entries": []}})
            assert "1 likely vulnerable" in result["summary"]
            assert "1 inconclusive" in result["summary"]
            assert result["verdict"] in ("VULNERABLE", "PARTIAL")

    def test_run_graphql_sync_wrapper(self):
        with patch("modules.graphql_scanner.GraphQLScanner") as MockScanner:
            instance = MagicMock()
            instance.scan_all_sync.return_value = {
                "endpoints": [{"url": "/graphql"}],
                "vulnerabilities": [{"type": "introspection"}],
            }
            MockScanner.return_value = instance
            result = ui_advanced.run_graphql({"log": {"entries": []}})
            assert result["attack"] == "graphql"
            assert len(result["endpoints"]) == 1
            assert len(result["findings"]) == 1

    def test_run_websocket_no_sync_wrapper_falls_back_to_async(self):
        import asyncio

        async def fake_scan_all():
            return {"endpoints": [], "vulnerabilities": []}

        with patch("modules.websocket_scanner.WebSocketScanner") as MockScanner:
            instance = MagicMock(spec=["scan_all"])
            instance.scan_all = fake_scan_all
            MockScanner.return_value = instance
            result = ui_advanced.run_websocket({"log": {"entries": []}})
            assert result["attack"] == "websocket"
            assert result["verdict"] == "NO_TARGETS"


class TestDispatch:
    def test_unknown_key_raises(self):
        with pytest.raises(KeyError):
            ui_advanced.run("not-a-real-attack", {})

    def test_all_keys_have_runners(self):
        for key in ui_advanced.ADVANCED_ATTACKS:
            assert key in ui_advanced.RUNNERS

    def test_all_keys_have_labels(self):
        for key in ui_advanced.ADVANCED_ATTACKS:
            assert key in ui_advanced.ATTACK_LABELS

    def test_dispatch_calls_correct_runner(self):
        fake = MagicMock(return_value={"attack": "cors", "findings": [], "verdict": "NO_TARGETS"})
        with patch.dict(ui_advanced.RUNNERS, {"cors": fake}, clear=False):
            ui_advanced.run("cors", {"log": {"entries": []}})
        fake.assert_called_once()
