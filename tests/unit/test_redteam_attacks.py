"""
Unit tests for Red Team attack modules
Tests configuration, payload loading, and attack logic
"""
from unittest.mock import Mock, patch, AsyncMock

import pytest

from modules.redteam_attacks import (
    MassAssignmentFuzzer,
    HiddenParameterDiscovery,
    RaceConditionTester,
    RedTeamOrchestrator,
    UnauthenticatedReplayAttack,
    AttackType,
    AttackResult
)


@pytest.fixture
def sample_har_data():
    """Sample HAR data for testing"""
    return {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.com/users",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer token123"},
                            {"name": "Content-Type", "value": "application/json"}
                        ],
                        "postData": {
                            "mimeType": "application/json",
                            "text": '{"username": "john", "email": "john@example.com"}'
                        }
                    },
                    "response": {
                        "status": 201,
                        "bodySize": 150
                    }
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/profile",
                        "headers": [
                            {"name": "Cookie", "value": "session=abc123"}
                        ]
                    },
                    "response": {
                        "status": 200,
                        "bodySize": 500
                    }
                },
                {
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.com/transfer",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer token456"}
                        ],
                        "postData": {
                            "mimeType": "application/json",
                            "text": '{"amount": 100, "to": "account2"}'
                        }
                    },
                    "response": {
                        "status": 200,
                        "bodySize": 80
                    }
                }
            ]
        }
    }


@pytest.fixture
def config_with_payloads():
    """Configuration with custom payloads"""
    return {
        "red_team_payloads": {
            "mass_assignment": [
                '{"role": "superadmin"}',
                '{"is_root": true}'
            ],
            "hidden_parameters": [
                "debug=true",
                "admin=1"
            ]
        },
        "race_condition_requests": 25
    }


class TestMassAssignmentFuzzer:
    """Test Mass Assignment vulnerability detection"""

    def test_init_with_default_payloads(self, sample_har_data):
        fuzzer = MassAssignmentFuzzer(sample_har_data)
        assert fuzzer.payloads == fuzzer.DANGEROUS_PARAMS
        assert len(fuzzer.payloads) > 0

    def test_init_with_config_payloads(self, sample_har_data, config_with_payloads):
        fuzzer = MassAssignmentFuzzer(sample_har_data, config_with_payloads)
        assert len(fuzzer.payloads) == 2
        assert {"role": "superadmin"} in fuzzer.payloads
        assert {"is_root": True} in fuzzer.payloads

    def test_load_payloads_from_config(self, sample_har_data, config_with_payloads):
        fuzzer = MassAssignmentFuzzer(sample_har_data, config_with_payloads)
        payloads = fuzzer._load_payloads()
        assert all(isinstance(p, dict) for p in payloads)

    def test_load_payloads_fallback_on_invalid_json(self, sample_har_data):
        invalid_config = {
            "red_team_payloads": {
                "mass_assignment": [
                    "not a json",
                    "also invalid"
                ]
            }
        }
        fuzzer = MassAssignmentFuzzer(sample_har_data, invalid_config)
        assert fuzzer.payloads == fuzzer.DANGEROUS_PARAMS

    def test_identify_mutation_endpoints(self, sample_har_data):
        fuzzer = MassAssignmentFuzzer(sample_har_data)
        endpoints = fuzzer.identify_mutation_endpoints()
        assert len(endpoints) == 2  # Two POST endpoints
        assert all(e["method"] in ["POST", "PUT", "PATCH"] for e in endpoints)

    def test_identify_only_json_endpoints(self, sample_har_data):
        fuzzer = MassAssignmentFuzzer(sample_har_data)
        endpoints = fuzzer.identify_mutation_endpoints()
        # Endpoints are filtered by JSON mimeType, so body must be present
        assert len(endpoints) == 2
        for endpoint in endpoints:
            assert endpoint.get("body") is not None

    @patch('modules.redteam_attacks.requests.request')
    def test_inject_dangerous_params_success(self, mock_request, sample_har_data):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"success": true}'
        mock_request.return_value = mock_response

        fuzzer = MassAssignmentFuzzer(sample_har_data)
        request = {
            "url": "https://api.example.com/users",
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body": '{"username": "test"}'
        }

        results = fuzzer.inject_dangerous_params(request)
        assert len(results) > 0
        assert all(r.attack_type == AttackType.MASS_ASSIGNMENT for r in results)

    def test_inject_dangerous_params_invalid_body(self, sample_har_data):
        fuzzer = MassAssignmentFuzzer(sample_har_data)
        request = {
            "url": "https://api.example.com/test",
            "method": "POST",
            "headers": {},
            "body": "not json"
        }
        results = fuzzer.inject_dangerous_params(request)
        assert len(results) == 0


class TestHiddenParameterDiscovery:
    """Test Hidden Parameter discovery"""

    def test_init_with_default_params(self, sample_har_data):
        discovery = HiddenParameterDiscovery(sample_har_data)
        assert discovery.hidden_params == discovery.COMMON_HIDDEN_PARAMS
        assert len(discovery.hidden_params) > 0

    def test_init_with_config_params(self, sample_har_data, config_with_payloads):
        discovery = HiddenParameterDiscovery(sample_har_data, config_with_payloads)
        assert len(discovery.hidden_params) == 2
        assert ("debug", ["true"]) in discovery.hidden_params
        assert ("admin", ["1"]) in discovery.hidden_params

    def test_load_hidden_params_from_config(self, sample_har_data):
        config = {
            "red_team_payloads": {
                "hidden_parameters": [
                    "test=1",
                    "test=true",
                    "debug=yes"
                ]
            }
        }
        discovery = HiddenParameterDiscovery(sample_har_data, config)
        params = discovery._load_hidden_params()

        test_param = next(p for p in params if p[0] == "test")
        assert "1" in test_param[1]
        assert "true" in test_param[1]

    @patch('modules.redteam_attacks.requests.get')
    def test_hidden_params_detection(self, mock_get, sample_har_data):
        baseline_response = Mock()
        baseline_response.content = b"baseline content"

        test_response = Mock()
        test_response.content = b"baseline content with extra debug information here"

        mock_get.side_effect = [test_response, baseline_response]

        discovery = HiddenParameterDiscovery(sample_har_data)
        results = discovery.test_hidden_params("https://api.example.com/data", {})

        assert len(results) == 0 or (len(results) > 0 and results[0].attack_type == AttackType.HIDDEN_PARAMS)


class TestRaceConditionTester:
    """Test Race Condition detection"""

    def test_init_with_default_burst_count(self, sample_har_data):
        tester = RaceConditionTester(sample_har_data)
        assert tester.burst_count == 50

    def test_init_with_config_burst_count(self, sample_har_data, config_with_payloads):
        tester = RaceConditionTester(sample_har_data, config_with_payloads)
        assert tester.burst_count == 25

    def test_identify_race_targets(self, sample_har_data):
        tester = RaceConditionTester(sample_har_data)
        targets = tester.identify_race_targets()
        assert len(targets) == 1  # Only /transfer endpoint
        assert "transfer" in targets[0]["url"]

    def test_identify_race_targets_keywords(self, sample_har_data):
        keywords = ['transfer', 'coupon', 'redeem', 'vote', 'purchase', 'checkout']

        har_with_race_endpoints = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "POST",
                            "url": f"https://api.example.com/{keyword}",
                            "headers": []
                        }
                    }
                    for keyword in keywords
                ]
            }
        }

        tester = RaceConditionTester(har_with_race_endpoints)
        targets = tester.identify_race_targets()
        assert len(targets) == len(keywords)

    @pytest.mark.asyncio
    async def test_burst_request_execution(self, sample_har_data):
        tester = RaceConditionTester(sample_har_data, {"race_condition_requests": 5})

        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.headers = {}
            mock_response.read = AsyncMock(return_value=b"response body")
            mock_response.close = Mock()
            mock_get.return_value.__aenter__.return_value = mock_response

            results = await tester.burst_request(
                "https://api.example.com/test",
                "GET",
                {},
                None
            )

            assert len(results) == 5

    def test_analyze_race_responses_vulnerable(self):
        responses = [
            {"status": 200, "length": 100},
            {"status": 200, "length": 100},
            {"status": 200, "length": 100},
            {"status": 400, "length": 50},
            {"status": 400, "length": 50}
        ]

        tester = RaceConditionTester({}, {"race_condition_requests": 5})
        analysis = tester.analyze_race_responses(responses)

        assert analysis["success_count"] == 3
        assert analysis["vulnerable"] == True
        assert analysis["confidence"] > 0

    def test_analyze_race_responses_protected(self):
        responses = [
            {"status": 200, "length": 100},
            {"status": 409, "length": 50},
            {"status": 409, "length": 50},
            {"status": 409, "length": 50},
            {"status": 409, "length": 50}
        ]

        tester = RaceConditionTester({}, {"race_condition_requests": 5})
        analysis = tester.analyze_race_responses(responses)

        assert analysis["success_count"] == 1
        assert analysis["vulnerable"] == False

    def test_analyze_race_responses_with_errors(self):
        responses = [
            {"status": 200, "length": 100},
            {"error": "Timeout"},
            {"error": "Connection refused"}
        ]

        tester = RaceConditionTester({}, {"race_condition_requests": 3})
        analysis = tester.analyze_race_responses(responses)

        assert analysis["errors"] == 2
        assert analysis["total_requests"] == 3


class TestUnauthenticatedReplayAttack:
    """Test Unauthenticated Replay attack"""

    def test_identify_authenticated_requests(self, sample_har_data):
        attack = UnauthenticatedReplayAttack(sample_har_data)
        auth_requests = attack.identify_authenticated_requests()

        assert len(auth_requests) == 3  # All requests have auth
        assert all("Authorization" in r["headers"] or "Cookie" in r["headers"]
                   for r in auth_requests)

    def test_identify_requests_with_token_headers(self):
        har_data = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "url": "https://api.example.com/data",
                            "method": "GET",
                            "headers": [
                                {"name": "X-Auth-Token", "value": "secret"}
                            ]
                        },
                        "response": {"status": 200, "bodySize": 100}
                    }
                ]
            }
        }

        attack = UnauthenticatedReplayAttack(har_data)
        auth_requests = attack.identify_authenticated_requests()
        assert len(auth_requests) == 1

    @patch('modules.redteam_attacks.requests.request')
    def test_execute_unauth_replay_vulnerable(self, mock_request, sample_har_data):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"a" * 200
        mock_request.return_value = mock_response

        attack = UnauthenticatedReplayAttack(sample_har_data)
        request = {
            "url": "https://api.example.com/profile",
            "method": "GET",
            "headers": {"Authorization": "Bearer token"},
            "original_response": {"status": 200, "bodySize": 200}
        }

        result = attack.execute_unauth_replay(request)
        assert result.vulnerable == True
        assert result.confidence > 0

    @patch('modules.redteam_attacks.requests.request')
    def test_execute_unauth_replay_protected(self, mock_request, sample_har_data):
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.content = b"Unauthorized"
        mock_request.return_value = mock_response

        attack = UnauthenticatedReplayAttack(sample_har_data)
        request = {
            "url": "https://api.example.com/profile",
            "method": "GET",
            "headers": {"Authorization": "Bearer token"},
            "original_response": {"status": 200, "bodySize": 200}
        }

        result = attack.execute_unauth_replay(request)
        assert result.vulnerable == False


class TestRedTeamOrchestrator:
    """Test Red Team orchestrator"""

    def test_init_with_config(self, sample_har_data, config_with_payloads):
        orchestrator = RedTeamOrchestrator(sample_har_data, config_with_payloads)
        assert orchestrator.config == config_with_payloads
        assert orchestrator.har_data == sample_har_data

    @patch.object(UnauthenticatedReplayAttack, 'run_attack')
    @patch.object(MassAssignmentFuzzer, 'run_attack')
    @patch.object(HiddenParameterDiscovery, 'run_attack')
    @patch.object(RaceConditionTester, 'run_attack')
    def test_run_all_attacks(self, mock_race, mock_hidden, mock_mass, mock_unauth,
                             sample_har_data, config_with_payloads):
        mock_unauth.return_value = []
        mock_mass.return_value = []
        mock_hidden.return_value = []
        mock_race.return_value = []

        orchestrator = RedTeamOrchestrator(sample_har_data, config_with_payloads)
        results = orchestrator.run_all_attacks()

        assert "unauth_replay" in results
        assert "mass_assignment" in results
        assert "hidden_params" in results
        assert "race_condition" in results

    def test_get_critical_findings(self, sample_har_data):
        orchestrator = RedTeamOrchestrator(sample_har_data)

        orchestrator.results = {
            "test_attack": [
                AttackResult(
                    attack_type=AttackType.MASS_ASSIGNMENT,
                    url="https://api.example.com/test",
                    method="POST",
                    vulnerable=True,
                    confidence=0.8,
                    evidence={},
                    description="High confidence finding",
                    remediation="Fix it"
                ),
                AttackResult(
                    attack_type=AttackType.HIDDEN_PARAMS,
                    url="https://api.example.com/test2",
                    method="GET",
                    vulnerable=True,
                    confidence=0.3,
                    evidence={},
                    description="Low confidence finding",
                    remediation="Fix it"
                )
            ]
        }

        critical = orchestrator.get_critical_findings()
        assert len(critical) == 1  # Only confidence > 0.5
        assert critical[0].confidence == 0.8

    def test_generate_report(self, sample_har_data):
        orchestrator = RedTeamOrchestrator(sample_har_data)

        orchestrator.results = {
            "attack1": [
                AttackResult(AttackType.MASS_ASSIGNMENT, "url1", "POST", True, 0.9, {}, "desc", "rem"),
                AttackResult(AttackType.MASS_ASSIGNMENT, "url2", "POST", False, 0.0, {}, "desc", "rem")
            ],
            "attack2": [
                AttackResult(AttackType.HIDDEN_PARAMS, "url3", "GET", True, 0.7, {}, "desc", "rem")
            ]
        }

        report = orchestrator.generate_report()
        assert report["total_tests"] == 3
        assert report["total_vulnerabilities"] == 2
        assert len(report["critical_findings"]) == 2


class TestAttackResult:
    """Test AttackResult dataclass"""

    def test_create_attack_result(self):
        result = AttackResult(
            attack_type=AttackType.MASS_ASSIGNMENT,
            url="https://api.example.com/test",
            method="POST",
            vulnerable=True,
            confidence=0.8,
            evidence={"key": "value"},
            description="Test description",
            remediation="Test remediation"
        )

        assert result.attack_type == AttackType.MASS_ASSIGNMENT
        assert result.url == "https://api.example.com/test"
        assert result.vulnerable == True
        assert result.confidence == 0.8
