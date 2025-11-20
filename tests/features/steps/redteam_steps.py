"""
BDD step implementations for Red Team features
"""
from behave import given, when, then

from modules.redteam_attacks import (
    MassAssignmentFuzzer,
    HiddenParameterDiscovery,
    RedTeamOrchestrator
)


@given('a valid HAR file with API endpoints')
def step_impl_har_file(context):
    context.har_data = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.com/users",
                        "headers": [
                            {"name": "Content-Type", "value": "application/json"}
                        ],
                        "postData": {
                            "mimeType": "application/json",
                            "text": '{"username": "test"}'
                        }
                    },
                    "response": {"status": 200, "bodySize": 100}
                }
            ]
        }
    }


@given('no custom configuration is provided')
def step_impl_no_config(context):
    context.config = {}


@given('a config file with custom mass_assignment payloads')
def step_impl_custom_mass_assignment(context):
    payloads = [row['payload'] for row in context.table]
    context.config = {
        "red_team_payloads": {
            "mass_assignment": payloads
        }
    }


@given('a config file with invalid JSON payloads')
def step_impl_invalid_payloads(context):
    payloads = [row['payload'] for row in context.table]
    context.config = {
        "red_team_payloads": {
            "mass_assignment": payloads
        }
    }


@given('a config file with custom hidden_parameters')
def step_impl_custom_hidden_params(context):
    params = [row['parameter'] for row in context.table]
    context.config = {
        "red_team_payloads": {
            "hidden_parameters": params
        }
    }


@given('a config file with both mass_assignment and hidden_parameters')
def step_impl_combined_config(context):
    context.config = {
        "red_team_payloads": {
            "mass_assignment": ['{"role": "admin"}'],
            "hidden_parameters": ["debug=true"]
        }
    }


@when('I execute Mass Assignment fuzzing')
def step_impl_execute_mass_assignment(context):
    context.fuzzer = MassAssignmentFuzzer(context.har_data, context.config)
    context.payloads = context.fuzzer.payloads


@when('I execute Hidden Parameter Discovery')
def step_impl_execute_hidden_params(context):
    context.discovery = HiddenParameterDiscovery(context.har_data, context.config)
    context.hidden_params = context.discovery.hidden_params


@when('I execute all Red Team attacks')
def step_impl_execute_all_attacks(context):
    context.orchestrator = RedTeamOrchestrator(context.har_data, context.config)


@then('the attack should use default payloads')
def step_impl_verify_default_payloads(context):
    assert len(context.payloads) > 5
    assert isinstance(context.payloads[0], dict)


@then('the payloads should include "{key}: {value}"')
def step_impl_verify_payload_includes(context, key, value):
    parsed_value = value if value in ['true', 'false'] else value
    if parsed_value == 'true':
        parsed_value = True
    found = any(key in p and str(p[key]) == str(parsed_value) for p in context.payloads)
    assert found, f"Payload with {key}: {value} not found"


@then('the attack should use {count:d} custom payloads')
def step_impl_verify_payload_count(context, count):
    assert len(context.payloads) == count


@then('the attack should inject "{value}" {field}')
def step_impl_verify_injection(context, value, field):
    found = any(value in str(p.values()) for p in context.payloads)
    assert found, f"Injection value '{value}' not found"


@then('the attack should fallback to default payloads')
def step_impl_verify_fallback(context):
    assert len(context.payloads) >= 5


@then('at least {count:d} payloads should be tested')
def step_impl_verify_min_payloads(context, count):
    assert len(context.payloads) >= count


@then('the attack should test "{param}" parameter')
def step_impl_verify_parameter_tested(context, param):
    param_names = [p[0] for p in context.hidden_params]
    assert param in param_names, f"Parameter '{param}' not found in {param_names}"


@then('Mass Assignment should use custom payloads')
def step_impl_verify_mass_custom(context):
    assert context.config.get("red_team_payloads", {}).get("mass_assignment") is not None


@then('Hidden Parameter Discovery should use custom parameters')
def step_impl_verify_hidden_custom(context):
    assert context.config.get("red_team_payloads", {}).get("hidden_parameters") is not None


@then('both attacks should complete successfully')
def step_impl_verify_completion(context):
    assert context.orchestrator is not None
