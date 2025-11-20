"""
BDD step implementations for Secrets Masking
"""
import json

from behave import given, when, then

from modules.utils.masking import (
    mask_sensitive_data,
    mask_string,
    mask_dict,
    mask_url,
    mask_har_entry
)


@given('the masking module is loaded')
def step_impl_module_loaded(context):
    context.masking_available = True


@given('a security report containing JWT tokens')
def step_impl_report_with_jwt(context):
    context.report_data = {
        "alerts": [
            {
                "url": "https://api.example.com/data",
                "evidence": "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.abc123"
            }
        ]
    }


@given('a HAR file with Authorization headers')
def step_impl_har_with_auth(context):
    context.har_entry = {
        "request": {
            "url": "https://api.example.com/data",
            "headers": [
                {"name": "Authorization", "value": "Bearer secret123"},
                {"name": "Cookie", "value": "session=abc123"}
            ]
        }
    }


@given('an alert with AWS API keys in the description')
def step_impl_alert_with_aws_key(context):
    context.alert = {
        "alert": "Exposed API Key",
        "description": "Found AWS key AKIAIOSFODNN7EXAMPLE in response"
    }


@given('a vulnerable endpoint with token in query string')
def step_impl_endpoint_with_token(context):
    context.url = context.text.strip()


@given('a POST request body')
def step_impl_post_body(context):
    context.request_body = context.text.strip()


@given('a HAR entry with session cookies')
def step_impl_har_with_cookies(context):
    context.har_entry = {
        "request": {
            "cookies": [
                {"name": "session", "value": "abc123def456"},
                {"name": "token", "value": "xyz789"}
            ]
        }
    }


@given('an alert description containing "{email}"')
def step_impl_alert_with_email(context, email):
    context.alert = {
        "description": f"User {email} attempted unauthorized access"
    }


@given('response content with "{cc_number}"')
def step_impl_response_with_cc(context, cc_number):
    context.response_content = f"Payment processed with card {cc_number}"


@given('a report with non-sensitive data')
def step_impl_non_sensitive_data(context):
    context.data = {row['field']: row['value'] for row in context.table}


@given('a nested data structure')
def step_impl_nested_structure(context):
    context.nested_data = json.loads(context.text.strip())


@given('a ZAP HTML report with sensitive data')
def step_impl_zap_html_report(context):
    context.html_content = """
    <html>
    <body>
        <div>Token: eyJhbGciOiJIUzI1NiJ9.abc.def</div>
        <div>API Key: AKIAIOSFODNN7EXAMPLE</div>
    </body>
    </html>
    """


@given('an alert with "{stripe_key}"')
def step_impl_alert_with_stripe(context, stripe_key):
    context.alert = {
        "evidence": f"Stripe key found: {stripe_key}"
    }


@given('a custom masking placeholder "{placeholder}"')
def step_impl_custom_placeholder(context, placeholder):
    context.placeholder = placeholder


@given('a Red Team attack on "{url}"')
def step_impl_redteam_attack_url(context, url):
    context.attack_url = url


@given('{count:d} high-severity alerts with tokens in URLs')
def step_impl_high_severity_alerts(context, count):
    context.alerts = [
        {
            "risk": "High",
            "url": f"https://api.example.com/endpoint{i}?token=secret{i}",
            "alert": f"Vulnerability {i}"
        }
        for i in range(count)
    ]


@when('I generate the JSON report')
def step_impl_generate_json_report(context):
    context.masked_report = mask_sensitive_data(context.report_data)


@when('I generate a report')
def step_impl_generate_report(context):
    context.masked_entry = mask_har_entry(context.har_entry)


@when('I print the alert to console')
def step_impl_print_alert(context):
    context.console_output = mask_string(context.alert["description"])


@when('I log the URL')
def step_impl_log_url(context):
    context.masked_url = mask_url(context.url)


@when('I generate a report including this request')
def step_impl_report_with_request(context):
    context.masked_body = mask_string(context.request_body)


@when('I process the HAR entry for reporting')
def step_impl_process_har_entry(context):
    context.processed_entry = mask_har_entry(context.har_entry)


@when('I save the alert to a text report')
def step_impl_save_text_report(context):
    context.saved_text = mask_string(context.alert["description"])


@when('I include the response in a report')
def step_impl_include_response(context):
    context.masked_content = mask_string(context.response_content)


@when('I apply masking')
def step_impl_apply_masking(context):
    if hasattr(context, 'nested_data'):
        context.masked_result = mask_dict(context.nested_data)
    else:
        context.masked_result = mask_dict(context.data)


@when('I save the HTML report')
def step_impl_save_html_report(context):
    context.masked_html = mask_string(context.html_content)


@when('I mask sensitive data')
def step_impl_mask_with_placeholder(context):
    context.masked_result = mask_string("Bearer token123", placeholder=context.placeholder)


@when('the attack logs progress')
def step_impl_attack_logs(context):
    context.logged_url = mask_url(context.attack_url)


@when('I save the critical findings report')
def step_impl_save_critical_findings(context):
    context.masked_alerts = [mask_sensitive_data(a) for a in context.alerts]


@then('all JWT tokens should be replaced with "[MASKED]"')
def step_impl_verify_jwt_masked(context):
    report_str = json.dumps(context.masked_report)
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in report_str
    assert "[MASKED]" in report_str


@then('the report should be valid JSON')
def step_impl_verify_valid_json(context):
    json.dumps(context.masked_report)  # Should not raise


@then('Authorization header values should show "[MASKED]"')
def step_impl_verify_auth_masked(context):
    auth_header = next(h for h in context.masked_entry["request"]["headers"]
                       if h["name"] == "Authorization")
    assert auth_header["value"] == "[MASKED]"


@then('Cookie header values should show "[MASKED]"')
def step_impl_verify_cookie_masked(context):
    cookie_header = next(h for h in context.masked_entry["request"]["headers"]
                         if h["name"] == "Cookie")
    assert cookie_header["value"] == "[MASKED]"


@then('the AWS key "{key}" should not appear')
def step_impl_verify_aws_not_present(context, key):
    assert key not in context.console_output


@then('"[MASKED]" should appear instead')
def step_impl_verify_masked_present(context):
    assert "[MASKED]" in context.console_output


@then('the output should be "{expected}"')
def step_impl_verify_output(context, expected):
    assert context.masked_url == expected


@then('"{secret}" should not appear in the report')
def step_impl_verify_secret_not_present(context, secret):
    assert secret not in context.masked_body


@then('the password field should contain "[MASKED]"')
def step_impl_verify_password_masked(context):
    assert "[MASKED]" in context.masked_body


@then('all cookie values should be "[MASKED]"')
def step_impl_verify_all_cookies_masked(context):
    for cookie in context.processed_entry["request"]["cookies"]:
        assert cookie["value"] == "[MASKED]"


@then('cookie names should remain visible')
def step_impl_verify_cookie_names_visible(context):
    cookie_names = [c["name"] for c in context.processed_entry["request"]["cookies"]]
    assert "session" in cookie_names
    assert "token" in cookie_names


@then('"{value}" should be replaced with "[MASKED]"')
def step_impl_verify_value_masked(context, value):
    assert value not in context.saved_text
    assert "[MASKED]" in context.saved_text


@then('the credit card number should be masked')
def step_impl_verify_cc_masked(context):
    assert "4532-1234-5678-9010" not in context.masked_content
    assert "[MASKED]" in context.masked_content


@then('all values should remain unchanged')
def step_impl_verify_unchanged(context):
    for key, value in context.data.items():
        assert context.masked_result[key] == value


@then('the Authorization value should be "[MASKED]" at all levels')
def step_impl_verify_nested_masked(context):
    auth_value = context.masked_result["level1"]["level2"]["Authorization"]
    assert auth_value == "[MASKED]"


@then('sensitive patterns should be masked')
def step_impl_verify_patterns_masked(context):
    assert "eyJhbGciOiJIUzI1NiJ9" not in context.masked_html
    assert "AKIAIOSFODNN7EXAMPLE" not in context.masked_html


@then('the HTML structure should remain valid')
def step_impl_verify_html_valid(context):
    assert "<html>" in context.masked_html
    assert "</html>" in context.masked_html


@then('the Stripe key should be masked')
def step_impl_verify_stripe_masked(context):
    masked = mask_string(context.alert["evidence"])
    assert "sk_live_" not in masked or "[MASKED]" in masked


@then('secrets should be replaced with "{placeholder}"')
def step_impl_verify_custom_placeholder(context, placeholder):
    assert placeholder in context.masked_result


@then('not with "[MASKED]"')
def step_impl_verify_not_default(context):
    assert "[MASKED]" not in context.masked_result


@then('the console output should show "[MASKED]" instead of "{secret}"')
def step_impl_verify_console_masked(context, secret):
    assert secret not in context.logged_url
    assert "[MASKED]" in context.logged_url


@then('the URL structure should remain identifiable')
def step_impl_verify_url_structure(context):
    assert "https://" in context.logged_url
    assert "api.example.com" in context.logged_url


@then('all tokens in URLs should be masked')
def step_impl_verify_all_tokens_masked(context):
    for alert in context.masked_alerts:
        assert "secret" not in alert["url"]


@then('the file should contain "[MASKED]" markers')
def step_impl_verify_markers_present(context):
    masked_str = json.dumps(context.masked_alerts)
    assert "[MASKED]" in masked_str
