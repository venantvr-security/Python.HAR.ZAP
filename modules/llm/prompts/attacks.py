"""
Attack prompts - Specific attack vector analysis and payload generation.
"""
from .base import PromptTemplate
from .system import PAYLOAD_GENERATOR, SECURITY_ANALYST


MASS_ASSIGNMENT = PromptTemplate(
    name="mass_assignment",
    description="Generate mass assignment payloads for privilege escalation",
    system=PAYLOAD_GENERATOR,
    user="""Generate Mass Assignment attack payloads for a $domain application.

Observed JSON keys: $json_keys
Observed endpoints: $endpoints

Generate field names and values that could:
1. Escalate privileges (admin, roles, permissions)
2. Modify financial values (balance, credits, discounts)
3. Bypass restrictions (verified, approved, active)
4. Access internal fields (internal_id, debug, test)

JSON response:
{
  "payloads": [
    {"field": "field_name", "value": "dangerous_value", "reason": "why it's dangerous"},
    ...
  ],
  "high_value_targets": ["/endpoint/to/test", ...]
}

Generate 15-20 domain-specific payloads, not generic ones."""
)


IDOR_STRATEGY = PromptTemplate(
    name="idor_strategy",
    description="Generate IDOR enumeration strategies by ID type",
    system=SECURITY_ANALYST,
    user="""Analyze these ID patterns and generate IDOR testing strategies:

ID patterns found:
$id_patterns

Endpoints: $endpoints

For each ID pattern, determine:
1. Pattern type (numeric_sequential, uuid, base64, prefixed, opaque)
2. Best enumeration strategy (enumerate, decode_mutate, harvest, skip)
3. Specific mutations to try

JSON response:
{
  "strategies": [
    {
      "pattern": "/api/users/{id}",
      "id_type": "numeric_sequential",
      "strategy": "enumerate",
      "mutations": ["{id}-1", "{id}+1", "0", "1", "-1", "999999"],
      "risk": "high|medium|low",
      "rationale": "why this strategy"
    }
  ]
}"""
)


RACE_CONDITION = PromptTemplate(
    name="race_condition",
    description="Detect TOCTOU windows in request flows",
    system=SECURITY_ANALYST,
    user="""Analyze these request flows for race condition vulnerabilities:

Request flows (sequences):
$request_flows

Domain: $domain

Identify TOCTOU (Time-Of-Check to Time-Of-Use) windows where:
1. Coupon/discount can be applied multiple times
2. Balance can be double-spent
3. Resource can be accessed during state transition
4. Payment can be manipulated between steps

JSON response:
{
  "race_windows": [
    {
      "name": "descriptive_name",
      "steps_involved": ["POST /cart", "POST /checkout"],
      "attack": "description of race attack",
      "method": "burst_parallel|intercept_modify",
      "concurrent_requests": 10,
      "severity": "critical|high|medium"
    }
  ]
}"""
)


BUSINESS_LOGIC = PromptTemplate(
    name="business_logic",
    description="Detect business logic vulnerabilities in flows",
    system=SECURITY_ANALYST,
    user="""Analyze these request flows for business logic vulnerabilities:

Request flows: $request_flows
Domain: $domain
Endpoints: $endpoints

Identify:
1. State skipping (calling step N without step N-1)
2. Negative value manipulation
3. Integer overflow opportunities
4. Price/quantity manipulation
5. Workflow bypass

JSON response:
{
  "vulnerabilities": [
    {
      "type": "state_skip|negative_amount|overflow|bypass",
      "flow": ["step1", "step2"],
      "attack": "description",
      "test_payload": {},
      "severity": "critical|high|medium"
    }
  ]
}"""
)


HIDDEN_PARAMS = PromptTemplate(
    name="hidden_params",
    description="Generate hidden/debug parameters to discover",
    system=PAYLOAD_GENERATOR,
    user="""Generate hidden parameter candidates for a $domain application.

Existing parameters: $param_names
Endpoints: $endpoints

Generate parameters likely to exist but not exposed:
1. Debug/test flags
2. Admin overrides
3. Feature flags
4. Internal controls
5. Bypass switches

JSON response:
{
  "hidden_params": [
    {"name": "param_name", "test_values": ["true", "1", "yes"], "category": "debug|admin|feature|bypass"},
    ...
  ],
  "high_value_endpoints": ["/endpoint/to/test", ...]
}

Generate 20-30 domain-specific parameters."""
)
