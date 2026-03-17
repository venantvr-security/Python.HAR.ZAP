"""
Analysis prompts - Full security analysis and domain inference.
"""
from .base import PromptTemplate
from .system import SECURITY_ANALYST, DOMAIN_EXPERT


FULL_ANALYSIS = PromptTemplate(
    name="full_analysis",
    description="Complete security analysis in single call",
    system=SECURITY_ANALYST,
    user="""Analyze this web application context for security testing:

## Application Context (from HAR traffic)
$context

## Required Analysis

Generate a comprehensive security testing plan as JSON with this exact structure:
{
  "domain_analysis": {
    "inferred_domain": "e-commerce|fintech|healthcare|saas|social|other",
    "business_entities": ["user", "order", "payment"],
    "sensitive_data_types": ["PII", "financial", "medical"],
    "confidence": 0.8
  },
  "strategies": [
    {
      "attack_type": "fuzzer|mass_assignment|idor|race_condition|passive_analysis|business_logic",
      "priority": "critical|high|medium|low",
      "targets": [
        {"endpoint": "/api/...", "method": "POST", "params": ["param1"], "reason": "..."}
      ],
      "payloads": [],
      "rationale": "Why this attack is relevant",
      "test_plan": ["Step 1...", "Step 2..."]
    }
  ],
  "prioritized_endpoints": [
    {"endpoint": "...", "risk_score": 0.9, "reasons": ["..."]}
  ],
  "custom_regex_patterns": [
    {"name": "...", "regex": "...", "severity": "critical|high|medium|low", "compliance": "HIPAA|PCI|GDPR|null"}
  ],
  "business_logic_flows": [
    {"name": "...", "steps": ["..."], "attack": "...", "severity": "..."}
  ]
}

Generate at least one strategy for each applicable attack_type.
Payloads must be domain-specific.
For IDOR, classify ID patterns and specify enumeration strategies.
For race conditions, identify TOCTOU windows in multi-step flows."""
)


DOMAIN_ANALYSIS = PromptTemplate(
    name="domain_analysis",
    description="Infer business domain from HAR context",
    system=DOMAIN_EXPERT,
    user="""Analyze these API endpoints and determine the business domain:

Endpoints: $endpoints
JSON keys: $json_keys
Parameters: $param_names

Respond with JSON:
{
  "domain": "e-commerce|fintech|healthcare|saas|social|other",
  "sub_domain": "string",
  "business_entities": ["entity1", "entity2"],
  "sensitive_data_types": ["PII", "financial", "medical"],
  "confidence": 0.0-1.0,
  "rationale": "explanation"
}"""
)
