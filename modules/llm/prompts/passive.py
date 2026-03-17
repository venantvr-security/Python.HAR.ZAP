"""
Passive analysis prompts - Regex generation for sensitive data detection.
"""
from .base import PromptTemplate
from .system import SECURITY_ANALYST


PASSIVE_REGEX = PromptTemplate(
    name="passive_regex",
    description="Generate domain-specific regex for sensitive data detection",
    system=SECURITY_ANALYST,
    user="""Generate custom regex patterns for detecting sensitive data leaks in a $domain application.

Observed JSON keys: $json_keys
Domain entities: $entities

Create regex patterns for domain-specific sensitive data that generic scanners miss.
Consider: internal IDs, business-specific codes, custom tokens, PII formats.

JSON response:
{
  "patterns": [
    {
      "name": "pattern_name",
      "regex": "valid_regex_pattern",
      "severity": "critical|high|medium|low",
      "compliance": "HIPAA|PCI|GDPR|null",
      "description": "what this detects"
    }
  ]
}

Generate 5-10 domain-specific patterns."""
)
