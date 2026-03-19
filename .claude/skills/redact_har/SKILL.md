---
description: Agent skill — redact sensitive values from HAR content before any external API call or LLM prompt
---

This is an agent skill. Invoke it automatically before sending any HAR file content to an external API (Anthropic, OpenAI, or any HTTP call in the codebase).

**What to redact**

Replace these value types with placeholder tokens. Preserve key names — they are safe and needed for analysis.

- Authorization header values → `[REDACTED_AUTH]`
- Cookie values → `[REDACTED_COOKIE]`
- Any value matching JWT pattern (`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`) → `[REDACTED_JWT]`
- Any value matching AWS key pattern (`AKIA[0-9A-Z]{16}`) → `[REDACTED_AWS_KEY]`
- Email addresses → `[REDACTED_EMAIL]`
- Values of keys named: password, passwd, pwd, secret, token, api_key, apikey, access_token, refresh_token, client_secret → `[REDACTED_SECRET]`
- Credit card patterns (`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b`) → `[REDACTED_CC]`
- SSN patterns → `[REDACTED_SSN]`
- Phone numbers in response bodies → `[REDACTED_PHONE]`

**What to preserve**

- All URL paths and endpoint structure
- All JSON key names
- All HTTP method names
- All status codes
- Numeric IDs (needed for IDOR pattern analysis)
- Content-Type, Accept, and non-sensitive headers

**Output**

Write the redacted content to a temp file `{original_name}.redacted.har` in the same directory. Never modify the original HAR file. Print a summary: N values redacted by category.

If invoked on content already redacted (contains `[REDACTED_`), skip and confirm: `[redact_har] ✓ already sanitized`.
