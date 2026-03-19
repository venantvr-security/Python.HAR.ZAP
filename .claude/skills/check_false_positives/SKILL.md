---
description: Agent skill — scan any detection/analysis code for false positive patterns before finalizing
---

This is an agent skill. Invoke it automatically when writing or modifying detection logic in:
- `modules/redteam_attacks.py`
- `modules/passive_analysis.py`
- `modules/idor_detector.py`
- `scripts/active/*.js`

Scan the code for these false positive patterns:

**FP-01: Status code alone**
`statusCode == 200` or `response.status_code == 200` used as the sole detection signal. Every non-error response is 200 on many APIs. Require at least one additional signal.

**FP-02: Content-length diff without normalization**
Comparing response body lengths without accounting for dynamic content (timestamps, CSRF tokens, session IDs that change on every request). Flag threshold comparisons under 500 bytes as high FP risk.

**FP-03: Keyword matching in response body**
Generic strings like "admin", "error", "success", "true" matched anywhere in response. These appear legitimately in hundreds of contexts. Require context-aware matching (JSON key context, not substring anywhere).

**FP-04: Missing baseline**
Detection that compares a mutated response against nothing. Without a clean baseline request immediately before the attack, length and content comparisons are meaningless.

**FP-05: No persistence verification**
For privilege escalation attacks (mass assignment, role injection): accepting HTTP 200 as confirmation without a follow-up GET to verify the change persisted. Server may silently ignore the injected field.

**FP-06: Regex over-matching**
Regex patterns in passive analysis that match too broadly. Check each pattern in `SensitiveDataScanner` against benign content that would match (e.g. a pattern for API keys that also matches UUIDs).

For each FP pattern found: file, line, pattern type, risk level (HIGH/MEDIUM), one-line fix.
If clean: `[check_false_positives] ✓ {filename}`.
