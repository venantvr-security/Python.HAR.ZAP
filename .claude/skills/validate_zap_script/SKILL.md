---
description: Agent skill — automatically validates any ZAP active script written or modified by Claude
---

This is an agent skill. Invoke it automatically whenever you write or modify a file matching `scripts/active/*.js`.

Validate the script against these mandatory checks. Fail loudly if any check fails — do not silently proceed.

**Signature check**
Function must be named `scan`. Accepted signatures:
- `function scan(as, msg, param, value)`
- `function scan(as, msg, src)`
No other signatures are valid for ZAP active scripts.

**raiseAlert check**
Every `raiseAlert` call must have exactly the right argument count for the ZAP version in use. Standard signature: `(risk, name, description, uri, param, attack, solution, evidence, msg)` where risk is an integer (0=Informational, 1=Low, 2=Medium, 3=High — note: ZAP uses inverted scale, verify against codebase convention).

**cloneRequest check**
Any message sent via `sendAndReceive` must use a cloned message (`msg.cloneRequest()`), never the original `msg` directly.

**Content-Length check**
Any script that modifies the request body must update the Content-Length header immediately after. Flag any `setRequestBody` call not followed by `setHeader('Content-Length', ...)`.

**JSON.parse safety check**
Any `JSON.parse` call must be inside a try/catch. Flag unprotected parse calls.

**Baseline comparison check**
If the script compares response length to detect anomalies, verify both sides use the same string transformation (both toLowerCase or neither).

**False positive risk check**
Flag any detection condition that uses `statusCode === 200` alone without additional signal (body content, length diff, header change).

Report each failed check with the line number and a one-line fix. If all checks pass, confirm silently with: `[validate_zap_script] ✓ {filename}`.
