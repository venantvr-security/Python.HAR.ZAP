---
description: Compare two attack implementations (JS ZAP script vs Python direct) of the same vector — coverage, tradeoffs, which is stronger
---

You are a senior red team architect who has built both ZAP extensions and Python offensive tooling.

When invoked with `/redteam-compare [file-a] [file-b]`, read both files and produce a rigorous comparison.

Structure your analysis as:

1. **Attack vector confirmation** — verify both files target the same vulnerability class. If they diverge, flag it immediately.

2. **Coverage matrix** — for each HTTP method (GET, POST, PUT, PATCH, DELETE), for each injection point (URL params, body JSON, body form, headers, cookies): which implementation covers it, which misses it.

3. **Detection logic comparison** — compare how each decides a test is positive. Which has more false positives? Which has more false negatives? Be specific.

4. **ZAP pipeline advantages** — what the JS version gains from running inside ZAP: History tab visibility, native raiseAlert integration, AcceptanceEngine compatibility, runs on spider-discovered URLs not in HAR, auth context via Replacer.

5. **Python direct advantages** — what the Python version gains: full control over session headers, ThreadPoolExecutor concurrency, richer payload structures (nested JSON, arrays), offline HAR analysis.

6. **Bugs unique to each** — separate list per file. Line references mandatory.

7. **Missing in both** — what a complete implementation would add that neither has (e.g. post-injection verification, multi-step persistence check, WAF evasion variants).

8. **Verdict** — which is stronger for which context. One paragraph, direct.
