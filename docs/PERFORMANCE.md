# Performance — where the time goes, and how to cut it

**The bottleneck is HTTP I/O, not CPU.** Measured on the access matrix: the pure
compute is ~0 ms; the wall-clock is entirely the requests (e.g. 36 sequential
requests at 20 ms ≈ 0.7 s; on a real API, 50 endpoints × 4 roles at 100 ms would
be ~20 s sequential). So every optimization below is about **doing fewer requests,
or doing them concurrently** — not about faster Python.

## 1. Parallelism (biggest win)

Independent requests run in a thread pool:

- **Access matrix** — the N roles × M endpoints are independent → parallelized.
  Tune with `matrix --workers N` (default 8). Raise it on a robust target, lower
  it to be gentle on production.
- **Rate-limit probe (API4)** — the burst is fired concurrently, which is both
  more realistic (throttling triggers under simultaneous load) and far faster.
- **IDOR detection** — `idor --workers N` (existing).

Violations/results stay deterministic: I/O is parallel, the verdict pass is
sequential and ordered.

## 2. Spend the LLM sparingly

- **Replay** — record once (`--ai-record run.json`), then `--ai-replay run.json`
  re-runs the exact AI-assisted assessment with **no API calls and no key**.
- **Cache** — completions are cached (`.llm_cache/`), so identical prompts across
  runs cost nothing.
- **Batch mode** — Gemini batch (`llm.batch_enabled`) is ~50% cheaper for the
  planning pass.
- **Bounded loops** — adaptive rounds are capped (`max_rounds`) with a confidence
  early-stop; the LLM is only consulted at genuine decision points.
- **No key? No slowdown** — every AI step falls back to deterministic heuristics.

## 3. Shrink the target set

- **HAR preprocessing filters** — exclude domains, static assets, methods,
  content-types and status codes before scanning (fewer endpoints in scope).
- **`--incremental`** — skips requests already scanned in a previous run.
- **Regression gate baseline** — known findings aren't re-triaged; only new ones
  matter (`--baseline`).
- **`max_targets`** — the adaptive campaign bounds how many endpoints it attacks.

## 4. Preview before you fire

- **`scan --dry-run`** prints the planned targets, policies, request volume and
  estimated duration without sending anything — size the run first.

## 5. Transport trade-off

Routing attacks **through ZAP** (`--via-zap`, and `diagnose` by default) adds proxy
overhead but gives you ZAP's passive scan and full history. For a quick, pure
adaptive pass, the direct-`requests` transport is lighter.
