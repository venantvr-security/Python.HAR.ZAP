# LLM Security Integration Roadmap

## Status: Implemented

Branch: `llm`

## Architecture

```mermaid
flowchart TD
    HAR --> HARContextExtractor --> LLMSecurityAnalyzer
    LLMSecurityAnalyzer -->|single call| SecurityPlan
    SecurityPlan --> MassAssign & IDOR & Race & Passive & BusinessLogic
    MassAssign & IDOR & Race & Passive & BusinessLogic --> PatternStore
    PatternStore -->|session-based| ZAPExport
```

One LLM call per HAR, cached by hash. Strategies consume the SecurityPlan.

## Modules

| Module | Purpose |
|--------|---------|
| `modules/llm/client.py` | Anthropic API wrapper, rate limiting |
| `modules/llm/cache.py` | File cache by HAR hash, TTL 24h |
| `modules/llm/context_extractor.py` | Privacy-safe HAR extraction (keys only) |
| `modules/llm/analyzer.py` | SecurityPlan generator |
| `modules/llm/pattern_store.py` | Session-based persistence, ZAP export |
| `modules/llm/strategies/` | Attack-specific enrichment |

## LLM Value per Attack Type

| Attack | LLM Contribution | Impact |
|--------|------------------|--------|
| Fuzzer | Domain-specific vocabulary | High |
| Mass Assignment | Probable model fields | High |
| IDOR | ID format detection, enumeration strategy | High |
| Race Condition | TOCTOU window detection | Very High |
| Passive Analysis | Custom regex per domain | Medium |
| Business Logic | Multi-step flow analysis | Very High |

## Pattern Store

Session-scoped persistence with ZAP integration:

```
./patterns/
```

Operations: GET / ADD / PERSIST / PUSH

## API Endpoints

```
POST /llm/analyze              # HAR -> SecurityPlan
POST /llm/enrich-and-store     # Full pipeline with persistence
GET  /llm/patterns/sessions    # List sessions
GET  /llm/patterns/current     # Current session
POST /llm/patterns/merge       # Merge all sessions
POST /llm/patterns/{id}/push   # Push to ZAP export
```

## Config

```yaml
llm:
  enabled: true
  provider: "anthropic"
  model: "claude-sonnet-4-20250514"
  max_tokens: 4000
  temperature: 0.1
  cache:
    enabled: true
    directory: "./.llm_cache"
    ttl_hours: 24
```

Env: `HARZAP_LLM_API_KEY`

## Privacy

Context extractor sends structure only:
- Endpoint patterns: `/users/{id}`, `/orders/{id}`
- JSON keys: `["user_id", "role", "email"]`
- Parameter names: `["page", "limit", "filter"]`

Never sends actual values.

## ZAP Integration

Docker mount:
```
-v ./patterns/zap_export/fuzzers:/home/zap/.ZAP/fuzzers/llm:ro
```

## TODO

- [ ] CLI command for offline enrichment
- [ ] Rate limiter metrics
- [ ] Multi-provider support (OpenAI, local models)
