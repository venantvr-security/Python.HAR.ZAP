# CLI Reference

[← Back to Index](../README.md)

---

## Global Options

```bash
python cli.py [OPTIONS] COMMAND [ARGS]

Options:
  -v, --verbose    Verbose output
  --version        Show version
  -h, --help       Show help
```

---

## Commands

### `scan` - Run Security Scan

```bash
python cli.py scan HAR_FILE [OPTIONS]

Arguments:
  HAR_FILE              HAR file to scan

Options:
  -c, --config FILE     Config YAML file
  -o, --output DIR      Output directory [default: ./output]
  --format FORMATS      Output formats (comma-separated):
                        json, html, sarif, junit
  --max-high N          Max high severity alerts (fail if exceeded)
  --max-medium N        Max medium severity alerts
  --fail-fast           Exit code 1 if criteria fail
  --incremental         Skip already-scanned requests
  --owasp               Include OWASP Top 10 compliance
  --graphql             Enable GraphQL scanning
  --websocket           Enable WebSocket scanning
  --no-docker           Use existing ZAP instance
  --zap-url URL         ZAP URL [default: http://localhost:8080]
  --api-key KEY         ZAP API key
  --webhook TYPE        Notification: slack, teams, discord
  --rate-limit FLOAT    Requests per second
```

#### Examples

```bash
# Basic scan
python cli.py scan traffic.har

# CI/CD scan with fail conditions
python cli.py scan traffic.har \
    --fail-fast \
    --max-high 0 \
    --max-medium 5 \
    --format sarif \
    --output ./results

# Full scan with all features
python cli.py scan traffic.har \
    --owasp \
    --graphql \
    --websocket \
    --incremental \
    --webhook slack

# Using existing ZAP
python cli.py scan traffic.har \
    --no-docker \
    --zap-url http://zap:8080 \
    --api-key abc123
```

---

### `graphql` - GraphQL Security Testing

```bash
python cli.py graphql HAR_FILE [OPTIONS]

Arguments:
  HAR_FILE              HAR file with GraphQL requests

Options:
  -o, --output DIR      Output directory
  --introspection       Test introspection endpoint
  --batch-test          Test batching/aliasing DoS
  --depth-test          Test query depth limits
  --fuzz                Fuzz GraphQL arguments
```

#### Examples

```bash
# Full GraphQL test
python cli.py graphql api.har \
    --introspection \
    --batch-test \
    --depth-test

# Fuzz GraphQL
python cli.py graphql api.har --fuzz
```

---

### `websocket` - WebSocket Security Testing

```bash
python cli.py websocket HAR_FILE [OPTIONS]

Arguments:
  HAR_FILE              HAR file with WebSocket connections

Options:
  -o, --output DIR      Output directory
  --cswsh               Test Cross-Site WebSocket Hijacking
  --fuzz                Fuzz WebSocket messages
```

#### Examples

```bash
# CSWSH test
python cli.py websocket traffic.har --cswsh

# Fuzz WebSocket
python cli.py websocket traffic.har --fuzz
```

---

### `idor` - IDOR Detection

```bash
python cli.py idor [OPTIONS]

Options:
  --session-a FILE      HAR file for User A (required)
  --session-b FILE      HAR file for User B (required)
  -o, --output DIR      Output directory
  --workers N           Parallel workers [default: 5]
  --fail-on-idor        Exit code 1 if IDOR found
  --webhook TYPE        Notification type
```

#### Examples

```bash
# Basic IDOR test
python cli.py idor \
    --session-a admin.har \
    --session-b user.har

# CI/CD IDOR test
python cli.py idor \
    --session-a admin.har \
    --session-b user.har \
    --fail-on-idor \
    --workers 10
```

---

### `cache` - Manage Incremental Cache

```bash
python cli.py cache ACTION [OPTIONS]

Actions:
  stats                 Show cache statistics
  clear                 Clear cache
  export                Export cache to JSON

Options:
  --older-than DAYS     Clear entries older than N days
  -o, --output FILE     Export output file
```

#### Examples

```bash
# View cache stats
python cli.py cache stats

# Clear old entries
python cli.py cache clear --older-than 30

# Export cache
python cli.py cache export -o cache_backup.json
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Failure (criteria not met, scan error, file not found) |

---

## Environment Variables

All options can be set via environment:

```bash
export HARZAP_ZAP_PORT=8080
export HARZAP_MAX_WORKERS=10
export HARZAP_RATE_LIMIT=10.0
export HARZAP_LOG_LEVEL=DEBUG
export HARZAP_LOG_JSON=true

python cli.py scan traffic.har
```

---

## Output Files

| Format | File | Description |
|--------|------|-------------|
| JSON | `scan_report_TIMESTAMP.json` | Full report with alerts |
| SARIF | `results_TIMESTAMP.sarif` | GitHub Security format |
| HTML | `scan_report_TIMESTAMP.html` | ZAP HTML report |
| JUnit | `junit.xml` | CI test results |
| Critical | `critical_findings_TIMESTAMP.txt` | High/Medium only |

---

### `advanced` - Advanced Attack Testing

```bash
python cli.py advanced HAR_FILE [OPTIONS]

Arguments:
  HAR_FILE              HAR file to analyze

Options:
  -o, --output DIR      Output directory
  --smuggling           Test HTTP request smuggling (CL.TE, TE.CL)
  --cache-poison        Test web cache poisoning
  --jwt                 Test JWT vulnerabilities (none alg, weak secrets)
  --cors                Test CORS misconfigurations
  --timing              Test blind injection via timing analysis (slow)
  --all                 Run all tests except timing
  --webhook TYPE        Notification: slack, teams, discord
```

#### Examples

```bash
# Run all advanced tests
python cli.py advanced traffic.har --all

# Test specific vulnerabilities
python cli.py advanced traffic.har --jwt --cors

# Full suite with timing (slow)
python cli.py advanced traffic.har --all --timing

# With notifications
python cli.py advanced api.har --jwt --webhook slack
```

---

## Next Steps

→ [Modules API](MODULES.md)
