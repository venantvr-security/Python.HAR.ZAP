# Configuration Guide

[← Back to Index](../README.md) | [← Installation](INSTALLATION.md) | [Next: Scanning →](SCANNING.md)

---

## Configuration Sources

Configuration is loaded with this priority (highest first):

1. **Environment variables** (`HARZAP_*`)
2. **Config file** (`config.yaml`)
3. **Default values**

---

## Config File (config.yaml)

### Basic Structure

```yaml
# =============================================================================
# SCOPE
# =============================================================================
scope_domains: []              # Whitelist (empty = all)
exclude_domains:
  - "google-analytics.com"
  - "cdn.jsdelivr.net"

allowed_methods:
  - GET
  - POST
  - PUT
  - DELETE
  - PATCH

# =============================================================================
# ZAP CONFIGURATION
# =============================================================================
zap_port: 8080
zap_image: "ghcr.io/zaproxy/zaproxy:stable"

# =============================================================================
# SCAN SETTINGS
# =============================================================================
max_scan_time: 300             # seconds
max_urls: 100                  # limit URLs to scan
max_workers: 10                # parallel workers
incremental: false             # delta scanning

# Rate limiting
rate_limit: 10.0               # requests per second
rate_burst: 20                 # burst capacity

# =============================================================================
# REPORTING
# =============================================================================
reporting:
  formats:
    - json
    - sarif
  include_curl: true           # cURL reproduction commands
  include_timeline: true       # Scan timeline
  executive_summary: true
```

---

## Environment Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `HARZAP_ZAP_PORT` | int | 8080 | ZAP API port |
| `HARZAP_ZAP_IMAGE` | str | zaproxy:stable | Docker image |
| `HARZAP_ZAP_URL` | str | auto | ZAP URL |
| `HARZAP_API_KEY` | str | - | ZAP API key |
| `HARZAP_MAX_SCAN_TIME` | int | 300 | Scan timeout |
| `HARZAP_MAX_URLS` | int | 100 | Max URLs |
| `HARZAP_MAX_WORKERS` | int | 10 | Parallel workers |
| `HARZAP_RATE_LIMIT` | float | 10.0 | Requests/sec |
| `HARZAP_RATE_BURST` | int | 20 | Burst capacity |
| `HARZAP_DEBUG` | bool | false | Debug mode |
| `HARZAP_LOG_LEVEL` | str | INFO | Log level |
| `HARZAP_LOG_JSON` | bool | false | JSON logging |
| `HARZAP_INCREMENTAL` | bool | false | Delta scanning |

### Example

```bash
export HARZAP_ZAP_PORT=8081
export HARZAP_MAX_WORKERS=20
export HARZAP_LOG_JSON=true
export HARZAP_LOG_LEVEL=DEBUG

python cli.py scan traffic.har
```

---

## Scan Policies

```yaml
scan_policies:
  - name: "SQL Injection"
    enabled: true
    threshold: "High"
    scanners:
      - 40018  # SQL Injection
      - 40019  # MySQL
      - 40020  # PostgreSQL
      - 40021  # Oracle
      - 40022  # SQLite

  - name: "Cross-Site Scripting"
    enabled: true
    threshold: "Medium"
    scanners:
      - 40012  # XSS Reflected
      - 40014  # XSS Persistent
      - 40016  # XSS DOM

  - name: "Path Traversal"
    enabled: true
    threshold: "High"
    scanners:
      - 6      # Path Traversal
      - 40003  # CRLF Injection
```

---

## Alert Thresholds

```yaml
alert_thresholds:
  high: 5      # fail if > 5 high alerts
  medium: 10   # fail if > 10 medium alerts
  low: 20      # informational
```

---

## Webhooks

```yaml
webhooks:
  - type: slack
    url: https://hooks.slack.com/services/xxx
    events:
      - critical
      - scan_complete

  - type: teams
    url: https://outlook.office.com/webhook/xxx
    events:
      - scan_complete

  - type: discord
    url: https://discord.com/api/webhooks/xxx
    events:
      - critical
```

---

## OWASP Compliance

```yaml
owasp:
  enabled: true
  version: "2021"
  fail_on_categories:
    - "A01:2021"  # Broken Access Control
    - "A03:2021"  # Injection
```

---

## GraphQL Settings

```yaml
graphql:
  enabled: true
  introspection_timeout: 30    # seconds
  max_depth: 10                # query depth limit test
  batch_limit: 100             # batch attack size
  dos_test_size: 1000          # DoS test payload count
```

---

## WebSocket Settings

```yaml
websocket:
  enabled: true
  timeout: 30
  max_messages: 100
```

---

## Configuration in Code

```python
from modules.config_loader import load_config, get_zap_config, get_scan_config

# Load with defaults + file + env
config = load_config('config.yaml')

# Extract specific configs
zap_config = get_zap_config(config)
scan_config = get_scan_config(config)
```

---

## Next Steps

→ [Scanning Guide](SCANNING.md)
