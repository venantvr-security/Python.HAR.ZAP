# DAST Security Platform

Enterprise-grade Dynamic Application Security Testing platform with OWASP ZAP orchestration, Red Team offensive testing, IDOR detection, and CI/CD integration.

## Features

### Core Capabilities

- **HAR Intelligence**: Smart parsing with fuzzable parameter detection and auth extraction
- **Docker Orchestration**: Automated ZAP lifecycle management
- **Red Team Attacks**: Offensive security testing (Unauth Replay, Mass Assignment, Hidden Params)
- **Passive Analysis**: Non-invasive security checks (headers, PII leaks, token entropy)
- **IDOR Detection**: Multi-session cross-user testing with visual diff proofs
- **OpenAPI Import**: Automatic endpoint discovery from Swagger/OpenAPI specs
- **Advanced Auth**: Form-based, OAuth2, JWT, HTTP Basic/Digest support
- **Acceptance Engine**: Define security criteria with fail-fast CI/CD mode

### Attack Vectors

#### Red Team (Offensive)

- **Unauthenticated Replay**: Tests if auth headers can be removed (CRITICAL)
- **Mass Assignment**: Injects privilege escalation parameters (`{"role": "admin"}`)
- **Hidden Parameters**: Discovers debug/admin mode switches (`?debug=true`)
- **Race Conditions**: Identifies TOCTOU vulnerabilities (transfer/coupon endpoints)

#### Passive (Non-Invasive)

- **Security Headers**: HSTS, CSP, X-Frame-Options, Secure/HttpOnly cookies
- **Sensitive Data**: Regex detection for PII, API keys, JWT, passwords, SSN, credit cards
- **Token Entropy**: Shannon entropy analysis for session predictability
- **Stack Traces**: Detects information disclosure in error responses

### New Features

#### HAR Preprocessing (Unified Pipeline)

- **Single-pass extraction**: Endpoints, payloads, querystrings, dictionaries
- **Advanced filtering**: Methods, domains, content-types, status codes, static exclusion
- **Export formats**: Unified JSON or granular component files
- **Token extraction**: Smart fuzzing wordlist generation from traffic

#### Dictionary & Payload System

- **PayloadAnalyzer**: Schema extraction, key-value pairs, template building
- **PayloadReconstructor**: Attack payload generation (mass assignment, injection, fuzzing)
- **DictionaryManager**: Extensible dictionaries with custom extensions

### Interfaces

- **Streamlit Web UI**: Self-explanatory dashboard with 9 specialized tabs
- **CLI**: CI/CD-friendly with JUnit/SARIF export
- **Legacy CLI**: Original orchestrator.py for backward compatibility

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Web Interface (Recommended)

```bash
streamlit run app.py
```

Access at http://localhost:8501

Tabs:

1. **Upload & Configure**: HAR upload, scope/exclusion rules, attack type selection
2. **HAR Preprocessing**: Unified HAR processing with filters, extraction, export
3. **ZAP Scan**: Traditional OWASP ZAP active/passive scanning
4. **ZAP Fuzzer**: Intelligent fuzzing with extracted tokens/IDs from HAR
5. **IDOR Testing**: Multi-session cross-user access control testing
6. **Red Team**: Offensive security attacks (auth bypass, privilege escalation)
7. **Passive Scan**: Non-invasive security analysis (headers, leaks, entropy)
8. **Results**: Unified view of all findings with severity filtering
9. **Acceptance**: Define pass/fail criteria for CI/CD integration

### CI/CD Integration

```bash
# Fail build if any high severity alerts
python cli.py scan traffic.har --max-high 0 --fail-fast

# IDOR detection with exit code
python cli.py idor --session-a user1.har --session-b user2.har --fail-on-idor

# Export SARIF for GitHub Security
python cli.py scan traffic.har --format sarif --output results.sarif

# JUnit XML for Jenkins/GitLab
python cli.py scan traffic.har --format junit --max-high 0 --max-medium 5
```

### Legacy CLI

```bash
python orchestrator.py captured_traffic.har -c config.yaml -o ./reports
```

## Configuration

Edit `config.yaml`:

```yaml
scope_domains:
  - "example.com"
  - "api.example.com"

exclude_domains:
  - "google-analytics.com"
  - "cdn.jsdelivr.net"

allowed_methods:
  - GET
  - POST
  - PUT
  - DELETE

zap_port: 8080
scan_fuzzable_urls: true
scan_api_endpoints: true
```

## Red Team Testing

### Unauthenticated Replay (CRITICAL)

Tests if endpoints remain accessible after removing authentication headers.

**Detection Logic:**

- Extract requests with `Authorization`/`Cookie` headers
- Replay without auth headers
- Vulnerable if: HTTP 200 + content_length > 100 bytes + status matches original

**Example Output:**

```
🚨 CRITICAL: https://api.example.com/user/profile accessible without auth!
Confidence: 87%
Evidence: Status 200, Content: 2.3KB (original: 2.4KB)
```

### Mass Assignment

Injects privilege escalation parameters into POST/PUT/PATCH requests.

**Payloads Tested:**

```json
{
  "role": "admin"
}
{
  "is_admin": true
}
{
  "permissions": [
    "admin",
    "write",
    "delete"
  ]
}
{
  "balance": 999999
}
```

**Vulnerable if:** Server accepts payload (HTTP 200/201) without error message

### Hidden Parameters

Discovers debug/admin parameters not visible in normal traffic.

**Common Params Tested:**

- `?debug=true`
- `?admin=1`
- `?test=yes`
- `?show_errors=true`

**Detection:** Content-length difference > 100 bytes from baseline

### Passive Analysis

**Security Headers:**

- Missing: HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- Weak CSP: `unsafe-inline`, `unsafe-eval`, wildcard sources
- Insecure Cookies: Missing `Secure` or `HttpOnly` flags

**Sensitive Data Scanner:**
Regex patterns for:

- Email addresses, phone numbers, SSN
- Credit card numbers (PCI-DSS violation)
- API keys (AWS: `AKIA[0-9A-Z]{16}`)
- JWT tokens, passwords in responses
- Private keys (RSA/EC)

**Token Entropy Analysis:**

- Shannon entropy calculation
- Flags tokens with < 4.0 bits entropy or < 16 chars length
- Severity: CRITICAL if < 3.0 bits

## IDOR Detection

Upload two HAR files from different authenticated sessions:

**Via Web UI:**

1. Navigate to "IDOR Testing" tab
2. Upload Session A (User A)
3. Upload Session B (User B)
4. Configure parallel workers
5. Run detection

**Via CLI:**

```bash
python cli.py idor \
  --session-a admin.har \
  --session-b standard_user.har \
  --workers 10 \
  --fail-on-idor
```

Results include:

- Confidence scores (content-length ratio > 50%)
- Visual HTTP diff (baseline vs test)
- cURL commands for manual reproduction
- Heuristic: Status 200 + significant content = IDOR

## Acceptance Criteria

Define security requirements in Web UI or via CLI:

**Criteria Types:**

- `max_high`: Maximum high severity alerts (ZAP + Red Team)
- `max_medium`: Maximum medium severity alerts
- `no_idor`: No IDOR vulnerabilities
- `no_sql_injection`: No SQL injection
- `no_xss`: No XSS vulnerabilities
- `clean_url`: Specific URL pattern must be clean
- `no_unauth_access`: All authenticated endpoints require valid credentials
- `min_token_entropy`: Minimum token entropy threshold (bits)

**Example CI/CD Pipeline:**

```yaml
# .gitlab-ci.yml
security_scan:
  script:
    - python cli.py scan traffic.har --max-high 0 --max-medium 5 --fail-fast
  artifacts:
    reports:
      junit: output/junit.xml
```

## Output Formats

### JSON (Detailed)

```bash
python cli.py scan traffic.har --format json
```

Full vulnerability details with payloads and evidence.

### SARIF (GitHub Security)

```bash
python cli.py scan traffic.har --format sarif
```

Upload to GitHub Code Scanning for issue tracking.

### JUnit XML (CI/CD)

```bash
python cli.py scan traffic.har --format junit --max-high 0
```

Test result format for Jenkins/GitLab/CircleCI.

### HTML (Human-readable)

```bash
python cli.py scan traffic.har --format html
```

ZAP native HTML report with charts.

## Advanced Features

### OpenAPI/Swagger Import

```python
from modules.openapi_importer import OpenAPIImporter

importer = OpenAPIImporter(zap_client)
importer.load_from_url('https://api.example.com/swagger.json')
endpoints = importer.parse_endpoints()
importer.import_to_zap(target_url='https://api.example.com')
```

### Custom Authentication

```python
from modules.advanced_zap_config import AdvancedZAPConfig

config_mgr = AdvancedZAPConfig(zap_client)
config_mgr.configure_authentication({
    'method': 'oauth2',
    'access_token': 'eyJhbGc...',
    'context_name': 'API'
})
```

## Architecture

```
app.py                          # Streamlit web interface (7 tabs)
cli.py                          # CI/CD CLI
orchestrator.py                 # Legacy CLI
modules/
  ├── har_analyzer.py           # HAR parsing & intelligence
  ├── docker_manager.py         # ZAP container lifecycle
  ├── zap_scanner.py            # Scan orchestration
  ├── idor_detector.py          # IDOR testing engine (ThreadPoolExecutor)
  ├── redteam_attacks.py        # Offensive security attacks
  │   ├── UnauthenticatedReplayAttack
  │   ├── MassAssignmentFuzzer
  │   ├── HiddenParameterDiscovery
  │   └── RaceConditionTester
  ├── passive_analysis.py       # Non-invasive security checks
  │   ├── SecurityHeadersAnalyzer
  │   ├── SensitiveDataScanner (10+ regex patterns)
  │   └── TokenEntropyAnalyzer (Shannon entropy)
  ├── redteam_ui_helpers.py     # Streamlit result renderers
  ├── acceptance_engine.py      # Criteria evaluation + SARIF/JUnit export
  ├── reporter.py               # Multi-format reporting
  ├── openapi_importer.py       # OpenAPI/Swagger parser
  └── advanced_zap_config.py    # Auth & context config
```

## Technical Implementation

**Parallelization:**

- `ThreadPoolExecutor` for Red Team attacks (5-10 workers)
- Async/await support via `aiohttp` for race condition testing

**Detection Algorithms:**

- Content-length ratio for auth bypass (> 50% threshold)
- Shannon entropy for token randomness
- Regex-based pattern matching for sensitive data
- HTTP status code + response size heuristics

**Security:**

- TLS verification disabled for testing (pentest context)
- Requests sanitized (no credentials in logs)
- Docker isolation for ZAP processes

## License

MIT

## Use Cases

1. **Penetration Testing**: Automated discovery of business logic flaws
2. **CI/CD Security Gates**: Fail builds on critical findings
3. **Compliance Audits**: PCI-DSS (PII leaks), OWASP Top 10 coverage
4. **Security Regression Testing**: Compare HAR files across releases
5. **Bug Bounty Hunting**: Systematic endpoint enumeration

## Limitations & Manual Testing Recommendations

**Automated (This Tool):**

- ✅ Unauthenticated replay
- ✅ Mass assignment detection
- ✅ IDOR (with 2 sessions)
- ✅ Security header validation
- ✅ Sensitive data leakage

**Requires Manual Testing:**

- ⚠️ Complex business logic (e.g., negative pricing)
- ⚠️ Multi-step workflows (checkout flow manipulation)
- ⚠️ Race conditions (requires precise timing + burst testing)
- ⚠️ Cryptographic weaknesses (algorithm analysis)

## Contributing

PRs welcome. Focus areas:

- ML-based false positive reduction (sklearn clustering)
- AsyncIO race condition burst testing (50+ concurrent requests)
- Additional auth methods (SAML, Kerberos)
- Distributed scanning (Celery/Redis queue)
- Real-time dashboards (Grafana/Prometheus integration)
- GraphQL/gRPC support

## Disclaimer

**For authorized security testing only.** Unauthorized penetration testing is illegal. Always obtain written permission before testing systems you don't own.
