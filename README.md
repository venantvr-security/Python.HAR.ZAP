# DAST Security Platform

Enterprise-grade Dynamic Application Security Testing platform with OWASP ZAP orchestration, IDOR detection, and CI/CD integration.

## Features

### Core Capabilities
- **HAR Intelligence**: Smart parsing with fuzzable parameter detection and auth extraction
- **Docker Orchestration**: Automated ZAP lifecycle management
- **IDOR Detection**: Multi-session cross-user testing with visual diff proofs
- **OpenAPI Import**: Automatic endpoint discovery from Swagger/OpenAPI specs
- **Advanced Auth**: Form-based, OAuth2, JWT, HTTP Basic/Digest support
- **Acceptance Engine**: Define security criteria with fail-fast CI/CD mode

### Interfaces
- **Streamlit Web UI**: Self-explanatory dashboard with drag-drop HAR upload
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

Features:
- Drag-drop HAR upload with live preview
- Visual target selection
- Real-time scan progress
- Interactive IDOR testing with diff viewer
- Acceptance criteria builder

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
- Confidence scores
- Visual HTTP diff (baseline vs test)
- cURL commands for manual reproduction
- Content-length ratio analysis

## Acceptance Criteria

Define security requirements in Web UI or via CLI:

**Criteria Types:**
- `max_high`: Maximum high severity alerts
- `max_medium`: Maximum medium severity alerts
- `no_idor`: No IDOR vulnerabilities
- `no_sql_injection`: No SQL injection
- `no_xss`: No XSS vulnerabilities
- `clean_url`: Specific URL pattern must be clean

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
app.py                    # Streamlit web interface
cli.py                    # CI/CD CLI
orchestrator.py           # Legacy CLI
modules/
  ├── har_analyzer.py           # HAR parsing & intelligence
  ├── docker_manager.py         # ZAP container lifecycle
  ├── zap_scanner.py            # Scan orchestration
  ├── idor_detector.py          # IDOR testing engine
  ├── acceptance_engine.py      # Criteria evaluation
  ├── reporter.py               # Multi-format reporting
  ├── openapi_importer.py       # OpenAPI/Swagger parser
  └── advanced_zap_config.py    # Auth & context config
```

## License

MIT

## Contributing

PRs welcome. Focus areas:
- ML-based false positive reduction
- Additional auth methods (SAML, Kerberos)
- Distributed scanning
- Real-time dashboards (Grafana integration)
