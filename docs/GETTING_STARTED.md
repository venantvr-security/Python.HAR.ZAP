# Getting Started

> From zero to first scan in 5 minutes

[← Back to Index](README.md)

---

## Prerequisites

- Python 3.9+
- Docker (for ZAP container) or existing ZAP instance
- HAR file from your target application

---

## Step 1: Installation

```bash
# Clone repository
git clone https://github.com/your-repo/harzap.git
cd harzap

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

→ [Detailed Installation Guide](guides/INSTALLATION.md)

---

## Step 2: Capture HAR File

### Using Browser DevTools

1. Open Chrome/Firefox DevTools (F12)
2. Go to **Network** tab
3. Navigate through your application
4. Right-click → **Save all as HAR with content**

### Using Proxy

```bash
# Using mitmproxy
mitmproxy -w traffic.har

# Using ZAP as proxy
# Configure browser to use localhost:8080
```

---

## Step 3: Run Your First Scan

### Basic Scan

```bash
python cli.py scan traffic.har
```

### Scan with Acceptance Criteria

```bash
python cli.py scan traffic.har \
    --fail-fast \
    --max-high 0 \
    --max-medium 5 \
    --owasp
```

### Scan with Existing ZAP Instance

```bash
python cli.py scan traffic.har \
    --no-docker \
    --zap-url http://localhost:8080 \
    --api-key your-api-key
```

---

## Step 4: View Results

### Console Output

```
[1/5] Analyzing HAR file...
URLs found: 127, API endpoints: 23, Fuzzable: 45

[2/5] Starting ZAP container...
[3/5] Executing scans...
[4/5] Generating reports...
  json: output/scan_report_20240101_120000.json
  sarif: output/results_20240101_120000.sarif

[OWASP] Score: 75.5/100 - PASS

SECURITY SCAN RESULTS
================================================================================
Total Alerts: 15
  High:   2
  Medium: 5
  Low:    8
```

### JSON Report Structure

```json
{
  "timestamp": "20240101_120000",
  "summary": {
    "total_alerts": 15,
    "high": 2,
    "medium": 5
  },
  "owasp_compliance": {
    "overall_score": 75.5,
    "passed": true
  },
  "alerts": [...]
}
```

---

## Step 5: Integrate with CI/CD

### GitHub Actions

```yaml
- name: Security Scan
  run: |
    python cli.py scan traffic.har \
      --fail-fast \
      --max-high 0 \
      --format sarif \
      --output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

→ [Full CI/CD Guide](examples/CICD.md)

---

## Common Workflows

### IDOR Testing

```bash
# Record two sessions with different users
python cli.py idor \
    --session-a user1.har \
    --session-b user2.har \
    --fail-on-idor
```

### GraphQL Security

```bash
python cli.py graphql api.har \
    --introspection \
    --batch-test \
    --depth-test
```

### Incremental Scanning

```bash
# First run: full scan
python cli.py scan traffic.har --incremental

# Subsequent runs: only new requests
python cli.py scan updated.har --incremental
```

---

## Next Steps

| Guide | Description |
|-------|-------------|
| [Configuration](guides/CONFIGURATION.md) | Customize settings |
| [Payloads](guides/PAYLOADS.md) | Custom attack payloads |
| [Scanning Guide](guides/SCANNING.md) | Advanced scanning |
| [CLI Reference](api/CLI.md) | All commands and options |
