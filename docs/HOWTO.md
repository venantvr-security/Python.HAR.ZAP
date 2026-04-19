# HOWTO: Diagnostic Security Testing

[← Docs index](README.md) · [QUICKSTART](../QUICKSTART.md) · [PENTEST walkthrough](../PENTEST.md) · [CLI reference](api/CLI.md)

## Prerequisites

```bash
# Install dependencies
make install

# Start ZAP container
make docker-up
```

## Step 1: Capture Traffic

Record a HAR file from your browser (F12 > Network > Export HAR) while browsing www.blahblah.com.

Save as: `traffic.har`

## Step 2: Run Full Diagnostic Suite

```bash
# Run all diagnostic attacks in one command
python cli.py diagnose traffic.har --target https://www.blahblah.com -o ./results
```

This runs:
- ZAP active scan (SQLi, XSS, etc.)
- HTTP smuggling tests (CL.TE, TE.CL)
- JWT vulnerability tests
- CORS misconfiguration tests
- Cache poisoning tests
- Red team attacks (mass assignment, hidden params, race conditions)
- Passive analysis (headers, PII, entropy)

## Step 3: Individual Commands

### ZAP Scan
```bash
python cli.py scan traffic.har --owasp --fail-fast --max-high 0
```

### Advanced Attacks
```bash
python cli.py advanced traffic.har --all
```

### IDOR Detection (requires 2 sessions)
```bash
python cli.py idor --session-a user1.har --session-b user2.har
```

### GraphQL
```bash
python cli.py graphql traffic.har --introspection --batch-test
```

### WebSocket
```bash
python cli.py websocket traffic.har --cswsh --fuzz
```

## Step 4: Review Results

Reports generated in `./results/`:
- `diagnostic_report.json` - Full findings
- `diagnostic_report.html` - Human-readable report
- `advanced_attacks.json` - Advanced attack results
- `zap_alerts.json` - ZAP findings

## Web Interface

```bash
make run
# Open http://localhost:8501
```

## CI/CD Integration

```bash
python cli.py diagnose traffic.har --fail-fast --max-high 0 --format sarif
```

Exit code 1 if critical vulnerabilities found.
