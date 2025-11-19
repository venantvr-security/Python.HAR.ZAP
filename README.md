# ZAP HAR Orchestrator

Automated OWASP ZAP security scanner with HAR intelligence and Docker orchestration.

## Features

- HAR parsing with smart filtering
- Fuzzable parameter detection
- Docker-managed ZAP instances
- Targeted scanning strategies
- Auth header auto-injection
- Multi-format reporting (JSON, HTML, TXT)

## Installation

```bash
pip install -r requirements.txt
```

## Usage

Basic scan:
```bash
python orchestrator.py captured_traffic.har
```

With config:
```bash
python orchestrator.py captured_traffic.har -c config.yaml -o ./reports
```

Use existing ZAP:
```bash
python orchestrator.py captured_traffic.har --no-docker --zap-url http://localhost:8090 --api-key YOUR_KEY
```

## Config

Edit `config.yaml`:
- `scope_domains`: Whitelist domains
- `exclude_domains`: Block analytics/CDNs
- `allowed_methods`: Filter HTTP verbs
- `zap_port`: Docker port mapping

## Output

Reports saved to `./output/`:
- `scan_report_*.json`: Full results
- `scan_report_*.html`: ZAP HTML report
- `critical_findings_*.txt`: High/Medium alerts
