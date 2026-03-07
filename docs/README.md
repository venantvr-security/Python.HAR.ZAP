# HAR-ZAP Documentation

> Professional DAST Security Platform for Pentesters and Security Engineers

---

## Quick Navigation

| Section | Description |
|---------|-------------|
| [Getting Started](GETTING_STARTED.md) | First steps, quick start guide |
| [Installation](guides/INSTALLATION.md) | Setup, dependencies, Docker |
| [Configuration](guides/CONFIGURATION.md) | Config file, environment variables |
| [Scanning Guide](guides/SCANNING.md) | Running scans, modes, options |
| [Payloads](guides/PAYLOADS.md) | Payload library, customization |
| [Advanced Attacks](guides/ADVANCED_ATTACKS.md) | Smuggling, JWT, CORS, Cache |
| [CLI Reference](api/CLI.md) | Command line interface |
| [Modules API](api/MODULES.md) | Python API reference |
| [CI/CD Integration](examples/CICD.md) | GitHub Actions, GitLab CI |
| [GraphQL Testing](examples/GRAPHQL.md) | GraphQL security testing |

---

## Architecture Overview

```mermaid
graph TB
    subgraph CLI["CLI (cli.py)"]
        scan[scan]
        graphql[graphql]
        websocket[websocket]
        idor[idor]
        cache[cache]
        advanced[advanced]
    end

    subgraph Core["Core Modules"]
        zap_scanner[zap_scanner.py]
        zap_fuzzer[zap_fuzzer.py]
        har_analyzer[har_analyzer.py]
        graphql_scanner[graphql_scanner.py]
        websocket_scanner[websocket_scanner.py]
        idor_detector[idor_detector.py]
        redteam[redteam_attacks.py]
    end

    subgraph Advanced["Advanced Attacks"]
        smuggling[http_smuggling.py]
        cache_poison[cache_poisoning.py]
        jwt[jwt_attacks.py]
        cors[cors_tester.py]
        timing[timing_analysis.py]
    end

    subgraph Infra["Infrastructure"]
        config_loader[config_loader.py]
        docker_manager[docker_manager.py]
        incremental[incremental_scanner.py]
        utils[utils/core.py]
    end

    subgraph Report["Reporting"]
        reporter[reporter.py]
        owasp[owasp_mapper.py]
        acceptance[acceptance_engine.py]
        notifications[notifications.py]
    end

    CLI --> Core
    CLI --> Advanced
    Core --> Infra
    Core --> Report
    Advanced --> Infra
```

---

## Features Matrix

| Feature | Description | Status |
|---------|-------------|--------|
| HAR-based scanning | Scan from recorded traffic | ✅ |
| Docker ZAP orchestration | Auto-start/stop ZAP | ✅ |
| Active scanning | SQL, XSS, injection testing | ✅ |
| Passive scanning | Headers, PII, entropy | ✅ |
| IDOR detection | Multi-session access control | ✅ |
| GraphQL testing | Introspection, batching, depth | ✅ |
| WebSocket testing | CSWSH, auth, injection | ✅ |
| Incremental scanning | Cache-based delta scans | ✅ |
| OWASP Top 10 mapping | Compliance reporting | ✅ |
| CI/CD integration | SARIF, JUnit, fail-fast | ✅ |
| Webhook notifications | Slack, Teams, Discord | ✅ |
| Rate limiting | Configurable request rate | ✅ |
| Custom payloads | Hierarchical payload library | ✅ |
| HTTP Smuggling | CL.TE, TE.CL, TE.TE detection | ✅ |
| Cache Poisoning | Unkeyed header injection | ✅ |
| JWT Attacks | None alg, weak secrets, confusion | ✅ |
| CORS Testing | Origin reflection, bypass | ✅ |
| Timing Analysis | Blind injection via timing | ✅ |

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run scan with HAR file
python cli.py scan traffic.har --owasp --fail-fast --max-high 0

# 3. View results
cat output/scan_report_*.json
```

→ [Full Getting Started Guide](GETTING_STARTED.md)

---

## Support

- Issues: GitHub Issues
- Security: security@example.com
