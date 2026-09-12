# HAR-ZAP Documentation

Point your browser, record, drop the HAR — get an exploitable attack report.
HAR-ZAP is an adaptive, LLM-assisted API pentester built on OWASP ZAP.

## Start here

| Doc | What it is |
|-----|-----------|
| [../README.md](../README.md) | Overview, the one workflow, scenario examples |
| [../QUICKSTART.md](../QUICKSTART.md) | Get a scan running in ~5 minutes |
| [GETTING_STARTED.md](GETTING_STARTED.md) | First-run walkthrough |
| [../PENTEST.md](../PENTEST.md) | Full didactic pentest scenario |
| [HOWTO.md](HOWTO.md) | Task recipes for `diagnose` |

## Guides

| Doc | What it is |
|-----|-----------|
| [guides/INSTALLATION.md](guides/INSTALLATION.md) | Install & prerequisites |
| [guides/CONFIGURATION.md](guides/CONFIGURATION.md) | `config.yaml` reference |
| [guides/ADVANCED_ATTACKS.md](guides/ADVANCED_ATTACKS.md) | JWT / CORS / cache / smuggling |
| [guides/PAYLOADS.md](guides/PAYLOADS.md) | Payload & pattern system |
| [guides/TOR_SETUP.md](guides/TOR_SETUP.md) | Routing through TOR |
| [PREPROCESSING_GUIDE.md](PREPROCESSING_GUIDE.md) | HAR preprocessing pipeline |
| [HUNTING_GUIDE.md](HUNTING_GUIDE.md) | Vulnerability-hunting playbook |

## Reference

| Doc | What it is |
|-----|-----------|
| [api/CLI.md](api/CLI.md) | CLI reference (all commands & flags) |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System architecture |
| [PERFORMANCE.md](PERFORMANCE.md) | Performance analysis & tuning tips |
| [examples/CICD.md](examples/CICD.md) | CI/CD integration & the regression gate |

## Deep dives

| Doc | What it is |
|-----|-----------|
| [INNOVATION.md](INNOVATION.md) | What makes HAR-ZAP different |
| [ZAP_NATIVE_FEATURES.md](ZAP_NATIVE_FEATURES.md) | Using ZAP's native engine |
| [ARACHNI_INSPIRED.md](ARACHNI_INSPIRED.md) | Feature mapping via ZAP native capabilities |
| [ROADMAP_LLM_SECURITY.md](ROADMAP_LLM_SECURITY.md) | LLM integration design notes |

## Red Team vectors

[redteam/](redteam/): [Unauthenticated Replay](redteam/UNAUTHENTICATED_REPLAY.md) ·
[Mass Assignment](redteam/MASS_ASSIGNMENT.md) ·
[Hidden Parameters](redteam/HIDDEN_PARAMETERS.md) ·
[Race Conditions](redteam/RACE_CONDITIONS.md)

## Archive

[archive/](archive/) holds historical implementation notes (Arachni porting,
cohesion audit) kept for reference — not part of the current user documentation.
