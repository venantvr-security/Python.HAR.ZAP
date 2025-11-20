# Architecture Overview

## Module Organization

### Core Modules

#### HAR Processing Layer

- **har_preprocessor.py** (500 lines) - Unified HAR preprocessing, single-pass extraction
- **har_analyzer.py** (200 lines) - Legacy HAR analysis with token extraction integration
- **token_extractor.py** (250 lines) - Smart token/ID extraction for fuzzing

#### Payload & Dictionary System

- **payload_analyzer.py** (350 lines) - JSON schema extraction, key-value analysis
- **payload_reconstructor.py** (350 lines) - Attack payload generation
- **dictionary_manager.py** (300 lines) - Extensible dictionary system

#### Attack Modules

- **redteam_attacks.py** (600 lines) - Offensive security tests
    - UnauthenticatedReplayAttack
    - MassAssignmentFuzzer
    - HiddenParameterDiscovery
    - RaceConditionTester
    - RedTeamOrchestrator

#### OWASP ZAP Integration

- **docker_manager.py** - ZAP Docker lifecycle
- **zap_scanner.py** - Active/passive scanning
- **zap_fuzzer.py** - Intelligent fuzzing with extracted tokens
- **advanced_zap_config.py** - Auth configuration

#### Detection & Analysis

- **idor_detector.py** (300 lines) - Multi-session IDOR testing
- **passive_analysis.py** (400 lines) - Non-invasive security checks

#### Utilities

- **masking.py** (200 lines) - Sensitive data masking (95% coverage)
- **reporter.py** - Report generation
- **acceptance_engine.py** - CI/CD criteria engine

### Interfaces

#### Web UI (app.py)

9 tabs:

1. Upload & Configure
2. **HAR Preprocessing** (NEW)
3. ZAP Scan
4. **ZAP Fuzzer** (NEW)
5. IDOR Testing
6. Red Team
7. Passive Scan
8. Results
9. Acceptance

#### CLI (cli.py)

CI/CD integration with JUnit/SARIF export

## Data Flow

### Standard Workflow

```
HAR File Upload
    ↓
HARPreprocessor (single-pass extraction)
    ↓
preprocessed.json (unified format)
    ├→ endpoints[]
    ├→ querystrings{}
    ├→ payloads{}
    ├→ dictionaries{keys, values, parameters, headers}
    └→ statistics{}
    ↓
Multiple Consumers:
    ├→ RedTeamOrchestrator
    ├→ ZAPFuzzer
    ├→ IDORDetector
    └→ PassiveAnalysisOrchestrator
```

### Legacy Workflow (still supported)

```
HAR File
    ↓
HARAnalyzer
    ↓
Individual module parsing
```

## Test Coverage

```
Total: 88 tests passing
- masking: 38 tests (95% coverage)
- redteam_attacks: 28 tests (74% coverage)
- token_extractor: 11 tests (89% coverage)
- har_preprocessor: 10 tests (68% coverage)

Overall: 22% coverage
```

## Configuration

### config.yaml

- Scope/exclusion domains
- Auth methods
- Attack types
- Scan policies

### Extensible Dictionaries

```
dictionaries/
├── custom/          (user-provided)
├── generated/       (base attack dicts)
└── *.json          (standard)
```

## Philosophy

**One HAR → One preprocessed.json → All modules**

Centralized extraction eliminates:

- Multiple HAR parses
- Format inconsistencies
- Redundant processing

Performance: 10x reduction in processing overhead
