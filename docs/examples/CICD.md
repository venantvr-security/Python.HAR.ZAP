# CI/CD Integration Guide

[← Back to Index](../README.md)

---

## GitHub Actions

### Basic Workflow

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run Security Scan
        env:
          HARZAP_LOG_JSON: true
        run: |
          python cli.py scan traffic.har \
            --fail-fast \
            --max-high 0 \
            --format sarif \
            --output results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: results.sarif
```

### With Docker Service

```yaml
jobs:
  security-scan:
    runs-on: ubuntu-latest

    services:
      zap:
        image: ghcr.io/zaproxy/zaproxy:stable
        ports:
          - 8080:8080
        options: >-
          --entrypoint zap.sh
          -e ZAP_PORT=8080

    steps:
      - uses: actions/checkout@v4

      - name: Wait for ZAP
        run: |
          timeout 60 bash -c 'until curl -s http://localhost:8080; do sleep 2; done'

      - name: Run Scan
        run: |
          python cli.py scan traffic.har \
            --no-docker \
            --zap-url http://localhost:8080 \
            --fail-fast
```

### IDOR Testing in PR

```yaml
name: IDOR Check

on:
  pull_request:
    paths:
      - 'api/**'

jobs:
  idor-check:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Run IDOR Detection
        run: |
          python cli.py idor \
            --session-a tests/fixtures/admin.har \
            --session-b tests/fixtures/user.har \
            --fail-on-idor

      - name: Upload Results
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: idor-results
          path: output/idor_results.json
```

---

## GitLab CI

### Basic Pipeline

```yaml
# .gitlab-ci.yml
stages:
  - test
  - security

security-scan:
  stage: security
  image: python:3.11

  services:
    - name: ghcr.io/zaproxy/zaproxy:stable
      alias: zap
      entrypoint: ["zap.sh"]
      command: ["-daemon", "-port", "8080", "-host", "0.0.0.0", "-config", "api.disablekey=true"]

  script:
    - pip install -r requirements.txt
    - |
      python cli.py scan traffic.har \
        --no-docker \
        --zap-url http://zap:8080 \
        --fail-fast \
        --max-high 0 \
        --format sarif

  artifacts:
    reports:
      sast: results.sarif
    paths:
      - output/
    when: always

  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
```

### Incremental Scanning

```yaml
incremental-scan:
  stage: security

  cache:
    key: harzap-cache
    paths:
      - .harzap_cache.db

  script:
    - python cli.py scan traffic.har --incremental --fail-fast
```

---

## Jenkins

### Jenkinsfile

```groovy
pipeline {
    agent any

    environment {
        HARZAP_LOG_JSON = 'true'
    }

    stages {
        stage('Setup') {
            steps {
                sh 'pip install -r requirements.txt'
            }
        }

        stage('Security Scan') {
            steps {
                sh '''
                    python cli.py scan traffic.har \
                        --fail-fast \
                        --max-high 0 \
                        --format junit \
                        --output results/
                '''
            }
            post {
                always {
                    junit 'results/junit.xml'
                    archiveArtifacts artifacts: 'results/*'
                }
            }
        }
    }

    post {
        failure {
            slackSend(
                color: 'danger',
                message: "Security scan failed: ${env.BUILD_URL}"
            )
        }
    }
}
```

---

## Azure DevOps

```yaml
# azure-pipelines.yml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.11'

  - script: pip install -r requirements.txt
    displayName: 'Install dependencies'

  - script: |
      python cli.py scan traffic.har \
        --fail-fast \
        --max-high 0 \
        --format sarif \
        --output $(Build.ArtifactStagingDirectory)
    displayName: 'Security Scan'
    env:
      HARZAP_LOG_JSON: true

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: $(Build.ArtifactStagingDirectory)
      artifactName: security-results
    condition: always()
```

---

## CircleCI

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: cimg/python:3.11
      - image: ghcr.io/zaproxy/zaproxy:stable
        command: ["zap.sh", "-daemon", "-port", "8080", "-host", "0.0.0.0", "-config", "api.disablekey=true"]

    steps:
      - checkout
      - run: pip install -r requirements.txt
      - run:
          name: Wait for ZAP
          command: timeout 60 bash -c 'until curl -s http://localhost:8080; do sleep 2; done'
      - run:
          name: Run Scan
          command: |
            python cli.py scan traffic.har \
              --no-docker \
              --zap-url http://localhost:8080 \
              --fail-fast
      - store_artifacts:
          path: output/

workflows:
  security:
    jobs:
      - security-scan
```

---

## Best Practices

### 1. Cache Incremental Database

```yaml
# GitHub Actions
- uses: actions/cache@v3
  with:
    path: .harzap_cache.db
    key: harzap-cache-${{ github.ref }}
```

### 2. Use SARIF for Security Tab

```yaml
- uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### 3. Notify on Critical Findings

```yaml
- name: Notify Slack
  if: failure()
  uses: slackapi/slack-github-action@v1
  with:
    webhook: ${{ secrets.SLACK_WEBHOOK }}
    payload: |
      {"text": "Security scan failed!"}
```

### 4. Gate PRs on Security

```yaml
# Require passing security check
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    steps:
      - run: python cli.py scan pr.har --fail-fast --max-high 0
```

---

## Next Steps

→ [GraphQL Testing](GRAPHQL.md)
