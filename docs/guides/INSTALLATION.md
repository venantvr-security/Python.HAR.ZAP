# Installation Guide

[← Back to Index](../README.md) | [Next: Configuration →](CONFIGURATION.md)

---

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| Python | 3.9+ | 3.11+ |
| RAM | 4 GB | 8 GB |
| Docker | 20.10+ | Latest |
| Disk | 2 GB | 5 GB |

---

## Installation Methods

### Method 1: pip (Recommended)

```bash
# Clone repository
git clone https://github.com/your-repo/harzap.git
cd harzap

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Method 2: Docker Compose

```bash
# Clone and run
git clone https://github.com/your-repo/harzap.git
cd harzap
docker-compose up -d
```

---

## Dependencies

### Core Dependencies

```
zapv2>=0.0.22          # ZAP API client
docker>=7.0.0          # Container management
requests>=2.31.0       # HTTP client
pyyaml>=6.0            # Configuration
aiohttp>=3.9.0         # Async HTTP (WebSocket, race conditions)
```

### Optional Dependencies

```
websockets>=12.0       # WebSocket testing
structlog>=24.0        # Structured logging (optional)
```

### Install Optional

```bash
pip install websockets structlog
```

---

## Docker Setup

### Pull ZAP Image

```bash
docker pull ghcr.io/zaproxy/zaproxy:stable
```

### Verify Docker Access

```bash
docker run --rm ghcr.io/zaproxy/zaproxy:stable zap.sh -version
```

### Without Docker

If you can't use Docker, install ZAP natively:

```bash
# Ubuntu/Debian
sudo apt install zaproxy

# macOS
brew install zaproxy

# Start ZAP
zap.sh -daemon -port 8080 -config api.key=your-key
```

---

## Environment Variables

```bash
# Optional: Configure via environment
export HARZAP_ZAP_PORT=8080
export HARZAP_MAX_WORKERS=10
export HARZAP_RATE_LIMIT=10.0
export HARZAP_LOG_LEVEL=INFO
export HARZAP_LOG_JSON=true  # For CI/CD
```

---

## Verification

```bash
# Test installation
python -c "from modules.zap_scanner import ZAPScanner; print('OK')"

# Test CLI
python cli.py --version

# Test Docker (if using)
python -c "from modules.docker_manager import DockerZAPManager; print('OK')"
```

---

## Troubleshooting

### Docker Permission Denied

```bash
# Add user to docker group
sudo usermod -aG docker $USER
# Re-login or run: newgrp docker
```

### Port 8080 Already in Use

```bash
# Change port in config.yaml
zap_port: 8081

# Or via environment
export HARZAP_ZAP_PORT=8081
```

### Python Version Issues

```bash
# Use pyenv for version management
pyenv install 3.11.0
pyenv local 3.11.0
```

---

## Next Steps

→ [Configuration Guide](CONFIGURATION.md)
