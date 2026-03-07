"""
Configuration loader with environment variable overrides.
Prefix: HARZAP_
"""
import os
from pathlib import Path
from typing import Dict, Any, Optional

import yaml

from .utils import ConfigError, get_logger

logger = get_logger(__name__)

# Environment variable mappings: ENV_VAR -> (config_key, type_converter)
ENV_MAPPING = {
    'HARZAP_ZAP_PORT': ('zap_port', int),
    'HARZAP_ZAP_IMAGE': ('zap_image', str),
    'HARZAP_ZAP_URL': ('zap_url', str),
    'HARZAP_API_KEY': ('api_key', str),
    'HARZAP_MAX_SCAN_TIME': ('max_scan_time', int),
    'HARZAP_MAX_URLS': ('max_urls', int),
    'HARZAP_MAX_WORKERS': ('max_workers', int),
    'HARZAP_RATE_LIMIT': ('rate_limit', float),
    'HARZAP_RATE_BURST': ('rate_burst', int),
    'HARZAP_DEBUG': ('debug', lambda x: x.lower() in ('true', '1', 'yes')),
    'HARZAP_LOG_LEVEL': ('log_level', str),
    'HARZAP_LOG_JSON': ('log_json', lambda x: x.lower() in ('true', '1', 'yes')),
    'HARZAP_WEBHOOK_URL': ('webhook_url', str),
    'HARZAP_INCREMENTAL': ('incremental', lambda x: x.lower() in ('true', '1', 'yes')),
}

# TOR/Proxy environment variable mappings (nested config)
TOR_ENV_MAPPING = {
    'HARZAP_TOR_ENABLED': ('proxy_chain', 'enabled', lambda x: x.lower() in ('true', '1', 'yes')),
    'HARZAP_TOR_HOST': ('proxy_chain', 'host', str),
    'HARZAP_TOR_PORT': ('proxy_chain', 'port', int),
    'HARZAP_TOR_TYPE': ('proxy_chain', 'type', str),
    'HARZAP_TOR_USERNAME': ('proxy_chain', 'username', str),
    'HARZAP_TOR_PASSWORD': ('proxy_chain', 'password', str),
    'HARZAP_TOR_CONTROL_PORT': ('tor', 'control_port', int),
    'HARZAP_TOR_CONTROL_PASSWORD': ('tor', 'control_password', str),
    'HARZAP_TOR_NEW_CIRCUIT_PER_SCAN': ('tor', 'new_circuit_per_scan', lambda x: x.lower() in ('true', '1', 'yes')),
}

DEFAULT_CONFIG = {
    'zap_port': 8080,
    'zap_image': 'ghcr.io/zaproxy/zaproxy:stable',
    'max_scan_time': 300,
    'max_urls': 100,
    'max_workers': 10,
    'rate_limit': 10.0,
    'rate_burst': 20,
    'debug': False,
    'log_level': 'INFO',
    'scan_fuzzable_urls': True,
    'scan_api_endpoints': True,
    'incremental': False,
    'exclude_domains': [
        'google-analytics.com', 'googletagmanager.com', 'facebook.com',
        'doubleclick.net', 'cdn.jsdelivr.net', 'fonts.googleapis.com'
    ],
    'allowed_methods': ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    'alert_thresholds': {'high': 5, 'medium': 10, 'low': 20},
}


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration with priority:
    1. Environment variables (highest)
    2. Config file
    3. Defaults (lowest)
    """
    config = DEFAULT_CONFIG.copy()

    # Load from file
    if config_path:
        path = Path(config_path)
        if path.exists():
            try:
                with open(path) as f:
                    file_config = yaml.safe_load(f) or {}
                config = _deep_merge(config, file_config)
                logger.info("config_loaded", path=str(path))
            except Exception as e:
                raise ConfigError(f"Failed to load config: {e}")
    else:
        # Try default locations
        for default_path in ['config.yaml', 'config.yml', '.harzap.yaml']:
            if Path(default_path).exists():
                with open(default_path) as f:
                    file_config = yaml.safe_load(f) or {}
                config = _deep_merge(config, file_config)
                logger.info("config_loaded", path=default_path)
                break

    # Apply environment overrides
    for env_var, (config_key, converter) in ENV_MAPPING.items():
        if env_var in os.environ:
            try:
                config[config_key] = converter(os.environ[env_var])
                logger.debug("env_override", key=config_key, source=env_var)
            except ValueError as e:
                logger.warning("env_parse_error", var=env_var, error=str(e))

    # Apply TOR/Proxy environment overrides (nested)
    for env_var, (section, key, converter) in TOR_ENV_MAPPING.items():
        if env_var in os.environ:
            try:
                if section not in config:
                    config[section] = {}
                config[section][key] = converter(os.environ[env_var])
                logger.debug("env_override", key=f"{section}.{key}", source=env_var)
            except ValueError as e:
                logger.warning("env_parse_error", var=env_var, error=str(e))

    return config


def _deep_merge(base: Dict, override: Dict) -> Dict:
    """Deep merge two dictionaries."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def get_zap_config(config: Dict) -> Dict[str, Any]:
    """Extract ZAP-specific config."""
    return {
        'zap_url': config.get('zap_url', f"http://127.0.0.1:{config['zap_port']}"),
        'api_key': config.get('api_key', ''),
        'zap_port': config['zap_port'],
        'zap_image': config['zap_image'],
    }


def get_scan_config(config: Dict) -> Dict[str, Any]:
    """Extract scan-specific config."""
    return {
        'max_scan_time': config['max_scan_time'],
        'max_urls': config['max_urls'],
        'scan_fuzzable_urls': config['scan_fuzzable_urls'],
        'scan_api_endpoints': config['scan_api_endpoints'],
        'exclude_domains': config['exclude_domains'],
        'allowed_methods': config['allowed_methods'],
        'alert_thresholds': config['alert_thresholds'],
        'incremental': config.get('incremental', False),
    }


def get_rate_limiter_config(config: Dict) -> Dict[str, Any]:
    """Extract rate limiter config."""
    return {
        'requests_per_second': config['rate_limit'],
        'burst': config['rate_burst'],
    }


def get_tor_config(config: Dict) -> Dict[str, Any]:
    """Extract TOR/proxy config."""
    proxy_chain = config.get('proxy_chain', {})
    tor = config.get('tor', {})

    return {
        'enabled': proxy_chain.get('enabled', False),
        'type': proxy_chain.get('type', 'socks5'),
        'host': proxy_chain.get('host', '127.0.0.1'),
        'port': proxy_chain.get('port', 9050),
        'username': proxy_chain.get('username', ''),
        'password': proxy_chain.get('password', ''),
        'control_port': tor.get('control_port', 9051),
        'control_password': tor.get('control_password', ''),
        'new_circuit_per_scan': tor.get('new_circuit_per_scan', False),
        'verify_connection': tor.get('verify_connection', True),
    }
