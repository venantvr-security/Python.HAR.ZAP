"""Tests for config loader module"""
import os
import pytest
from unittest.mock import patch, mock_open

from modules.config_loader import (
    load_config,
    _deep_merge,
    get_zap_config,
    get_scan_config,
    get_rate_limiter_config,
    get_tor_config,
    DEFAULT_CONFIG,
    ENV_MAPPING,
    TOR_ENV_MAPPING,
)


class TestLoadConfig:
    """Test configuration loading"""

    def test_load_default_config(self):
        with patch.dict(os.environ, {}, clear=True):
            with patch('pathlib.Path.exists', return_value=False):
                config = load_config()

        assert config['zap_port'] == 8080
        assert config['max_scan_time'] == 300
        assert config['rate_limit'] == 10.0

    def test_load_config_from_file(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("zap_port: 9090\nmax_urls: 50")

        with patch.dict(os.environ, {}, clear=True):
            config = load_config(str(config_file))

        assert config['zap_port'] == 9090
        assert config['max_urls'] == 50

    def test_env_override_int(self):
        with patch.dict(os.environ, {'HARZAP_ZAP_PORT': '9999'}, clear=True):
            with patch('pathlib.Path.exists', return_value=False):
                config = load_config()

        assert config['zap_port'] == 9999

    def test_env_override_float(self):
        with patch.dict(os.environ, {'HARZAP_RATE_LIMIT': '5.5'}, clear=True):
            with patch('pathlib.Path.exists', return_value=False):
                config = load_config()

        assert config['rate_limit'] == 5.5

    def test_env_override_bool_true(self):
        with patch.dict(os.environ, {'HARZAP_DEBUG': 'true'}, clear=True):
            with patch('pathlib.Path.exists', return_value=False):
                config = load_config()

        assert config['debug'] is True

    def test_env_override_bool_yes(self):
        with patch.dict(os.environ, {'HARZAP_DEBUG': 'yes'}, clear=True):
            with patch('pathlib.Path.exists', return_value=False):
                config = load_config()

        assert config['debug'] is True

    def test_env_override_bool_1(self):
        with patch.dict(os.environ, {'HARZAP_DEBUG': '1'}, clear=True):
            with patch('pathlib.Path.exists', return_value=False):
                config = load_config()

        assert config['debug'] is True

    def test_env_override_string(self):
        with patch.dict(os.environ, {'HARZAP_ZAP_IMAGE': 'custom/zap:latest'}, clear=True):
            with patch('pathlib.Path.exists', return_value=False):
                config = load_config()

        assert config['zap_image'] == 'custom/zap:latest'

    def test_tor_env_override(self):
        with patch.dict(os.environ, {
            'HARZAP_TOR_ENABLED': 'true',
            'HARZAP_TOR_PORT': '9150'
        }, clear=True):
            with patch('pathlib.Path.exists', return_value=False):
                config = load_config()

        assert config['proxy_chain']['enabled'] is True
        assert config['proxy_chain']['port'] == 9150

    def test_invalid_env_value(self):
        with patch.dict(os.environ, {'HARZAP_ZAP_PORT': 'not_a_number'}, clear=True):
            with patch('pathlib.Path.exists', return_value=False):
                config = load_config()

        # Should use default when conversion fails
        assert config['zap_port'] == 8080

    def test_file_and_env_priority(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("zap_port: 9090")

        with patch.dict(os.environ, {'HARZAP_ZAP_PORT': '7777'}, clear=True):
            config = load_config(str(config_file))

        # Env should override file
        assert config['zap_port'] == 7777


class TestDeepMerge:
    """Test deep merge functionality"""

    def test_simple_merge(self):
        base = {'a': 1, 'b': 2}
        override = {'b': 3, 'c': 4}
        result = _deep_merge(base, override)

        assert result == {'a': 1, 'b': 3, 'c': 4}

    def test_nested_merge(self):
        base = {'a': {'x': 1, 'y': 2}, 'b': 3}
        override = {'a': {'y': 5, 'z': 6}}
        result = _deep_merge(base, override)

        assert result == {'a': {'x': 1, 'y': 5, 'z': 6}, 'b': 3}

    def test_override_dict_with_value(self):
        base = {'a': {'x': 1}}
        override = {'a': 'string'}
        result = _deep_merge(base, override)

        assert result == {'a': 'string'}

    def test_empty_override(self):
        base = {'a': 1, 'b': 2}
        result = _deep_merge(base, {})

        assert result == base


class TestGetZapConfig:
    """Test ZAP config extraction"""

    def test_get_zap_config(self):
        config = {
            'zap_port': 8080,
            'zap_image': 'zap:latest',
            'api_key': 'secret'
        }
        zap_config = get_zap_config(config)

        assert zap_config['zap_port'] == 8080
        assert zap_config['api_key'] == 'secret'
        assert 'zap_url' in zap_config

    def test_zap_url_generation(self):
        config = {'zap_port': 9090, 'zap_image': 'zap'}
        zap_config = get_zap_config(config)

        assert zap_config['zap_url'] == 'http://127.0.0.1:9090'

    def test_custom_zap_url(self):
        config = {
            'zap_port': 8080,
            'zap_image': 'zap',
            'zap_url': 'http://custom:1234'
        }
        zap_config = get_zap_config(config)

        assert zap_config['zap_url'] == 'http://custom:1234'


class TestGetScanConfig:
    """Test scan config extraction"""

    def test_get_scan_config(self):
        config = DEFAULT_CONFIG.copy()
        scan_config = get_scan_config(config)

        assert scan_config['max_scan_time'] == 300
        assert scan_config['max_urls'] == 100
        assert 'exclude_domains' in scan_config
        assert 'allowed_methods' in scan_config

    def test_incremental_default(self):
        config = DEFAULT_CONFIG.copy()
        scan_config = get_scan_config(config)

        assert scan_config['incremental'] is False


class TestGetRateLimiterConfig:
    """Test rate limiter config extraction"""

    def test_get_rate_limiter_config(self):
        config = {'rate_limit': 5.0, 'rate_burst': 10}
        rl_config = get_rate_limiter_config(config)

        assert rl_config['requests_per_second'] == 5.0
        assert rl_config['burst'] == 10


class TestGetTorConfig:
    """Test TOR config extraction"""

    def test_get_tor_config_defaults(self):
        config = {}
        tor_config = get_tor_config(config)

        assert tor_config['enabled'] is False
        assert tor_config['type'] == 'socks5'
        assert tor_config['port'] == 9050
        assert tor_config['control_port'] == 9051

    def test_get_tor_config_enabled(self):
        config = {
            'proxy_chain': {
                'enabled': True,
                'host': '10.0.0.1',
                'port': 9150
            },
            'tor': {
                'control_port': 9151,
                'new_circuit_per_scan': True
            }
        }
        tor_config = get_tor_config(config)

        assert tor_config['enabled'] is True
        assert tor_config['host'] == '10.0.0.1'
        assert tor_config['port'] == 9150
        assert tor_config['control_port'] == 9151
        assert tor_config['new_circuit_per_scan'] is True


class TestEnvMappings:
    """Test environment variable mappings"""

    def test_env_mapping_keys(self):
        assert 'HARZAP_ZAP_PORT' in ENV_MAPPING
        assert 'HARZAP_RATE_LIMIT' in ENV_MAPPING
        assert 'HARZAP_DEBUG' in ENV_MAPPING

    def test_tor_env_mapping_keys(self):
        assert 'HARZAP_TOR_ENABLED' in TOR_ENV_MAPPING
        assert 'HARZAP_TOR_PORT' in TOR_ENV_MAPPING
        assert 'HARZAP_TOR_CONTROL_PORT' in TOR_ENV_MAPPING
