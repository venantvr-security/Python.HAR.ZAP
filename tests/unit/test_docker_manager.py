"""Tests for Docker manager module"""
import pytest
from unittest.mock import Mock, patch, MagicMock

pytest.importorskip("docker")
from modules.docker_manager import DockerZAPManager


@pytest.fixture
def config():
    return {
        'zap_port': 8080,
        'zap_image': 'ghcr.io/zaproxy/zaproxy:stable'
    }


@pytest.fixture
def mock_docker_client():
    client = Mock()
    client.images = Mock()
    client.containers = Mock()
    return client


class TestDockerZAPManager:
    """Test Docker ZAP management"""

    def test_init(self, config):
        with patch('docker.from_env') as mock_docker:
            manager = DockerZAPManager(config)

        assert manager.zap_port == 8080
        assert manager.image == 'ghcr.io/zaproxy/zaproxy:stable'
        assert len(manager.api_key) == 32  # 16 bytes hex

    def test_init_custom_port(self):
        config = {'zap_port': 9090}

        with patch('docker.from_env'):
            manager = DockerZAPManager(config)

        assert manager.zap_port == 9090

    def test_init_custom_image(self):
        config = {'zap_image': 'custom/zap:v1'}

        with patch('docker.from_env'):
            manager = DockerZAPManager(config)

        assert manager.image == 'custom/zap:v1'

    def test_start_zap_success(self, config, mock_docker_client):
        mock_container = Mock()
        mock_container.id = 'container123'
        mock_container.short_id = 'cont123'
        mock_docker_client.containers.run.return_value = mock_container

        with patch('docker.from_env', return_value=mock_docker_client):
            with patch.object(DockerZAPManager, '_wait_for_zap'):
                manager = DockerZAPManager(config)
                result = manager.start_zap()

        assert result['container_id'] == 'container123'
        assert result['port'] == 8080
        assert 'api_key' in result
        assert 'zap_url' in result
        mock_docker_client.images.pull.assert_called_once()
        mock_docker_client.containers.run.assert_called_once()

    def test_start_zap_pull_failure_uses_local(self, config, mock_docker_client):
        mock_container = Mock()
        mock_container.id = 'container123'
        mock_container.short_id = 'cont123'
        mock_docker_client.images.pull.side_effect = Exception("Network error")
        mock_docker_client.containers.run.return_value = mock_container

        with patch('docker.from_env', return_value=mock_docker_client):
            with patch.object(DockerZAPManager, '_wait_for_zap'):
                manager = DockerZAPManager(config)
                result = manager.start_zap()

        # Should still succeed using local image
        assert result['container_id'] == 'container123'

    def test_wait_for_zap_success(self, config, mock_docker_client):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'version': '2.14.0'}

        with patch('docker.from_env', return_value=mock_docker_client):
            with patch('requests.get', return_value=mock_response):
                manager = DockerZAPManager(config)
                manager._wait_for_zap()  # Should not raise

    def test_wait_for_zap_timeout(self, config, mock_docker_client):
        with patch('docker.from_env', return_value=mock_docker_client):
            with patch('requests.get', side_effect=Exception("Connection refused")):
                manager = DockerZAPManager(config)
                manager.STARTUP_TIMEOUT = 1  # Short timeout for test

                with pytest.raises(TimeoutError):
                    manager._wait_for_zap()

    def test_stop_zap(self, config, mock_docker_client):
        mock_container = Mock()
        mock_container.short_id = 'cont123'

        with patch('docker.from_env', return_value=mock_docker_client):
            manager = DockerZAPManager(config)
            manager.container = mock_container
            manager.stop_zap()

        mock_container.stop.assert_called_once_with(timeout=10)
        mock_container.remove.assert_called_once()

    def test_stop_zap_no_container(self, config, mock_docker_client):
        with patch('docker.from_env', return_value=mock_docker_client):
            manager = DockerZAPManager(config)
            manager.container = None
            manager.stop_zap()  # Should not raise

    def test_stop_zap_error_handling(self, config, mock_docker_client):
        mock_container = Mock()
        mock_container.short_id = 'cont123'
        mock_container.stop.side_effect = Exception("Stop failed")

        with patch('docker.from_env', return_value=mock_docker_client):
            manager = DockerZAPManager(config)
            manager.container = mock_container
            manager.stop_zap()  # Should not raise

    def test_get_logs(self, config, mock_docker_client):
        mock_container = Mock()
        mock_container.logs.return_value = b"ZAP started\nScanning..."

        with patch('docker.from_env', return_value=mock_docker_client):
            manager = DockerZAPManager(config)
            manager.container = mock_container
            logs = manager.get_logs(tail=10)

        assert logs == "ZAP started\nScanning..."
        mock_container.logs.assert_called_once_with(tail=10)

    def test_get_logs_no_container(self, config, mock_docker_client):
        with patch('docker.from_env', return_value=mock_docker_client):
            manager = DockerZAPManager(config)
            manager.container = None
            logs = manager.get_logs()

        assert logs == ""

    def test_context_manager(self, config, mock_docker_client):
        mock_container = Mock()
        mock_container.id = 'container123'
        mock_container.short_id = 'cont123'
        mock_docker_client.containers.run.return_value = mock_container

        with patch('docker.from_env', return_value=mock_docker_client):
            with patch.object(DockerZAPManager, '_wait_for_zap'):
                manager = DockerZAPManager(config)

                with manager as result:
                    assert 'container_id' in result

        mock_container.stop.assert_called_once()
        mock_container.remove.assert_called_once()

    def test_api_key_generation(self, config):
        with patch('docker.from_env'):
            manager1 = DockerZAPManager(config)
            manager2 = DockerZAPManager(config)

        # Each instance should have unique API key
        assert manager1.api_key != manager2.api_key


class TestDockerZAPManagerConstants:
    """Test manager constants"""

    def test_default_image(self):
        assert DockerZAPManager.DEFAULT_IMAGE == 'ghcr.io/zaproxy/zaproxy:stable'

    def test_default_port(self):
        assert DockerZAPManager.DEFAULT_PORT == 8080

    def test_startup_timeout(self):
        assert DockerZAPManager.STARTUP_TIMEOUT == 60
