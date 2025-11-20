import secrets
import time
from typing import Optional

import docker


class DockerZAPManager:
    DEFAULT_IMAGE = 'ghcr.io/zaproxy/zaproxy:stable'
    DEFAULT_PORT = 8080
    STARTUP_TIMEOUT = 60

    def __init__(self, config: dict):
        self.config = config
        self.client = docker.from_env()
        # noinspection PyUnresolvedReferences
        self.container: Optional[docker.models.containers.Container] = None
        self.api_key = secrets.token_hex(16)
        self.zap_port = config.get('zap_port', self.DEFAULT_PORT)
        self.image = config.get('zap_image', self.DEFAULT_IMAGE)

    def start_zap(self) -> dict:
        print(f"[Docker] Pulling image: {self.image}")
        try:
            self.client.images.pull(self.image)
        except Exception as e:
            print(f"[Docker] Warning: {e}. Using local image if available.")

        print(f"[Docker] Starting ZAP container on port {self.zap_port}")

        self.container = self.client.containers.run(
            self.image,
            command=f"zap.sh -daemon -host 0.0.0.0 -port {self.zap_port} -config api.key={self.api_key} -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true",
            ports={f'{self.zap_port}/tcp': ('127.0.0.1', self.zap_port)},
            detach=True,
            remove=False,
            name=f"zap-scanner-{int(time.time())}"
        )

        print(f"[Docker] Container started: {self.container.short_id}")
        self._wait_for_zap()

        return {
            'container_id': self.container.id,
            'api_key': self.api_key,
            'zap_url': f'http://localhost:{self.zap_port}',
            'port': self.zap_port
        }

    def _wait_for_zap(self):
        print("[Docker] Waiting for ZAP to start...")
        import requests

        start_time = time.time()
        while time.time() - start_time < self.STARTUP_TIMEOUT:
            try:
                response = requests.get(
                    f'http://localhost:{self.zap_port}/JSON/core/view/version/',
                    params={'apikey': self.api_key},
                    timeout=2
                )
                if response.status_code == 200:
                    version = response.json().get('version', 'unknown')
                    print(f"[Docker] ZAP ready (version: {version})")
                    return
            except Exception:  # Broad exception for robustness
                pass

            time.sleep(2)

        raise TimeoutError(f"ZAP did not start within {self.STARTUP_TIMEOUT} seconds")

    def stop_zap(self):
        if self.container:
            print(f"[Docker] Stopping container: {self.container.short_id}")
            try:
                self.container.stop(timeout=10)
                self.container.remove()
                print("[Docker] Container stopped and removed")
            except Exception as e:
                print(f"[Docker] Error stopping container: {e}")

    def get_logs(self, tail: int = 50) -> str:
        if self.container:
            return self.container.logs(tail=tail).decode('utf-8')
        return ""

    def __enter__(self):
        return self.start_zap()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop_zap()
