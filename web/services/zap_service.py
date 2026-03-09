"""
ZAP Service

Orchestrates ZAP container lifecycle and scan operations.
Wrapper around existing modules for web interface.
"""
import time
from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from zapv2 import ZAPv2

# Import existing modules
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from modules.docker_manager import DockerZAPManager
from modules.zap_scanner import ZAPScanner
from modules.zap_http_client import ZAPHttpClient


class ZAPService:
    """Orchestrate ZAP container and scanning operations"""

    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.docker_manager: Optional[DockerZAPManager] = None
        self.scanner: Optional[ZAPScanner] = None
        self.http_client: Optional[ZAPHttpClient] = None
        self.zap: Optional['ZAPv2'] = None
        self._zap_config: Optional[Dict] = None

    @property
    def is_running(self) -> bool:
        """Check if ZAP is running (managed or external)"""
        if self.docker_manager and self.docker_manager.container:
            return True
        # Check for external ZAP
        return self._check_external_zap()

    def _check_external_zap(self) -> bool:
        """Check if ZAP is running externally"""
        try:
            import requests
            port = self.config.get('zap_port', 8080)
            resp = requests.get(f'http://127.0.0.1:{port}/JSON/core/view/version/', timeout=2)
            return resp.status_code == 200
        except Exception:
            return False

    def start(self, config: Dict = None) -> Dict:
        """Start ZAP Docker container"""
        config = config or self.config

        if self.is_running:
            return self._zap_config

        self.docker_manager = DockerZAPManager(
            port=config.get('zap_port', 8080),
            image=config.get('zap_image', 'ghcr.io/zaproxy/zaproxy:stable')
        )

        self._zap_config = self.docker_manager.start_zap()

        # Initialize HTTP client
        self.http_client = ZAPHttpClient(
            zap_url=self._zap_config['zap_url'],
            api_key=self._zap_config['api_key']
        )

        return self._zap_config

    def stop(self) -> bool:
        """Stop ZAP container"""
        if not self.docker_manager:
            return False

        try:
            self.docker_manager.stop_zap()
            self.docker_manager = None
            self.scanner = None
            self.http_client = None
            self._zap_config = None
            return True
        except Exception:
            return False

    def _get_zap_connection(self):
        """Get ZAP connection details (managed or external)"""
        if self._zap_config:
            return self._zap_config
        # External ZAP defaults
        port = self.config.get('zap_port', 8080)
        return {
            'zap_url': f'http://127.0.0.1:{port}',
            'api_key': ''
        }

    def get_status(self) -> Dict:
        """Get comprehensive ZAP status"""
        if not self.is_running:
            return {
                'running': False,
                'version': None,
                'alerts_count': 0,
                'urls_count': 0
            }

        try:
            from zapv2 import ZAPv2
            conn = self._get_zap_connection()
            zap = ZAPv2(
                apikey=conn.get('api_key', ''),
                proxies={'http': conn['zap_url'], 'https': conn['zap_url']}
            )

            return {
                'running': True,
                'version': zap.core.version,
                'alerts_count': len(zap.core.alerts()),
                'urls_count': len(zap.core.urls()),
                'zap_url': conn['zap_url'],
                'api_key': 'external' if not self._zap_config else conn['api_key'][:8] + '...'
            }
        except Exception as e:
            return {
                'running': True,
                'version': 'unknown',
                'error': str(e)
            }

    def get_logs(self, lines: int = 50) -> str:
        """Get ZAP container logs"""
        if not self.docker_manager:
            return ""
        return self.docker_manager.get_logs(tail=lines)

    def get_alerts(self, risk: str = None) -> List[Dict]:
        """Get ZAP alerts, optionally filtered by risk"""
        if not self.is_running:
            return []

        try:
            from zapv2 import ZAPv2
            conn = self._get_zap_connection()
            zap = ZAPv2(
                apikey=conn.get('api_key', ''),
                proxies={'http': conn['zap_url'], 'https': conn['zap_url']}
            )

            alerts = zap.core.alerts()

            if risk:
                alerts = [a for a in alerts if a.get('risk', '').lower() == risk.lower()]

            return alerts
        except Exception:
            return []

    def get_active_scans(self) -> List[Dict]:
        """Get list of active scans with progress"""
        if not self.is_running:
            return []

        try:
            from zapv2 import ZAPv2
            conn = self._get_zap_connection()
            zap = ZAPv2(
                apikey=conn.get('api_key', ''),
                proxies={'http': conn['zap_url'], 'https': conn['zap_url']}
            )

            scans = []
            # Get active scan status
            scan_ids = zap.ascan.scans
            for scan in scan_ids:
                scans.append({
                    'id': scan.get('id'),
                    'progress': int(scan.get('progress', 0)),
                    'state': scan.get('state'),
                    'alerts_count': scan.get('alertCount', 0)
                })

            return scans
        except Exception:
            return []

    def start_scan(self, url: str, scan_type: str = "active", policy: str = None) -> Optional[Dict]:
        """Start a scan on URL

        Args:
            url: Target URL
            scan_type: spider, active, or full (spider + active)
            policy: Scan policy name (optional)
        """
        if not self.is_running:
            return None

        try:
            from zapv2 import ZAPv2
            conn = self._get_zap_connection()
            zap = ZAPv2(
                apikey=conn.get('api_key', ''),
                proxies={'http': conn['zap_url'], 'https': conn['zap_url']}
            )

            result = {'url': url, 'scan_type': scan_type}

            # Access URL first
            zap.core.access_url(url)
            time.sleep(1)

            # Spider
            if scan_type in ('spider', 'full'):
                spider_id = zap.spider.scan(url)
                result['spider_id'] = spider_id

                # Wait for spider if doing full scan
                if scan_type == 'full':
                    while int(zap.spider.status(spider_id)) < 100:
                        time.sleep(2)

            # Active scan
            if scan_type in ('active', 'full'):
                scan_id = zap.ascan.scan(url, scanpolicyname=policy if policy and policy != 'default' else None)
                result['scan_id'] = scan_id

            return result
        except Exception as e:
            return None

    def get_scan_progress(self, scan_id: str) -> Dict:
        """Get progress of a specific scan"""
        if not self.is_running:
            return {'progress': 0, 'state': 'stopped'}

        try:
            from zapv2 import ZAPv2
            conn = self._get_zap_connection()
            zap = ZAPv2(
                apikey=conn.get('api_key', ''),
                proxies={'http': conn['zap_url'], 'https': conn['zap_url']}
            )

            progress = int(zap.ascan.status(scan_id))
            alerts = zap.core.alerts()

            return {
                'progress': progress,
                'state': 'running' if progress < 100 else 'completed',
                'alerts': {
                    'high': len([a for a in alerts if a.get('risk') == 'High']),
                    'medium': len([a for a in alerts if a.get('risk') == 'Medium']),
                    'low': len([a for a in alerts if a.get('risk') == 'Low']),
                    'info': len([a for a in alerts if a.get('risk') == 'Informational'])
                }
            }
        except Exception:
            return {'progress': 0, 'state': 'error'}

    def stop_scan(self, scan_id: str) -> bool:
        """Stop an active scan"""
        if not self.is_running:
            return False

        try:
            from zapv2 import ZAPv2
            conn = self._get_zap_connection()
            zap = ZAPv2(
                apikey=conn.get('api_key', ''),
                proxies={'http': conn['zap_url'], 'https': conn['zap_url']}
            )

            zap.ascan.stop(scan_id)
            return True
        except Exception:
            return False

    def clear_session(self) -> bool:
        """Clear ZAP session (delete alerts, history)"""
        if not self.is_running:
            return False

        try:
            from zapv2 import ZAPv2
            conn = self._get_zap_connection()
            zap = ZAPv2(
                apikey=conn.get('api_key', ''),
                proxies={'http': conn['zap_url'], 'https': conn['zap_url']}
            )

            zap.core.delete_all_alerts()
            zap.core.new_session()
            return True
        except Exception:
            return False

    def get_http_client(self) -> Optional[ZAPHttpClient]:
        """Get ZAP HTTP client for routing requests"""
        if self.http_client:
            return self.http_client

        # Create client for external ZAP
        if self.is_running and not self.http_client:
            conn = self._get_zap_connection()
            self.http_client = ZAPHttpClient(
                zap_url=conn['zap_url'],
                api_key=conn.get('api_key', '')
            )

        return self.http_client

    @staticmethod
    def from_config(config: Dict) -> 'ZAPService':
        """Create ZAPService from config.yaml"""
        return ZAPService(config)
