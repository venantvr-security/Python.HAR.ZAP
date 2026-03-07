"""
TOR Proxy Service

Manages TOR SOCKS5 proxy integration for anonymous scanning.
Routes ZAP traffic through TOR network.
"""
import socket
import struct
from typing import Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from modules.advanced_zap_config import AdvancedZAPConfig


class TORService:
    """Manage TOR proxy connection and ZAP integration"""

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 9050
    DEFAULT_CONTROL_PORT = 9051
    CHECK_IP_URL = "https://check.torproject.org/api/ip"

    def __init__(self, config: Dict = None):
        config = config or {}
        self.host = config.get('host', self.DEFAULT_HOST)
        self.port = config.get('port', self.DEFAULT_PORT)
        self.control_port = config.get('control_port', self.DEFAULT_CONTROL_PORT)
        self.control_password = config.get('control_password', '')
        self._connected = False

    def check_connection(self) -> bool:
        """Test SOCKS5 connection to TOR daemon"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.host, self.port))

            # SOCKS5 handshake (no auth)
            sock.send(b'\x05\x01\x00')
            response = sock.recv(2)

            sock.close()
            self._connected = response == b'\x05\x00'
            return self._connected
        except Exception:
            self._connected = False
            return False

    def get_exit_ip(self) -> Optional[str]:
        """Get current TOR exit node IP via check.torproject.org"""
        try:
            import socks
            import socket as std_socket

            # Create SOCKS5 socket
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, self.host, self.port)
            sock.settimeout(10)

            # Connect to check.torproject.org
            sock.connect(("check.torproject.org", 443))

            # Simple HTTPS request
            import ssl
            context = ssl.create_default_context()
            wrapped = context.wrap_socket(sock, server_hostname="check.torproject.org")

            request = (
                "GET /api/ip HTTP/1.1\r\n"
                "Host: check.torproject.org\r\n"
                "Connection: close\r\n\r\n"
            )
            wrapped.send(request.encode())

            response = b""
            while True:
                chunk = wrapped.recv(4096)
                if not chunk:
                    break
                response += chunk

            wrapped.close()

            # Parse response
            body = response.split(b'\r\n\r\n', 1)[-1].decode()
            import json
            data = json.loads(body)
            return data.get('IP')

        except ImportError:
            # PySocks not installed, try alternative
            return self._get_exit_ip_requests()
        except Exception:
            return None

    def _get_exit_ip_requests(self) -> Optional[str]:
        """Fallback using requests with SOCKS proxy"""
        try:
            import requests
            proxies = {
                'http': f'socks5h://{self.host}:{self.port}',
                'https': f'socks5h://{self.host}:{self.port}'
            }
            resp = requests.get(self.CHECK_IP_URL, proxies=proxies, timeout=10)
            return resp.json().get('IP')
        except Exception:
            return None

    def new_circuit(self) -> bool:
        """Request new TOR circuit via control port (NEWNYM signal)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.host, self.control_port))

            # Authenticate
            if self.control_password:
                sock.send(f'AUTHENTICATE "{self.control_password}"\r\n'.encode())
            else:
                sock.send(b'AUTHENTICATE\r\n')

            response = sock.recv(1024).decode()
            if '250' not in response:
                sock.close()
                return False

            # Request new circuit
            sock.send(b'SIGNAL NEWNYM\r\n')
            response = sock.recv(1024).decode()

            sock.close()
            return '250' in response
        except Exception:
            return False

    def configure_zap_proxy(self, zap_config: 'AdvancedZAPConfig') -> bool:
        """Configure ZAP to route traffic through TOR"""
        try:
            zap_config.configure_proxy_chain({
                'enabled': True,
                'host': self.host,
                'port': self.port,
                'type': 'socks5',
                'username': '',
                'password': ''
            })
            return True
        except Exception:
            return False

    def disable_zap_proxy(self, zap_config: 'AdvancedZAPConfig') -> bool:
        """Disable TOR proxy in ZAP"""
        try:
            zap_config.configure_proxy_chain({
                'enabled': False,
                'host': '',
                'port': 0
            })
            return True
        except Exception:
            return False

    def get_status(self) -> Dict:
        """Get comprehensive TOR status"""
        connected = self.check_connection()
        exit_ip = self.get_exit_ip() if connected else None

        return {
            'connected': connected,
            'host': self.host,
            'port': self.port,
            'control_port': self.control_port,
            'exit_ip': exit_ip,
            'tor_detected': exit_ip is not None
        }

    @staticmethod
    def from_config(config: Dict) -> 'TORService':
        """Create TORService from config.yaml structure"""
        proxy_chain = config.get('proxy_chain', {})
        tor_config = config.get('tor', {})

        return TORService({
            'host': proxy_chain.get('host', TORService.DEFAULT_HOST),
            'port': proxy_chain.get('port', TORService.DEFAULT_PORT),
            'control_port': tor_config.get('control_port', TORService.DEFAULT_CONTROL_PORT),
            'control_password': tor_config.get('control_password', '')
        })
