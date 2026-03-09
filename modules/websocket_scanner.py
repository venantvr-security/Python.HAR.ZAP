"""
WebSocket Scanner - Authentication testing, message injection, CSWSH detection.
"""
import asyncio
import json
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .utils import get_logger

logger = get_logger("websocket.scanner")

WS_PATTERNS = [
    r'wss?://',
    r'socket\.io',
    r'sockjs',
    r'signalr',
]


@dataclass
class WebSocketEndpoint:
    url: str
    origin: Optional[str] = None
    protocols: List[str] = field(default_factory=list)
    requires_auth: bool = False
    messages_captured: List[Dict] = field(default_factory=list)


@dataclass
class WebSocketVulnerability:
    type: str
    endpoint: str
    severity: str
    description: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None


class WebSocketScanner:
    """Scanner for WebSocket endpoint security testing."""

    def __init__(self, har_data: Dict, config: Optional[Dict] = None, zap_client=None):
        self.har_data = har_data
        self.config = config or {}
        # Note: zap_client stored but WebSocket tests use websockets library directly
        # ZAP WebSocket passthrough requires separate configuration
        self.zap_client = zap_client
        self.endpoints: List[WebSocketEndpoint] = []
        self.vulnerabilities: List[WebSocketVulnerability] = []

        self.timeout = self.config.get('timeout', 30)
        self.max_messages = self.config.get('max_messages', 100)

    def detect_endpoints(self) -> List[WebSocketEndpoint]:
        """Detect WebSocket endpoints from HAR data."""
        logger.info("detecting_websocket_endpoints")
        detected = {}

        for entry in self.har_data.get('entries', []):
            request = entry.get('request', {})
            url = request.get('url', '')
            headers = {h['name'].lower(): h['value'] for h in request.get('headers', [])}

            # Check for WebSocket upgrade
            if headers.get('upgrade', '').lower() == 'websocket':
                ws_url = self._http_to_ws(url)
                if ws_url not in detected:
                    detected[ws_url] = WebSocketEndpoint(
                        url=ws_url,
                        origin=headers.get('origin'),
                        protocols=headers.get('sec-websocket-protocol', '').split(',')
                    )

            # Check URL patterns
            for pattern in WS_PATTERNS:
                if re.search(pattern, url, re.IGNORECASE):
                    ws_url = self._http_to_ws(url) if url.startswith('http') else url
                    if ws_url not in detected:
                        detected[ws_url] = WebSocketEndpoint(url=ws_url)

            # Check response for WebSocket indicators
            response = entry.get('response', {})
            if response.get('status') == 101:
                ws_url = self._http_to_ws(url)
                if ws_url not in detected:
                    detected[ws_url] = WebSocketEndpoint(url=ws_url)

        self.endpoints = list(detected.values())
        logger.info("websocket_endpoints_detected", count=len(self.endpoints))
        return self.endpoints

    def _http_to_ws(self, url: str) -> str:
        """Convert HTTP URL to WebSocket URL."""
        if url.startswith('https://'):
            return 'wss://' + url[8:]
        elif url.startswith('http://'):
            return 'ws://' + url[7:]
        return url

    async def test_authentication(self, endpoint: WebSocketEndpoint) -> Dict:
        """Test if WebSocket requires authentication."""
        logger.debug("testing_ws_auth", url=endpoint.url[:50])

        result = {
            'url': endpoint.url,
            'requires_auth': False,
            'accepts_any_origin': False
        }

        try:
            import websockets

            # Test without auth
            async with websockets.connect(
                endpoint.url,
                close_timeout=5,
                open_timeout=self.timeout
            ) as ws:
                # Try to receive a message
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=5)
                    result['initial_message'] = str(msg)[:200]
                except asyncio.TimeoutError:
                    pass

                result['connection_successful'] = True

        except Exception as e:
            error_msg = str(e).lower()
            if any(x in error_msg for x in ['401', '403', 'unauthorized', 'forbidden']):
                result['requires_auth'] = True
                endpoint.requires_auth = True
            result['error'] = str(e)

        return result

    async def test_origin_validation(self, endpoint: WebSocketEndpoint) -> Dict:
        """Test for Cross-Site WebSocket Hijacking (CSWSH)."""
        logger.debug("testing_cswsh", url=endpoint.url[:50])

        result = {
            'url': endpoint.url,
            'vulnerable': False,
            'tests': []
        }

        malicious_origins = [
            'https://evil.com',
            'https://attacker.com',
            'null',
            '',
        ]

        try:
            import websockets

            for origin in malicious_origins:
                try:
                    extra_headers = {'Origin': origin} if origin else {}
                    async with websockets.connect(
                        endpoint.url,
                        extra_headers=extra_headers,
                        close_timeout=5,
                        open_timeout=10
                    ) as ws:
                        result['tests'].append({
                            'origin': origin,
                            'accepted': True
                        })
                        result['vulnerable'] = True

                except Exception as e:
                    result['tests'].append({
                        'origin': origin,
                        'accepted': False,
                        'error': str(e)[:100]
                    })

        except ImportError:
            result['error'] = 'websockets library not installed'

        if result['vulnerable']:
            self.vulnerabilities.append(WebSocketVulnerability(
                type='CSWSH',
                endpoint=endpoint.url,
                severity='High',
                description='WebSocket accepts connections from arbitrary origins',
                remediation='Implement strict Origin header validation'
            ))

        return result

    async def fuzz_messages(
        self,
        endpoint: WebSocketEndpoint,
        payloads: List[str]
    ) -> List[Dict]:
        """Fuzz WebSocket messages with payloads."""
        logger.info("fuzzing_ws_messages", url=endpoint.url[:50], payloads=len(payloads))
        results = []

        try:
            import websockets

            async with websockets.connect(
                endpoint.url,
                close_timeout=5,
                open_timeout=self.timeout
            ) as ws:
                for payload in payloads[:self.max_messages]:
                    try:
                        await ws.send(payload)
                        response = await asyncio.wait_for(ws.recv(), timeout=5)

                        result = {
                            'payload': payload[:100],
                            'response': str(response)[:500],
                            'interesting': False
                        }

                        # Check for interesting responses
                        resp_lower = str(response).lower()
                        if any(x in resp_lower for x in ['error', 'exception', 'sql', 'syntax']):
                            result['interesting'] = True

                        results.append(result)

                    except asyncio.TimeoutError:
                        results.append({
                            'payload': payload[:100],
                            'response': None,
                            'timeout': True
                        })
                    except Exception as e:
                        results.append({
                            'payload': payload[:100],
                            'error': str(e)[:200]
                        })

        except ImportError:
            logger.error("websockets_not_installed")
        except Exception as e:
            logger.error("ws_fuzz_error", error=str(e))

        return results

    async def test_injection(self, endpoint: WebSocketEndpoint) -> List[Dict]:
        """Test for injection vulnerabilities in WebSocket messages."""
        injection_payloads = [
            # SQL
            "' OR '1'='1",
            "1; DROP TABLE users--",
            # XSS
            "<script>alert(1)</script>",
            # Command
            "; id",
            "| whoami",
            # JSON injection
            '{"__proto__": {"admin": true}}',
            '{"constructor": {"prototype": {"admin": true}}}',
            # NoSQL
            '{"$ne": null}',
            '{"$gt": ""}',
        ]

        return await self.fuzz_messages(endpoint, injection_payloads)

    def scan_all_sync(self) -> Dict[str, Any]:
        """Run full WebSocket security scan (synchronous wrapper)."""
        return asyncio.get_event_loop().run_until_complete(self.scan_all())

    async def scan_all(self) -> Dict[str, Any]:
        """Run full WebSocket security scan."""
        logger.info("websocket_scan_start")

        if not self.endpoints:
            self.detect_endpoints()

        results = {
            'endpoints': [],
            'vulnerabilities': [],
            'summary': {}
        }

        for endpoint in self.endpoints:
            endpoint_result = {
                'url': endpoint.url,
                'auth_test': None,
                'origin_test': None,
                'injection_tests': []
            }

            # Auth test
            endpoint_result['auth_test'] = await self.test_authentication(endpoint)

            # CSWSH test
            endpoint_result['origin_test'] = await self.test_origin_validation(endpoint)

            # Injection test
            endpoint_result['injection_tests'] = await self.test_injection(endpoint)

            results['endpoints'].append(endpoint_result)

        results['vulnerabilities'] = [
            {
                'type': v.type,
                'endpoint': v.endpoint,
                'severity': v.severity,
                'description': v.description,
                'remediation': v.remediation
            }
            for v in self.vulnerabilities
        ]

        results['summary'] = {
            'total_endpoints': len(self.endpoints),
            'require_auth': sum(1 for e in self.endpoints if e.requires_auth),
            'vulnerabilities_found': len(self.vulnerabilities)
        }

        logger.info("websocket_scan_complete", **results['summary'])
        return results
