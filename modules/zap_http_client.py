"""
Unified HTTP Client - All requests routed through ZAP
Provides centralized logging, alerting, and request replay capabilities
"""
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Union
from urllib.parse import urlparse

from zapv2 import ZAPv2


@dataclass
class ZAPResponse:
    """Unified response object"""
    status_code: int
    headers: Dict[str, str]
    content: bytes
    text: str
    elapsed: float
    url: str
    method: str
    request_id: Optional[int] = None  # ZAP message ID for replay


class ZAPHttpClient:
    """
    Unified HTTP client that routes all requests through ZAP.

    Benefits:
    - All traffic logged in ZAP history
    - Centralized alerting via ZAP
    - Request replay capability
    - Consistent proxy configuration
    - Session management
    """

    def __init__(self, zap: ZAPv2 = None, zap_url: str = 'http://localhost:8080',
                 api_key: str = '', timeout: int = 30):
        """
        Initialize ZAP HTTP Client.

        Args:
            zap: Existing ZAPv2 instance (optional)
            zap_url: ZAP API URL
            api_key: ZAP API key
            timeout: Request timeout in seconds
        """
        if zap:
            self.zap = zap
        else:
            self.zap = ZAPv2(apikey=api_key, proxies={
                'http': zap_url,
                'https': zap_url
            })

        self.zap_url = zap_url
        self.api_key = api_key
        self.timeout = timeout
        self._session_tokens = {}

    def _build_zap_request(self, method: str, url: str,
                           headers: Dict[str, str] = None,
                           data: Union[str, bytes, Dict] = None) -> str:
        """Build HTTP request string for ZAP sendRequest API"""
        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path or '/'
        if parsed.query:
            path += f'?{parsed.query}'

        # Build request line
        request_lines = [f"{method.upper()} {path} HTTP/1.1"]

        # Add Host header
        request_lines.append(f"Host: {host}")

        # Add custom headers
        if headers:
            for name, value in headers.items():
                if name.lower() != 'host':  # Skip duplicate Host
                    request_lines.append(f"{name}: {value}")

        # Add Content-Length and body for POST/PUT/PATCH
        body = ''
        if data:
            if isinstance(data, dict):
                import json
                body = json.dumps(data)
                if 'Content-Type' not in (headers or {}):
                    request_lines.append('Content-Type: application/json')
            elif isinstance(data, bytes):
                body = data.decode('utf-8', errors='ignore')
            else:
                body = str(data)

            request_lines.append(f"Content-Length: {len(body)}")

        # Build full request
        request_lines.append('')  # Empty line before body
        request_lines.append(body)

        return '\r\n'.join(request_lines)

    def _parse_zap_response(self, response_str: str, url: str,
                            method: str, elapsed: float) -> ZAPResponse:
        """Parse ZAP response string into ZAPResponse object"""
        if not response_str:
            return ZAPResponse(
                status_code=0,
                headers={},
                content=b'',
                text='',
                elapsed=elapsed,
                url=url,
                method=method
            )

        try:
            # Split headers and body
            if '\r\n\r\n' in response_str:
                header_section, body = response_str.split('\r\n\r\n', 1)
            elif '\n\n' in response_str:
                header_section, body = response_str.split('\n\n', 1)
            else:
                header_section = response_str
                body = ''

            # Parse status line
            lines = header_section.split('\n')
            status_line = lines[0].strip()
            status_code = int(status_line.split()[1]) if len(status_line.split()) > 1 else 0

            # Parse headers
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    name, value = line.split(':', 1)
                    headers[name.strip()] = value.strip()

            return ZAPResponse(
                status_code=status_code,
                headers=headers,
                content=body.encode('utf-8', errors='ignore'),
                text=body,
                elapsed=elapsed,
                url=url,
                method=method
            )

        except Exception as e:
            return ZAPResponse(
                status_code=0,
                headers={'error': str(e)},
                content=response_str.encode() if response_str else b'',
                text=response_str or '',
                elapsed=elapsed,
                url=url,
                method=method
            )

    def request(self, method: str, url: str,
                headers: Dict[str, str] = None,
                data: Union[str, bytes, Dict] = None,
                json_data: Dict = None,
                follow_redirects: bool = True) -> ZAPResponse:
        """
        Send HTTP request through ZAP.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            headers: Request headers
            data: Request body (string, bytes, or dict)
            json_data: JSON body (alternative to data)
            follow_redirects: Follow HTTP redirects

        Returns:
            ZAPResponse object
        """
        if json_data:
            data = json_data
            headers = headers or {}
            headers['Content-Type'] = 'application/json'

        # Build ZAP request
        request_str = self._build_zap_request(method, url, headers, data)

        start_time = time.time()

        try:
            # Send via ZAP API
            response_str = self.zap.core.send_request(
                request_str,
                followredirects=follow_redirects
            )

            elapsed = time.time() - start_time

            return self._parse_zap_response(response_str, url, method, elapsed)

        except Exception as e:
            elapsed = time.time() - start_time
            return ZAPResponse(
                status_code=0,
                headers={'error': str(e)},
                content=b'',
                text='',
                elapsed=elapsed,
                url=url,
                method=method
            )

    def get(self, url: str, headers: Dict[str, str] = None,
            params: Dict[str, str] = None, **kwargs) -> ZAPResponse:
        """Send GET request through ZAP"""
        if params:
            from urllib.parse import urlencode
            separator = '&' if '?' in url else '?'
            url = f"{url}{separator}{urlencode(params)}"
        return self.request('GET', url, headers=headers, **kwargs)

    def post(self, url: str, headers: Dict[str, str] = None,
             data: Union[str, bytes, Dict] = None,
             json_data: Dict = None, **kwargs) -> ZAPResponse:
        """Send POST request through ZAP"""
        return self.request('POST', url, headers=headers,
                           data=data, json_data=json_data, **kwargs)

    def put(self, url: str, headers: Dict[str, str] = None,
            data: Union[str, bytes, Dict] = None,
            json_data: Dict = None, **kwargs) -> ZAPResponse:
        """Send PUT request through ZAP"""
        return self.request('PUT', url, headers=headers,
                           data=data, json_data=json_data, **kwargs)

    def patch(self, url: str, headers: Dict[str, str] = None,
              data: Union[str, bytes, Dict] = None,
              json_data: Dict = None, **kwargs) -> ZAPResponse:
        """Send PATCH request through ZAP"""
        return self.request('PATCH', url, headers=headers,
                           data=data, json_data=json_data, **kwargs)

    def delete(self, url: str, headers: Dict[str, str] = None, **kwargs) -> ZAPResponse:
        """Send DELETE request through ZAP"""
        return self.request('DELETE', url, headers=headers, **kwargs)

    def options(self, url: str, headers: Dict[str, str] = None, **kwargs) -> ZAPResponse:
        """Send OPTIONS request through ZAP"""
        return self.request('OPTIONS', url, headers=headers, **kwargs)

    # === ZAP-specific features ===

    def raise_alert(self, risk: int, confidence: int, name: str,
                    description: str, url: str, param: str = '',
                    attack: str = '', evidence: str = '',
                    solution: str = '', reference: str = '',
                    cwe_id: int = 0, wasc_id: int = 0,
                    message_id: int = None):
        """
        Raise a ZAP alert for a finding.

        Args:
            risk: 0=Info, 1=Low, 2=Medium, 3=High
            confidence: 0=False Positive, 1=Low, 2=Medium, 3=High, 4=Confirmed
            name: Alert name
            description: Alert description
            url: Affected URL
            param: Vulnerable parameter
            attack: Attack payload used
            evidence: Evidence from response
            solution: Remediation advice
            reference: Reference URLs
            cwe_id: CWE ID
            wasc_id: WASC ID
            message_id: ZAP message ID (for linking to request)
        """
        try:
            self.zap.alert.add_alert(
                name=name,
                risk=risk,
                confidence=confidence,
                description=description,
                url=url,
                param=param,
                attack=attack,
                evidence=evidence,
                solution=solution,
                reference=reference,
                cweid=cwe_id,
                wascid=wasc_id,
                messageid=message_id or ''
            )
        except Exception as e:
            print(f"[ZAPHttpClient] Failed to raise alert: {e}")

    def get_messages(self, base_url: str = None, start: int = 0,
                     count: int = 100) -> List[Dict]:
        """Get messages from ZAP history"""
        try:
            if base_url:
                return self.zap.core.messages(baseurl=base_url, start=start, count=count)
            return self.zap.core.messages(start=start, count=count)
        except Exception:
            return []

    def get_alerts(self, base_url: str = None, risk: str = None) -> List[Dict]:
        """Get alerts from ZAP"""
        try:
            kwargs = {}
            if base_url:
                kwargs['baseurl'] = base_url
            if risk:
                kwargs['riskid'] = risk
            return self.zap.core.alerts(**kwargs)
        except Exception:
            return []

    def access_url(self, url: str) -> bool:
        """Add URL to ZAP's site tree via spider access"""
        try:
            self.zap.core.access_url(url, followredirects=True)
            return True
        except Exception:
            return False

    def set_session_token(self, site: str, name: str, value: str):
        """Set session token for a site"""
        self._session_tokens[site] = {name: value}
        try:
            self.zap.httpsessions.set_session_token_value(
                site=site,
                session=name,
                sessiontoken=value
            )
        except Exception:
            pass


class ZAPHttpClientFactory:
    """Factory for creating ZAP HTTP clients with shared configuration"""

    _instance: Optional[ZAPHttpClient] = None
    _zap: Optional[ZAPv2] = None

    @classmethod
    def initialize(cls, zap: ZAPv2 = None, zap_url: str = 'http://localhost:8080',
                   api_key: str = ''):
        """Initialize the factory with ZAP configuration"""
        cls._zap = zap
        cls._instance = ZAPHttpClient(zap=zap, zap_url=zap_url, api_key=api_key)

    @classmethod
    def get_client(cls) -> ZAPHttpClient:
        """Get the shared ZAP HTTP client instance"""
        if cls._instance is None:
            cls._instance = ZAPHttpClient()
        return cls._instance

    @classmethod
    def get_zap(cls) -> Optional[ZAPv2]:
        """Get the underlying ZAP instance"""
        return cls._zap


# Convenience functions for modules that don't need full client
def zap_request(method: str, url: str, **kwargs) -> ZAPResponse:
    """Send request through ZAP (uses shared client)"""
    return ZAPHttpClientFactory.get_client().request(method, url, **kwargs)


def zap_get(url: str, **kwargs) -> ZAPResponse:
    """Send GET through ZAP"""
    return ZAPHttpClientFactory.get_client().get(url, **kwargs)


def zap_post(url: str, **kwargs) -> ZAPResponse:
    """Send POST through ZAP"""
    return ZAPHttpClientFactory.get_client().post(url, **kwargs)


def raise_zap_alert(risk: int, name: str, description: str, url: str, **kwargs):
    """Raise alert in ZAP"""
    ZAPHttpClientFactory.get_client().raise_alert(
        risk=risk, confidence=2, name=name,
        description=description, url=url, **kwargs
    )
