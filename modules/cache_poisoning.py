"""
Web Cache Poisoning Detection
Unkeyed header injection and cache key manipulation
Reference: https://portswigger.net/web-security/web-cache-poisoning

All requests routed through ZAP for unified logging and alerting.
"""
import hashlib
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from modules.zap_http_client import ZAPHttpClient


@dataclass
class CachePoisonResult:
    url: str
    poison_header: str
    poison_value: str
    vulnerable: bool
    confidence: float
    evidence: Dict
    severity: str = "High"
    cwe: str = "CWE-349"
    cvss: float = 7.5


class CachePoisoningTester:
    """
    Test for Web Cache Poisoning vulnerabilities
    Detects unkeyed headers reflected in cached responses
    """

    # Headers commonly excluded from cache keys
    POISON_HEADERS = [
        # Host manipulation
        ('X-Forwarded-Host', 'evil-cache-{rand}.com'),
        ('X-Host', 'evil-cache-{rand}.com'),
        ('X-Forwarded-Server', 'evil-cache-{rand}.com'),
        ('X-Original-Host', 'evil-cache-{rand}.com'),
        ('Forwarded', 'host=evil-cache-{rand}.com'),

        # URL manipulation
        ('X-Original-URL', '/admin?cache={rand}'),
        ('X-Rewrite-URL', '/admin?cache={rand}'),
        ('X-Original-Path', '/admin?cache={rand}'),

        # Protocol manipulation
        ('X-Forwarded-Scheme', 'nothttps-{rand}'),
        ('X-Forwarded-Proto', 'nothttps-{rand}'),
        ('X-Forwarded-Ssl', 'off-{rand}'),

        # IP spoofing (can affect caching)
        ('X-Forwarded-For', '127.0.0.1-{rand}'),
        ('X-Client-IP', '127.0.0.1-{rand}'),
        ('X-Real-IP', '127.0.0.1-{rand}'),
        ('True-Client-IP', '127.0.0.1-{rand}'),
        ('CF-Connecting-IP', '127.0.0.1-{rand}'),
        ('X-Custom-IP-Authorization', '127.0.0.1-{rand}'),

        # Method override
        ('X-HTTP-Method-Override', 'POST-{rand}'),
        ('X-Method-Override', 'DELETE-{rand}'),
    ]

    # Cache indicator headers
    CACHE_INDICATORS = [
        'x-cache',
        'x-cache-hits',
        'cf-cache-status',
        'x-varnish',
        'age',
        'x-proxy-cache',
        'x-drupal-cache',
        'x-akamai-cache-status',
        'x-fastly-cache',
        'x-cdn-cache'
    ]

    def __init__(self, har_data: Dict, config: Dict = None,
                 zap_client: 'ZAPHttpClient' = None):
        self.har_data = har_data
        self.config = config or {}
        self.timeout = self.config.get('cache_timeout', 10)
        self.zap_client = zap_client
        self._use_zap = zap_client is not None

    def _get(self, url: str, headers: Dict = None,
             allow_redirects: bool = False) -> Optional[Dict]:
        """HTTP GET via ZAP or fallback to requests"""
        try:
            if self._use_zap:
                resp = self.zap_client.get(url, headers=headers,
                                           follow_redirects=allow_redirects)
                return {
                    'status_code': resp.status_code,
                    'headers': resp.headers,
                    'text': resp.text
                }
            else:
                import requests
                resp = requests.get(url, headers=headers, timeout=self.timeout,
                                   verify=False, allow_redirects=allow_redirects)
                return {
                    'status_code': resp.status_code,
                    'headers': {k.lower(): v for k, v in resp.headers.items()},
                    'text': resp.text
                }
        except Exception:
            return None

    def _request(self, method: str, url: str, headers: Dict = None,
                 data: str = None) -> Optional[Dict]:
        """Generic HTTP request via ZAP or fallback"""
        try:
            if self._use_zap:
                resp = self.zap_client.request(method, url, headers=headers, data=data)
                return {
                    'status_code': resp.status_code,
                    'headers': resp.headers,
                    'text': resp.text
                }
            else:
                import requests
                resp = requests.request(method, url, headers=headers, data=data,
                                       timeout=self.timeout, verify=False)
                return {
                    'status_code': resp.status_code,
                    'headers': {k.lower(): v for k, v in resp.headers.items()},
                    'text': resp.text
                }
        except Exception:
            return None

    def _raise_alert(self, result: 'CachePoisonResult'):
        """Raise ZAP alert for finding"""
        if self._use_zap and result.vulnerable:
            risk_map = {'Critical': 3, 'High': 3, 'Medium': 2, 'Low': 1}
            self.zap_client.raise_alert(
                risk=risk_map.get(result.severity, 2),
                name=f"Cache Poisoning: {result.poison_header}",
                description=f"Web cache poisoning via {result.poison_header} header",
                url=result.url,
                attack=result.poison_value,
                evidence=str(result.evidence),
                solution="Include all user-controllable headers in cache key",
                cwe_id=349
            )

    def _generate_cache_buster(self) -> str:
        """Generate unique cache buster value"""
        return hashlib.md5(str(time.time()).encode()).hexdigest()[:8]

    def identify_cacheable_endpoints(self) -> List[Dict]:
        """Find endpoints that appear to use caching"""
        cacheable = []
        entries = self.har_data.get('log', {}).get('entries', [])

        for entry in entries:
            response = entry.get('response', {})
            headers = {h['name'].lower(): h['value']
                      for h in response.get('headers', [])}

            # Look for cache indicators
            cache_headers = {}
            for indicator in self.CACHE_INDICATORS:
                if indicator in headers:
                    cache_headers[indicator] = headers[indicator]

            # Check Cache-Control
            cache_control = headers.get('cache-control', '')
            has_public_cache = any(d in cache_control for d in ['public', 'max-age', 's-maxage'])

            if cache_headers or has_public_cache:
                request = entry.get('request', {})
                cacheable.append({
                    'url': request.get('url'),
                    'method': request.get('method', 'GET'),
                    'cache_headers': cache_headers,
                    'cache_control': cache_control
                })

        return cacheable

    def test_header_reflection(self, url: str, header_name: str,
                               header_template: str) -> Optional[CachePoisonResult]:
        """Test if header value is reflected in response"""
        rand = self._generate_cache_buster()
        header_value = header_template.replace('{rand}', rand)

        # Add cache buster to URL
        separator = '&' if '?' in url else '?'
        test_url = f"{url}{separator}cb={rand}"

        # Request 1: With poison header
        response1 = self._get(test_url, headers={header_name: header_value})
        if not response1:
            return None

        # Check for reflection in response body
        body_reflection = header_value in response1['text'] or rand in response1['text']

        # Check for reflection in response headers
        header_reflection = any(
            rand in str(v) for v in response1['headers'].values()
        )

        if not (body_reflection or header_reflection):
            return None

        # Wait for cache
        time.sleep(2)

        # Request 2: Without poison header (should get cached response)
        response2 = self._get(test_url)
        if not response2:
            return None

        # Check if poison value appears in cached response
        cached_reflection = (
            rand in response2['text'] or
            any(rand in str(v) for v in response2['headers'].values())
        )

        if cached_reflection:
            result = CachePoisonResult(
                url=url,
                poison_header=header_name,
                poison_value=header_value,
                vulnerable=True,
                confidence=0.9,
                evidence={
                    'reflected_in_body': rand in response2['text'],
                    'reflected_in_headers': any(rand in str(v)
                                               for v in response2['headers'].values()),
                    'cache_status': response2['headers'].get('x-cache', 'unknown'),
                    'response_preview': response2['text'][:200] if rand in response2['text'] else ''
                },
                severity="Critical" if body_reflection else "High"
            )
            self._raise_alert(result)
            return result

        # Even if not cached, reflection is interesting
        if body_reflection:
            result = CachePoisonResult(
                url=url,
                poison_header=header_name,
                poison_value=header_value,
                vulnerable=True,
                confidence=0.5,
                evidence={
                    'reflected_first_request': True,
                    'cached': False,
                    'note': 'Value reflected but may not be cached'
                },
                severity="Medium"
            )
            self._raise_alert(result)
            return result

        return None

    def test_fat_get(self, url: str) -> Optional[CachePoisonResult]:
        """
        Test for Fat GET attack (body in GET request)
        Some caches ignore GET body but backend processes it
        """
        rand = self._generate_cache_buster()
        separator = '&' if '?' in url else '?'
        test_url = f"{url}{separator}fatget={rand}"

        # Request with body
        response1 = self._request(
            'GET',
            test_url,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data=f"test={rand}"
        )

        if not response1:
            return None

        if rand in response1['text']:
            time.sleep(2)

            # Normal GET
            response2 = self._get(test_url)

            if response2 and rand in response2['text']:
                result = CachePoisonResult(
                    url=url,
                    poison_header='GET Body (Fat GET)',
                    poison_value=f"test={rand}",
                    vulnerable=True,
                    confidence=0.8,
                    evidence={
                        'attack_type': 'fat_get',
                        'body_processed': True,
                        'cached': True
                    },
                    severity="High"
                )
                self._raise_alert(result)
                return result

        return None

    def test_parameter_cloaking(self, url: str) -> Optional[CachePoisonResult]:
        """
        Test for parameter cloaking using different parsers
        Cache may exclude param while backend includes it
        """
        rand = self._generate_cache_buster()

        # Different URL encoding tricks
        cloaking_payloads = [
            (f"?cb={rand};poison={rand}", 'semicolon'),
            (f"?cb={rand}%00poison={rand}", 'null_byte'),
            (f"?cb={rand}%26poison={rand}", 'encoded_ampersand'),
        ]

        for payload, technique in cloaking_payloads:
            test_url = url.split('?')[0] + payload

            response = self._get(test_url)
            if not response:
                continue

            if f"poison={rand}" in response['text'] or response['text'].count(rand) > 1:
                result = CachePoisonResult(
                    url=url,
                    poison_header=f'Parameter Cloaking ({technique})',
                    poison_value=payload,
                    vulnerable=True,
                    confidence=0.6,
                    evidence={
                        'technique': technique,
                        'reflected': True
                    },
                    severity="Medium"
                )
                self._raise_alert(result)
                return result

        return None

    def run_tests(self) -> List[CachePoisonResult]:
        """Execute cache poisoning tests"""
        print("[CachePoison] Scanning for cache poisoning vulnerabilities...")

        targets = self.identify_cacheable_endpoints()
        print(f"[CachePoison] Found {len(targets)} cacheable endpoints")

        results = []
        tested_urls = set()

        for target in targets:
            url = target['url']
            base_url = url.split('?')[0]

            if base_url in tested_urls:
                continue
            tested_urls.add(base_url)

            # Test poison headers
            for header_name, header_template in self.POISON_HEADERS:
                result = self.test_header_reflection(url, header_name, header_template)
                if result:
                    results.append(result)
                    print(f"[CachePoison] 🚨 {header_name} poison detected!")
                    break  # One finding per URL for headers

            # Test fat GET
            fat_result = self.test_fat_get(url)
            if fat_result:
                results.append(fat_result)
                print(f"[CachePoison] 🚨 Fat GET attack possible!")

            # Test parameter cloaking
            cloak_result = self.test_parameter_cloaking(url)
            if cloak_result:
                results.append(cloak_result)
                print(f"[CachePoison] ⚠️ Parameter cloaking detected!")

        return results

    def generate_report(self, results: List[CachePoisonResult]) -> Dict:
        """Generate summary report"""
        return {
            'total_cacheable_endpoints': len(self.identify_cacheable_endpoints()),
            'vulnerable_count': len([r for r in results if r.vulnerable]),
            'findings': [
                {
                    'url': r.url,
                    'poison_header': r.poison_header,
                    'confidence': r.confidence,
                    'severity': r.severity,
                    'evidence': r.evidence,
                    'remediation': 'Include all user-controllable headers in cache key'
                }
                for r in results
            ]
        }
