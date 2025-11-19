import requests
import json
import difflib
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from enum import Enum


class IDORStatus(Enum):
    VULNERABLE = "VULNERABLE"
    PROTECTED = "PROTECTED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ERROR = "ERROR"


@dataclass
class IDORTestResult:
    url: str
    method: str
    status: IDORStatus
    baseline_response: Optional[Dict]
    test_response: Optional[Dict]
    confidence: float
    proof: Dict
    diff_html: Optional[str] = None


class IDORDetector:
    SUSPICIOUS_PARAMS = ['id', 'user_id', 'userId', 'uid', 'account_id', 'accountId',
                         'profile_id', 'doc_id', 'file_id', 'order_id', 'resource_id']

    MIN_CONTENT_THRESHOLD = 0.5
    FALSE_POSITIVE_THRESHOLD = 0.1

    def __init__(self, session_a_data: Dict, session_b_data: Dict, config: Dict = None):
        self.session_a = session_a_data
        self.session_b = session_b_data
        self.config = config or {}
        self.results = []
        self.max_workers = self.config.get('max_workers', 5)

    def extract_auth_tokens(self, har_data: Dict) -> Dict[str, str]:
        """Extract authentication tokens from HAR entries"""
        auth_headers = {}

        entries = har_data.get('log', {}).get('entries', [])
        if entries:
            request = entries[0].get('request', {})
            headers = {h['name']: h['value'] for h in request.get('headers', [])}

            if 'Authorization' in headers:
                auth_headers['Authorization'] = headers['Authorization']
            if 'Cookie' in headers:
                auth_headers['Cookie'] = headers['Cookie']

            for key, value in headers.items():
                if 'token' in key.lower() or 'auth' in key.lower():
                    auth_headers[key] = value

        return auth_headers

    def identify_idor_targets(self, har_data: Dict) -> List[Dict]:
        """Identify URLs with potential IDOR vulnerabilities"""
        targets = []
        entries = har_data.get('log', {}).get('entries', [])

        for entry in entries:
            request = entry.get('request', {})
            url = request.get('url', '')
            method = request.get('method', 'GET')

            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)

            has_suspicious_param = any(
                param.lower() in [sp.lower() for sp in self.SUSPICIOUS_PARAMS]
                for param in query_params.keys()
            )

            if has_suspicious_param:
                targets.append({
                    'url': url,
                    'method': method,
                    'params': query_params,
                    'response': entry.get('response', {})
                })

        return targets

    def create_test_variants(self, target: Dict) -> List[Dict]:
        """Create test variants by modifying ID parameters"""
        variants = []
        parsed = urlparse(target['url'])
        query_params = parse_qs(parsed.query)

        for param_name, param_values in query_params.items():
            if any(sp.lower() in param_name.lower() for sp in self.SUSPICIOUS_PARAMS):
                for value in param_values:
                    if value.isdigit():
                        test_values = [
                            str(int(value) + 1),
                            str(int(value) - 1),
                            str(int(value) * 10),
                            '1', '999999'
                        ]

                        for test_value in test_values:
                            modified_params = query_params.copy()
                            modified_params[param_name] = [test_value]

                            new_query = urlencode(modified_params, doseq=True)
                            new_url = urlunparse((
                                parsed.scheme, parsed.netloc, parsed.path,
                                parsed.params, new_query, parsed.fragment
                            ))

                            variants.append({
                                'url': new_url,
                                'method': target['method'],
                                'modified_param': param_name,
                                'original_value': value,
                                'test_value': test_value
                            })

        return variants

    def execute_baseline_request(self, target: Dict, auth_headers: Dict) -> Optional[Dict]:
        """Execute baseline request with User A credentials"""
        try:
            session = requests.Session()
            session.headers.update(auth_headers)

            response = session.request(
                method=target['method'],
                url=target['url'],
                timeout=10,
                verify=False
            )

            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text,
                'content_length': len(response.content),
                'json': response.json() if self._is_json(response) else None
            }
        except Exception as e:
            return {'error': str(e)}

    def execute_cross_user_test(self, variant: Dict, auth_headers_b: Dict) -> Optional[Dict]:
        """Execute test request with User B credentials accessing User A resources"""
        try:
            session = requests.Session()
            session.headers.update(auth_headers_b)

            response = session.request(
                method=variant['method'],
                url=variant['url'],
                timeout=10,
                verify=False
            )

            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text,
                'content_length': len(response.content),
                'json': response.json() if self._is_json(response) else None
            }
        except Exception as e:
            return {'error': str(e)}

    def analyze_responses(self, baseline: Dict, test: Dict, variant: Dict) -> IDORTestResult:
        """Analyze responses to determine IDOR vulnerability"""

        if 'error' in baseline or 'error' in test:
            return IDORTestResult(
                url=variant['url'],
                method=variant['method'],
                status=IDORStatus.ERROR,
                baseline_response=baseline,
                test_response=test,
                confidence=0.0,
                proof={'error': baseline.get('error') or test.get('error')}
            )

        test_status = test['status_code']
        baseline_status = baseline['status_code']

        if test_status in [401, 403]:
            return IDORTestResult(
                url=variant['url'],
                method=variant['method'],
                status=IDORStatus.PROTECTED,
                baseline_response=baseline,
                test_response=test,
                confidence=1.0,
                proof={'message': 'Access properly denied'}
            )

        if test_status == 200 and baseline_status == 200:
            content_ratio = test['content_length'] / max(baseline['content_length'], 1)

            if content_ratio < self.FALSE_POSITIVE_THRESHOLD:
                return IDORTestResult(
                    url=variant['url'],
                    method=variant['method'],
                    status=IDORStatus.FALSE_POSITIVE,
                    baseline_response=baseline,
                    test_response=test,
                    confidence=0.3,
                    proof={'message': 'Response too small, likely error page'}
                )

            if content_ratio >= self.MIN_CONTENT_THRESHOLD:
                similarity = self._calculate_similarity(
                    baseline.get('content', ''),
                    test.get('content', '')
                )

                confidence = min(content_ratio, 1.0) * (1.0 if similarity < 0.95 else 0.7)

                diff_html = self._generate_diff_html(
                    baseline.get('content', ''),
                    test.get('content', '')
                )

                return IDORTestResult(
                    url=variant['url'],
                    method=variant['method'],
                    status=IDORStatus.VULNERABLE,
                    baseline_response=baseline,
                    test_response=test,
                    confidence=confidence,
                    proof={
                        'param': variant['modified_param'],
                        'original_value': variant['original_value'],
                        'test_value': variant['test_value'],
                        'content_ratio': content_ratio,
                        'similarity': similarity
                    },
                    diff_html=diff_html
                )

        return IDORTestResult(
            url=variant['url'],
            method=variant['method'],
            status=IDORStatus.FALSE_POSITIVE,
            baseline_response=baseline,
            test_response=test,
            confidence=0.2,
            proof={'message': f'Unexpected status code: {test_status}'}
        )

    def run_detection(self) -> List[IDORTestResult]:
        """Main detection routine with parallel execution"""
        print("[IDOR] Extracting authentication tokens...")
        auth_a = self.extract_auth_tokens(self.session_a)
        auth_b = self.extract_auth_tokens(self.session_b)

        if not auth_a or not auth_b:
            print("[IDOR] Error: Could not extract authentication tokens")
            return []

        print("[IDOR] Identifying potential IDOR targets...")
        targets = self.identify_idor_targets(self.session_a)
        print(f"[IDOR] Found {len(targets)} potential targets")

        all_variants = []
        for target in targets:
            variants = self.create_test_variants(target)
            for variant in variants:
                all_variants.append((target, variant))

        print(f"[IDOR] Testing {len(all_variants)} variants with {self.max_workers} workers...")

        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_variant = {
                executor.submit(self._test_variant, target, variant, auth_a, auth_b): (target, variant)
                for target, variant in all_variants
            }

            for future in as_completed(future_to_variant):
                result = future.result()
                if result:
                    results.append(result)
                    if result.status == IDORStatus.VULNERABLE:
                        print(f"[IDOR] 🚨 VULNERABLE: {result.url} (confidence: {result.confidence:.2f})")

        self.results = results
        return results

    def _test_variant(self, target: Dict, variant: Dict, auth_a: Dict, auth_b: Dict) -> Optional[IDORTestResult]:
        """Test a single variant (used by thread pool)"""
        baseline = self.execute_baseline_request(target, auth_a)
        test = self.execute_cross_user_test(variant, auth_b)
        return self.analyze_responses(baseline, test, variant)

    def _is_json(self, response: requests.Response) -> bool:
        """Check if response is JSON"""
        content_type = response.headers.get('Content-Type', '')
        return 'application/json' in content_type

    def _calculate_similarity(self, text1: str, text2: str) -> float:
        """Calculate similarity ratio between two texts"""
        return difflib.SequenceMatcher(None, text1, text2).ratio()

    def _generate_diff_html(self, content1: str, content2: str) -> str:
        """Generate HTML diff visualization"""
        diff = difflib.HtmlDiff()
        return diff.make_file(
            content1.splitlines(),
            content2.splitlines(),
            'Baseline (User A → Resource A)',
            'Test (User B → Resource A)'
        )

    def generate_curl_commands(self, result: IDORTestResult, auth_b: Dict) -> str:
        """Generate cURL command for manual reproduction"""
        headers = ' '.join([f"-H '{k}: {v}'" for k, v in auth_b.items()])
        return f"curl -X {result.method} {headers} '{result.url}'"

    def get_summary(self) -> Dict:
        """Generate summary statistics"""
        return {
            'total_tests': len(self.results),
            'vulnerable': len([r for r in self.results if r.status == IDORStatus.VULNERABLE]),
            'protected': len([r for r in self.results if r.status == IDORStatus.PROTECTED]),
            'false_positives': len([r for r in self.results if r.status == IDORStatus.FALSE_POSITIVE]),
            'errors': len([r for r in self.results if r.status == IDORStatus.ERROR])
        }
