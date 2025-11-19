"""
Red Team Attack Modules - Business Logic & Access Control Testing
"""
import asyncio
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional

import requests


class AttackType(Enum):
    UNAUTH_REPLAY = "Unauthenticated Replay"
    BROKEN_AUTH = "Broken Authentication"
    MASS_ASSIGNMENT = "Mass Assignment"
    HIDDEN_PARAMS = "Hidden Parameters"
    RACE_CONDITION = "Race Condition"


@dataclass
class AttackResult:
    attack_type: AttackType
    url: str
    method: str
    vulnerable: bool
    confidence: float
    evidence: Dict
    description: str
    remediation: str


class UnauthenticatedReplayAttack:
    """Test if authenticated endpoints are accessible without credentials"""

    def __init__(self, har_data: Dict):
        self.har_data = har_data
        self.results = []

    def identify_authenticated_requests(self) -> List[Dict]:
        """Extract requests that have authentication headers"""
        authenticated = []

        entries = self.har_data.get('log', {}).get('entries', [])

        for entry in entries:
            request = entry.get('request', {})
            headers = {h['name']: h['value'] for h in request.get('headers', [])}

            has_auth = any([
                'Authorization' in headers,
                'Cookie' in headers,
                any('token' in k.lower() for k in headers.keys())
            ])

            if has_auth:
                authenticated.append({
                    'url': request.get('url'),
                    'method': request.get('method', 'GET'),
                    'headers': headers,
                    'body': request.get('postData', {}).get('text'),
                    'original_response': entry.get('response', {})
                })

        return authenticated

    def execute_unauth_replay(self, request: Dict) -> AttackResult:
        """Execute request without authentication headers"""
        url = request['url']
        method = request['method']

        clean_headers = {
            k: v for k, v in request['headers'].items()
            if k.lower() not in ['authorization', 'cookie']
            and 'token' not in k.lower()
        }

        clean_headers['User-Agent'] = 'Mozilla/5.0 (Security Test)'

        try:
            response = requests.request(
                method=method,
                url=url,
                headers=clean_headers,
                data=request.get('body'),
                timeout=10,
                verify=False,
                allow_redirects=False
            )

            original_status = request['original_response'].get('status', 0)
            original_size = request['original_response'].get('bodySize', 0)

            is_vulnerable = (
                response.status_code == 200
                and len(response.content) > 100
                and response.status_code == original_status
            )

            confidence = 0.0
            if is_vulnerable:
                size_ratio = len(response.content) / max(original_size, 1)
                confidence = min(size_ratio, 1.0) if size_ratio > 0.5 else 0.3

            return AttackResult(
                attack_type=AttackType.UNAUTH_REPLAY,
                url=url,
                method=method,
                vulnerable=is_vulnerable,
                confidence=confidence,
                evidence={
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'original_status': original_status,
                    'original_size': original_size,
                    'headers_removed': ['Authorization', 'Cookie', 'Token']
                },
                description=f"Endpoint accessible without authentication (HTTP {response.status_code})",
                remediation="Implement proper authentication checks on server-side"
            )

        except Exception as e:
            return AttackResult(
                attack_type=AttackType.UNAUTH_REPLAY,
                url=url,
                method=method,
                vulnerable=False,
                confidence=0.0,
                evidence={'error': str(e)},
                description=f"Test failed: {e}",
                remediation=""
            )

    def run_attack(self, max_workers: int = 5) -> List[AttackResult]:
        """Execute unauthenticated replay on all authenticated requests"""
        print("[RedTeam] Identifying authenticated requests...")
        auth_requests = self.identify_authenticated_requests()

        print(f"[RedTeam] Found {len(auth_requests)} authenticated requests")
        print("[RedTeam] Testing unauthenticated access...")

        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(self.execute_unauth_replay, req)
                for req in auth_requests
            ]

            for future in futures:
                result = future.result()
                results.append(result)

                if result.vulnerable:
                    print(f"[RedTeam] 🚨 CRITICAL: {result.url} accessible without auth!")

        self.results = results
        return results


class MassAssignmentFuzzer:
    """Test for mass assignment vulnerabilities by injecting privilege escalation parameters"""

    DANGEROUS_PARAMS = [
        {'role': 'admin'},
        {'is_admin': True},
        {'admin': 1},
        {'role': 'administrator'},
        {'permission': 'write'},
        {'permissions': ['admin', 'write', 'delete']},
        {'is_superuser': True},
        {'account_type': 'premium'},
        {'credits': 999999},
        {'balance': 999999}
    ]

    def __init__(self, har_data: Dict):
        self.har_data = har_data
        self.results = []

    def identify_mutation_endpoints(self) -> List[Dict]:
        """Find POST/PUT/PATCH endpoints with JSON payloads"""
        mutation_endpoints = []

        entries = self.har_data.get('log', {}).get('entries', [])

        for entry in entries:
            request = entry.get('request', {})
            method = request.get('method')

            if method not in ['POST', 'PUT', 'PATCH']:
                continue

            post_data = request.get('postData', {})
            content_type = post_data.get('mimeType', '')

            if 'json' in content_type:
                mutation_endpoints.append({
                    'url': request.get('url'),
                    'method': method,
                    'headers': {h['name']: h['value'] for h in request.get('headers', [])},
                    'body': post_data.get('text', '{}')
                })

        return mutation_endpoints

    def inject_dangerous_params(self, request: Dict) -> List[AttackResult]:
        """Inject mass assignment payloads"""
        results = []
        url = request['url']
        method = request['method']
        headers = request['headers']

        try:
            original_body = eval(request['body']) if request['body'] else {}
        except:
            import json
            try:
                original_body = json.loads(request['body'])
            except:
                return results

        for dangerous_payload in self.DANGEROUS_PARAMS:
            poisoned_body = {**original_body, **dangerous_payload}

            try:
                response = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    json=poisoned_body,
                    timeout=10,
                    verify=False
                )

                is_vulnerable = (
                    response.status_code in [200, 201, 204]
                    and 'error' not in response.text.lower()
                    and 'invalid' not in response.text.lower()
                )

                if is_vulnerable:
                    results.append(AttackResult(
                        attack_type=AttackType.MASS_ASSIGNMENT,
                        url=url,
                        method=method,
                        vulnerable=True,
                        confidence=0.7,
                        evidence={
                            'injected_params': dangerous_payload,
                            'status_code': response.status_code,
                            'response_preview': response.text[:500]
                        },
                        description=f"Endpoint accepted privilege escalation parameter: {dangerous_payload}",
                        remediation="Use allowlist/DTO pattern for input validation"
                    ))

            except Exception as e:
                pass

        return results

    def run_attack(self) -> List[AttackResult]:
        """Execute mass assignment fuzzing"""
        print("[RedTeam] Identifying mutation endpoints...")
        endpoints = self.identify_mutation_endpoints()

        print(f"[RedTeam] Testing {len(endpoints)} endpoints for mass assignment...")

        all_results = []
        for endpoint in endpoints:
            results = self.inject_dangerous_params(endpoint)
            all_results.extend(results)

            if results:
                print(f"[RedTeam] ⚠️  Potential mass assignment: {endpoint['url']}")

        self.results = all_results
        return all_results


class HiddenParameterDiscovery:
    """Discover hidden parameters like debug, admin, test modes"""

    COMMON_HIDDEN_PARAMS = [
        ('debug', ['true', '1', 'yes']),
        ('admin', ['true', '1', 'yes']),
        ('test', ['true', '1', 'yes']),
        ('internal', ['true', '1']),
        ('dev', ['true', '1']),
        ('trace', ['true', '1']),
        ('verbose', ['true', '1']),
        ('show_errors', ['true', '1'])
    ]

    def __init__(self, har_data: Dict):
        self.har_data = har_data

    def test_hidden_params(self, url: str, headers: Dict) -> List[AttackResult]:
        """Test URL with hidden parameter variations"""
        results = []

        for param_name, values in self.COMMON_HIDDEN_PARAMS:
            for value in values:
                separator = '&' if '?' in url else '?'
                test_url = f"{url}{separator}{param_name}={value}"

                try:
                    response = requests.get(
                        test_url,
                        headers=headers,
                        timeout=5,
                        verify=False
                    )

                    baseline_response = requests.get(url, headers=headers, timeout=5, verify=False)

                    content_diff = abs(len(response.content) - len(baseline_response.content))
                    is_vulnerable = content_diff > 100

                    if is_vulnerable:
                        results.append(AttackResult(
                            attack_type=AttackType.HIDDEN_PARAMS,
                            url=test_url,
                            method='GET',
                            vulnerable=True,
                            confidence=0.6,
                            evidence={
                                'parameter': param_name,
                                'value': value,
                                'baseline_size': len(baseline_response.content),
                                'modified_size': len(response.content)
                            },
                            description=f"Hidden parameter '{param_name}' changes response",
                            remediation="Remove debug parameters from production"
                        ))

                except:
                    pass

        return results

    def run_attack(self) -> List[AttackResult]:
        """Execute hidden parameter discovery"""
        print("[RedTeam] Discovering hidden parameters...")

        entries = self.har_data.get('log', {}).get('entries', [])
        unique_urls = set()

        for entry in entries[:20]:
            request = entry.get('request', {})
            unique_urls.add(request.get('url'))

        all_results = []
        for url in list(unique_urls)[:10]:
            results = self.test_hidden_params(url, {})
            all_results.extend(results)

        return all_results


class RaceConditionTester:
    """
    Test for race conditions on critical endpoints
    TODO: Implement async burst requests for endpoints like:
    - /transfer (TOCTOU)
    - /coupon (multiple redemptions)
    - /vote (ballot stuffing)
    """

    def __init__(self, har_data: Dict):
        self.har_data = har_data

    async def burst_request(self, url: str, method: str, headers: Dict, body: str, count: int = 50):
        """Send multiple simultaneous requests"""
        import aiohttp

        async with aiohttp.ClientSession() as session:
            tasks = []

            for _ in range(count):
                if method == 'GET':
                    task = session.get(url, headers=headers, ssl=False)
                elif method == 'POST':
                    task = session.post(url, headers=headers, data=body, ssl=False)
                else:
                    continue

                tasks.append(task)

            responses = await asyncio.gather(*tasks, return_exceptions=True)

            return responses

    def identify_race_targets(self) -> List[Dict]:
        """Identify endpoints likely vulnerable to race conditions"""
        race_keywords = ['transfer', 'coupon', 'redeem', 'vote', 'purchase', 'checkout']

        targets = []
        entries = self.har_data.get('log', {}).get('entries', [])

        for entry in entries:
            request = entry.get('request', {})
            url = request.get('url', '').lower()

            if any(keyword in url for keyword in race_keywords):
                targets.append({
                    'url': request.get('url'),
                    'method': request.get('method'),
                    'headers': {h['name']: h['value'] for h in request.get('headers', [])},
                    'body': request.get('postData', {}).get('text')
                })

        return targets

    def run_attack(self) -> List[AttackResult]:
        """
        Execute race condition tests
        TODO: Full implementation requires careful timing analysis
        """
        print("[RedTeam] Identifying race condition targets...")
        targets = self.identify_race_targets()

        if not targets:
            print("[RedTeam] No obvious race condition targets found")
            return []

        print(f"[RedTeam] TODO: Implement burst testing for {len(targets)} potential targets")
        print("[RedTeam] Manual testing recommended for:")
        for target in targets:
            print(f"  - {target['method']} {target['url']}")

        return []


class RedTeamOrchestrator:
    """Orchestrate all red team attacks"""

    def __init__(self, har_data: Dict, config: Dict = None):
        self.har_data = har_data
        self.config = config or {}
        self.results = {}

    def run_all_attacks(self) -> Dict[str, List[AttackResult]]:
        """Execute all red team attack modules"""
        print("\n" + "="*80)
        print("RED TEAM ATTACK SIMULATION")
        print("="*80)

        self.results['unauth_replay'] = UnauthenticatedReplayAttack(
            self.har_data
        ).run_attack()

        self.results['mass_assignment'] = MassAssignmentFuzzer(
            self.har_data
        ).run_attack()

        self.results['hidden_params'] = HiddenParameterDiscovery(
            self.har_data
        ).run_attack()

        self.results['race_condition'] = RaceConditionTester(
            self.har_data
        ).run_attack()

        return self.results

    def get_critical_findings(self) -> List[AttackResult]:
        """Get all critical vulnerabilities"""
        critical = []

        for attack_type, results in self.results.items():
            for result in results:
                if result.vulnerable and result.confidence > 0.5:
                    critical.append(result)

        return sorted(critical, key=lambda x: x.confidence, reverse=True)

    def generate_report(self) -> Dict:
        """Generate summary report"""
        total_tests = sum(len(results) for results in self.results.values())
        total_vulns = sum(
            1 for results in self.results.values()
            for result in results
            if result.vulnerable
        )

        return {
            'total_tests': total_tests,
            'total_vulnerabilities': total_vulns,
            'by_type': {
                attack_type: len([r for r in results if r.vulnerable])
                for attack_type, results in self.results.items()
            },
            'critical_findings': [
                {
                    'type': r.attack_type.value,
                    'url': r.url,
                    'confidence': r.confidence,
                    'description': r.description
                }
                for r in self.get_critical_findings()
            ]
        }
