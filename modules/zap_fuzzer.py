"""
ZAP Fuzzer Integration with intelligent wordlists
"""
import time
from typing import Dict, List

# noinspection PyUnresolvedReferences
from zapv2 import ZAPv2


class ZAPFuzzer:
    """Advanced fuzzing with ZAP using extracted tokens"""

    def __init__(self, zap: ZAPv2, wordlists: Dict[str, List[str]]):
        self.zap = zap
        self.wordlists = wordlists
        self.fuzzer_ids = []

    def fuzz_idor_endpoints(self, endpoints: List[Dict]) -> List[Dict]:
        """Fuzz endpoints with ID parameters using extracted IDs"""
        results = []

        if not self.wordlists.get('ids'):
            print("[ZAPFuzzer] No IDs extracted for IDOR fuzzing")
            return results

        id_wordlist = self.wordlists['ids']
        print(f"[ZAPFuzzer] IDOR fuzzing with {len(id_wordlist)} extracted IDs")

        for endpoint in endpoints:
            url = endpoint['url']
            params = endpoint.get('params', [])

            # Find ID parameters
            id_params = [p for p in params if 'id' in p.lower()]

            if not id_params:
                continue

            for param in id_params:
                print(f"[ZAPFuzzer] Fuzzing {url} param={param}")

                # Create fuzzer scan
                try:
                    # Use ZAP fuzzer API
                    fuzzer_id = self.zap.fuzzer.add_fuzzer(
                        url=url,
                        fuzzlocations=[param],
                        fuzztype='Custom'
                    )

                    # Add payloads from extracted IDs
                    for payload in id_wordlist[:100]:  # Limit to 100
                        self.zap.fuzzer.add_payload(
                            fuzzerid=fuzzer_id,
                            payload=str(payload)
                        )

                    # Start fuzzing
                    self.zap.fuzzer.start_fuzzer(fuzzerid=fuzzer_id)
                    self.fuzzer_ids.append(fuzzer_id)

                    # Wait for completion
                    self._wait_for_fuzzer(fuzzer_id)

                    # Collect results
                    fuzzer_results = self.zap.fuzzer.messages(fuzzerid=fuzzer_id)

                    # Analyze for IDOR
                    vulnerable = self._analyze_idor_results(fuzzer_results, endpoint)

                    results.append({
                        'url': url,
                        'param': param,
                        'fuzzer_id': fuzzer_id,
                        'total_requests': len(id_wordlist),
                        'vulnerable': vulnerable,
                        'results': fuzzer_results
                    })

                except Exception as e:
                    print(f"[ZAPFuzzer] Error fuzzing {url}: {e}")

        return results

    def fuzz_authentication(self, endpoints: List[Dict]) -> List[Dict]:
        """Fuzz authentication with extracted usernames/passwords"""
        results = []

        usernames = self.wordlists.get('usernames', [])
        if not usernames:
            print("[ZAPFuzzer] No usernames extracted")
            return results

        print(f"[ZAPFuzzer] Auth fuzzing with {len(usernames)} usernames")

        for endpoint in endpoints:
            url = endpoint['url']
            params = endpoint.get('params', [])

            # Find auth-related params
            auth_params = [p for p in params
                           if any(x in p.lower() for x in ['user', 'login', 'email', 'account'])]

            if not auth_params:
                continue

            for param in auth_params:
                try:
                    fuzzer_id = self.zap.fuzzer.add_fuzzer(
                        url=url,
                        fuzzlocations=[param],
                        fuzztype='Custom'
                    )

                    for username in usernames[:50]:
                        self.zap.fuzzer.add_payload(
                            fuzzerid=fuzzer_id,
                            payload=username
                        )

                    self.zap.fuzzer.start_fuzzer(fuzzerid=fuzzer_id)
                    self._wait_for_fuzzer(fuzzer_id)

                    fuzzer_results = self.zap.fuzzer.messages(fuzzerid=fuzzer_id)

                    results.append({
                        'url': url,
                        'param': param,
                        'fuzzer_id': fuzzer_id,
                        'results': fuzzer_results
                    })

                except Exception as e:
                    print(f"[ZAPFuzzer] Error fuzzing auth {url}: {e}")

        return results

    def fuzz_custom_params(self, url: str, param: str, wordlist_name: str) -> Dict:
        """Fuzz specific parameter with custom wordlist"""
        wordlist = self.wordlists.get(wordlist_name, [])

        if not wordlist:
            return {'error': f'Wordlist {wordlist_name} not found'}

        try:
            fuzzer_id = self.zap.fuzzer.add_fuzzer(
                url=url,
                fuzzlocations=[param],
                fuzztype='Custom'
            )

            for payload in wordlist[:200]:  # Limit
                self.zap.fuzzer.add_payload(
                    fuzzerid=fuzzer_id,
                    payload=str(payload)
                )

            self.zap.fuzzer.start_fuzzer(fuzzerid=fuzzer_id)
            self._wait_for_fuzzer(fuzzer_id)

            results = self.zap.fuzzer.messages(fuzzerid=fuzzer_id)

            return {
                'url': url,
                'param': param,
                'wordlist': wordlist_name,
                'total_payloads': len(wordlist),
                'fuzzer_id': fuzzer_id,
                'results': results,
                'unique_responses': self._count_unique_responses(results)
            }

        except Exception as e:
            return {'error': str(e)}

    def _wait_for_fuzzer(self, fuzzer_id: str, timeout: int = 300):
        """Wait for fuzzer to complete"""
        start = time.time()

        while time.time() - start < timeout:
            try:
                status = self.zap.fuzzer.status(fuzzerid=fuzzer_id)
                state = status.get('state', 'UNKNOWN')

                if state == 'FINISHED':
                    print(f"[ZAPFuzzer] Fuzzer {fuzzer_id} completed")
                    return

                progress = status.get('progress', 0)
                if progress % 20 == 0:
                    print(f"[ZAPFuzzer] Progress: {progress}%")

                time.sleep(2)

            except Exception as e:
                print(f"[ZAPFuzzer] Error checking status: {e}")
                break

    @staticmethod
    def _analyze_idor_results(results: List[Dict], endpoint: Dict) -> bool:
        """Analyze fuzzer results for IDOR vulnerabilities"""
        success_responses = 0

        for result in results:
            status_code = result.get('responseHeader', {}).get('statusCode', 0)

            # Count successful responses (200, 201, etc)
            if 200 <= status_code < 300:
                success_responses += 1

        # If more than 10% of fuzzed IDs return success, likely IDOR
        threshold = len(results) * 0.1
        return success_responses > threshold

    @staticmethod
    def _count_unique_responses(results: List[Dict]) -> int:
        """Count unique response patterns"""
        unique = set()

        for result in results:
            # Hash based on status + length
            status = result.get('responseHeader', {}).get('statusCode', 0)
            length = len(result.get('responseBody', ''))
            unique.add((status, length))

        return len(unique)

    def get_interesting_responses(self, fuzzer_id: str, min_status: int = 200,
                                  max_status: int = 299) -> List[Dict]:
        """Get responses in specific status code range"""
        try:
            all_results = self.zap.fuzzer.messages(fuzzerid=fuzzer_id)

            interesting = [
                r for r in all_results
                if min_status <= r.get('responseHeader', {}).get('statusCode', 0) <= max_status
            ]

            return interesting

        except Exception as e:
            print(f"[ZAPFuzzer] Error getting responses: {e}")
            return []

    def stop_all(self):
        """Stop all active fuzzers"""
        for fuzzer_id in self.fuzzer_ids:
            try:
                self.zap.fuzzer.stop_fuzzer(fuzzerid=fuzzer_id)
            except Exception:  # Broad exception for robustness
                pass

    def generate_report(self) -> Dict:
        """Generate fuzzing summary report"""
        report = {
            'total_fuzzers': len(self.fuzzer_ids),
            'fuzzers': []
        }

        for fuzzer_id in self.fuzzer_ids:
            try:
                status = self.zap.fuzzer.status(fuzzerid=fuzzer_id)
                messages = self.zap.fuzzer.messages(fuzzerid=fuzzer_id)

                report['fuzzers'].append({
                    'id': fuzzer_id,
                    'state': status.get('state'),
                    'total_requests': len(messages),
                    'status_breakdown': self._status_breakdown(messages)
                })

            except Exception:  # Broad exception for robustness
                pass

        return report

    @staticmethod
    def _status_breakdown(messages: List[Dict]) -> Dict[int, int]:
        """Break down responses by status code"""
        breakdown = {}

        for msg in messages:
            status = msg.get('responseHeader', {}).get('statusCode', 0)
            breakdown[status] = breakdown.get(status, 0) + 1

        return breakdown
