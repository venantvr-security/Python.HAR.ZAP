"""
ZAP Fuzzer - Intelligent fuzzing with extracted tokens, rate limiting, and batch processing.
"""
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from zapv2 import ZAPv2

from .utils import retry_zap_call, RateLimiter, get_logger

logger = get_logger("zap.fuzzer")


class ZAPFuzzer:
    """Advanced fuzzing with ZAP using extracted tokens and rate limiting."""

    def __init__(
        self,
        zap: ZAPv2,
        wordlists: Dict[str, List[str]],
        config: Optional[Dict] = None
    ):
        self.zap = zap
        self.wordlists = wordlists
        self.fuzzer_ids = []
        self.config = config or {}

        # Configurable limits
        self.max_workers = self.config.get('max_workers', 5)
        self.max_payloads = self.config.get('max_payloads', 200)
        self.fuzzer_timeout = self.config.get('fuzzer_timeout', 300)
        self.idor_threshold = self.config.get('idor_threshold', 0.1)

        # Rate limiter
        self.rate_limiter = RateLimiter(
            requests_per_second=self.config.get('rate_limit', 10.0),
            burst=self.config.get('rate_burst', 20)
        )

    def fuzz_idor_endpoints(self, endpoints: List[Dict]) -> List[Dict]:
        """Fuzz endpoints with ID parameters using extracted IDs."""
        results = []
        id_wordlist = self.wordlists.get('ids', [])

        if not id_wordlist:
            logger.warning("no_ids_for_idor_fuzzing")
            return results

        logger.info("idor_fuzzing_start", endpoints=len(endpoints), ids=len(id_wordlist))

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._fuzz_idor_endpoint, ep, id_wordlist): ep
                for ep in endpoints
            }

            for future in as_completed(futures):
                endpoint = futures[future]
                try:
                    endpoint_results = future.result()
                    if endpoint_results:
                        results.extend(endpoint_results)
                except Exception as e:
                    logger.error("idor_fuzz_error", url=endpoint.get('url', '')[:30], error=str(e))

        logger.info("idor_fuzzing_complete", results=len(results))
        return results

    @retry_zap_call(max_retries=2)
    def _fuzz_idor_endpoint(self, endpoint: Dict, id_wordlist: List[str]) -> List[Dict]:
        """Fuzz single endpoint for IDOR vulnerabilities.

        Retourne un résultat PAR paramètre d'ID. Le vrai vecteur IDOR n'est pas
        forcément le premier paramètre (ex. `doc_id` après `user_id`) : abandonner
        après le premier param laissait des vulnérabilités non testées.
        """
        url = endpoint['url']
        params = endpoint.get('params', [])
        id_params = [p for p in params if 'id' in p.lower()]

        if not id_params:
            return []

        endpoint_results = []
        for param in id_params:
            self.rate_limiter.acquire()

            fuzzer_id = self.zap.fuzzer.add_fuzzer(
                url=url,
                fuzzlocations=[param],
                fuzztype='Custom'
            )
            self.fuzzer_ids.append(fuzzer_id)

            # Batch add payloads
            payloads = id_wordlist[:self.max_payloads]
            for payload in payloads:
                self.rate_limiter.acquire()
                self.zap.fuzzer.add_payload(
                    fuzzerid=fuzzer_id,
                    payload=str(payload)
                )

            self.zap.fuzzer.start_fuzzer(fuzzerid=fuzzer_id)
            self._wait_for_fuzzer(fuzzer_id)

            fuzzer_results = self.zap.fuzzer.messages(fuzzerid=fuzzer_id)
            vulnerable = self._analyze_idor_results(fuzzer_results)

            logger.debug(
                "idor_endpoint_result",
                url=url[:30],
                param=param,
                vulnerable=vulnerable,
                requests=len(payloads)
            )

            endpoint_results.append({
                'url': url,
                'param': param,
                'fuzzer_id': fuzzer_id,
                'total_requests': len(payloads),
                'vulnerable': vulnerable,
                'results': fuzzer_results
            })

        return endpoint_results

    def fuzz_authentication(self, endpoints: List[Dict]) -> List[Dict]:
        """Fuzz authentication endpoints with extracted usernames."""
        results = []
        usernames = self.wordlists.get('usernames', [])

        if not usernames:
            logger.warning("no_usernames_for_auth_fuzzing")
            return results

        logger.info("auth_fuzzing_start", endpoints=len(endpoints), usernames=len(usernames))

        for endpoint in endpoints:
            endpoint_results = self._fuzz_auth_endpoint(endpoint, usernames)
            if endpoint_results:
                results.extend(endpoint_results)

        return results

    @retry_zap_call(max_retries=2)
    def _fuzz_auth_endpoint(self, endpoint: Dict, usernames: List[str]) -> List[Dict]:
        """Fuzz single auth endpoint.

        Retourne un résultat PAR paramètre d'authentification (un endpoint peut
        exposer plusieurs champs : `username`, `email`…). Abandonner après le
        premier laissait les autres champs non fuzzés.
        """
        url = endpoint['url']
        params = endpoint.get('params', [])

        auth_params = [
            p for p in params
            if any(x in p.lower() for x in ['user', 'login', 'email', 'account'])
        ]

        if not auth_params:
            return []

        endpoint_results = []
        for param in auth_params:
            self.rate_limiter.acquire()

            fuzzer_id = self.zap.fuzzer.add_fuzzer(
                url=url,
                fuzzlocations=[param],
                fuzztype='Custom'
            )
            self.fuzzer_ids.append(fuzzer_id)

            for username in usernames[:self.max_payloads]:
                self.rate_limiter.acquire()
                self.zap.fuzzer.add_payload(fuzzerid=fuzzer_id, payload=username)

            self.zap.fuzzer.start_fuzzer(fuzzerid=fuzzer_id)
            self._wait_for_fuzzer(fuzzer_id)

            fuzzer_results = self.zap.fuzzer.messages(fuzzerid=fuzzer_id)

            logger.debug("auth_endpoint_result", url=url[:30], param=param)

            endpoint_results.append({
                'url': url,
                'param': param,
                'fuzzer_id': fuzzer_id,
                'results': fuzzer_results
            })

        return endpoint_results

    @retry_zap_call(max_retries=2)
    def fuzz_custom_params(self, url: str, param: str, wordlist_name: str) -> Dict:
        """Fuzz specific parameter with custom wordlist."""
        wordlist = self.wordlists.get(wordlist_name, [])

        if not wordlist:
            return {'error': f'Wordlist {wordlist_name} not found'}

        logger.info("custom_fuzzing_start", url=url[:30], param=param, wordlist=wordlist_name)

        self.rate_limiter.acquire()

        fuzzer_id = self.zap.fuzzer.add_fuzzer(
            url=url,
            fuzzlocations=[param],
            fuzztype='Custom'
        )
        self.fuzzer_ids.append(fuzzer_id)

        payloads = wordlist[:self.max_payloads]
        for payload in payloads:
            self.rate_limiter.acquire()
            self.zap.fuzzer.add_payload(fuzzerid=fuzzer_id, payload=str(payload))

        self.zap.fuzzer.start_fuzzer(fuzzerid=fuzzer_id)
        self._wait_for_fuzzer(fuzzer_id)

        results = self.zap.fuzzer.messages(fuzzerid=fuzzer_id)

        return {
            'url': url,
            'param': param,
            'wordlist': wordlist_name,
            'total_payloads': len(payloads),
            'fuzzer_id': fuzzer_id,
            'results': results,
            'unique_responses': self._count_unique_responses(results)
        }

    def fuzz_with_payloads(
        self,
        url: str,
        param: str,
        payloads: List[str],
        payload_type: str = 'custom'
    ) -> Dict:
        """Fuzz with explicit payload list."""
        logger.info("payload_fuzzing_start", url=url[:30], param=param, type=payload_type)

        self.rate_limiter.acquire()

        fuzzer_id = self.zap.fuzzer.add_fuzzer(
            url=url,
            fuzzlocations=[param],
            fuzztype='Custom'
        )
        self.fuzzer_ids.append(fuzzer_id)

        limited_payloads = payloads[:self.max_payloads]
        for payload in limited_payloads:
            self.rate_limiter.acquire()
            self.zap.fuzzer.add_payload(fuzzerid=fuzzer_id, payload=str(payload))

        self.zap.fuzzer.start_fuzzer(fuzzerid=fuzzer_id)
        self._wait_for_fuzzer(fuzzer_id)

        results = self.zap.fuzzer.messages(fuzzerid=fuzzer_id)

        return {
            'url': url,
            'param': param,
            'payload_type': payload_type,
            'total_payloads': len(limited_payloads),
            'fuzzer_id': fuzzer_id,
            'results': results,
            'status_breakdown': self._status_breakdown(results),
            'unique_responses': self._count_unique_responses(results)
        }

    def _wait_for_fuzzer(self, fuzzer_id: str):
        """Wait for fuzzer completion with timeout."""
        start = time.time()

        while time.time() - start < self.fuzzer_timeout:
            try:
                self.rate_limiter.acquire()
                status = self.zap.fuzzer.status(fuzzerid=fuzzer_id)
                state = status.get('state', 'UNKNOWN')

                if state == 'FINISHED':
                    logger.debug("fuzzer_completed", fuzzer_id=fuzzer_id)
                    return

                progress = status.get('progress', 0)
                if progress % 25 == 0:
                    logger.debug("fuzzer_progress", fuzzer_id=fuzzer_id, progress=f"{progress}%")

                time.sleep(2)

            except Exception as e:
                logger.warning("fuzzer_status_error", error=str(e))
                break

        logger.warning("fuzzer_timeout", fuzzer_id=fuzzer_id)

    def _analyze_idor_results(self, results: List[Dict]) -> bool:
        """Analyze fuzzer results for IDOR vulnerabilities."""
        if not results:
            return False

        success_responses = sum(
            1 for r in results
            if 200 <= r.get('responseHeader', {}).get('statusCode', 0) < 300
        )

        threshold = len(results) * self.idor_threshold
        return success_responses > threshold

    @staticmethod
    def _count_unique_responses(results: List[Dict]) -> int:
        """Count unique response patterns."""
        unique = set()
        for result in results:
            status = result.get('responseHeader', {}).get('statusCode', 0)
            length = len(result.get('responseBody', ''))
            unique.add((status, length))
        return len(unique)

    @staticmethod
    def _status_breakdown(messages: List[Dict]) -> Dict[int, int]:
        """Break down responses by status code."""
        breakdown = {}
        for msg in messages:
            status = msg.get('responseHeader', {}).get('statusCode', 0)
            breakdown[status] = breakdown.get(status, 0) + 1
        return breakdown

    def get_interesting_responses(
        self,
        fuzzer_id: str,
        min_status: int = 200,
        max_status: int = 299
    ) -> List[Dict]:
        """Get responses in specific status code range."""
        try:
            self.rate_limiter.acquire()
            all_results = self.zap.fuzzer.messages(fuzzerid=fuzzer_id)
            return [
                r for r in all_results
                if min_status <= r.get('responseHeader', {}).get('statusCode', 0) <= max_status
            ]
        except Exception as e:
            logger.error("get_responses_error", error=str(e))
            return []

    def stop_all(self):
        """Stop all active fuzzers."""
        logger.info("stopping_all_fuzzers", count=len(self.fuzzer_ids))
        for fuzzer_id in self.fuzzer_ids:
            try:
                self.zap.fuzzer.stop_fuzzer(fuzzerid=fuzzer_id)
            except Exception:
                pass

    def generate_report(self) -> Dict:
        """Generate fuzzing summary report."""
        report = {
            'total_fuzzers': len(self.fuzzer_ids),
            'fuzzers': []
        }

        for fuzzer_id in self.fuzzer_ids:
            try:
                self.rate_limiter.acquire()
                status = self.zap.fuzzer.status(fuzzerid=fuzzer_id)
                messages = self.zap.fuzzer.messages(fuzzerid=fuzzer_id)

                report['fuzzers'].append({
                    'id': fuzzer_id,
                    'state': status.get('state'),
                    'total_requests': len(messages),
                    'status_breakdown': self._status_breakdown(messages)
                })
            except Exception:
                pass

        return report
