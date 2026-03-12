"""
ZAP Orchestrator - Central pipeline: HAR → ZAP Context → Attacks → Alerts

All traffic flows through ZAP. Custom attacks run as ZAP scripts.
"""
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

from zapv2 import ZAPv2

from .utils import get_logger, retry_zap_call, RateLimiter
from .script_manager import ZAPScriptManager
from .zap_fuzzer import ZAPFuzzer
from .advanced_zap_config import AdvancedZAPConfig

logger = get_logger("zap.orchestrator")


class ZAPOrchestrator:
    """Central orchestrator: HAR data feeds ZAP which executes everything."""

    def __init__(
        self,
        zap_url: str,
        api_key: str,
        har_data: Dict,
        config: Dict,
        scripts_dir: str = './scripts'
    ):
        self.zap = ZAPv2(
            apikey=api_key,
            proxies={'http': zap_url, 'https': zap_url}
        )
        self.zap_url = zap_url
        self.api_key = api_key
        self.har_data = har_data
        self.config = config
        self.scripts_dir = Path(scripts_dir)

        self.rate_limiter = RateLimiter(
            requests_per_second=config.get('rate_limit', 10.0),
            burst=config.get('rate_burst', 20)
        )

        self.script_manager = ZAPScriptManager(self.zap, scripts_dir, config)
        self.advanced_config = AdvancedZAPConfig(self.zap)
        self.fuzzer: Optional[ZAPFuzzer] = None
        self.context_id: Optional[str] = None
        self.context_name = "HAR-Context"

    def run_pipeline(self, strategies: Optional[List[str]] = None) -> Dict:
        """
        Execute full pipeline:
        1. Create ZAP context from HAR
        2. Configure auth
        3. Populate site tree
        4. Load attack scripts
        5. Run discovery (spider)
        6. Run scans (passive + active)
        7. Collect alerts
        """
        logger.info("pipeline_start", strategies=strategies)
        results = {
            'context': None,
            'discovery': {},
            'scans': {},
            'alerts': [],
            'summary': {}
        }

        # 1. Create context from HAR
        self.context_id = self._create_context_from_har()
        results['context'] = {'id': self.context_id, 'name': self.context_name}

        # 2. Configure auth from HAR
        self._configure_auth()

        # 3. Populate site tree from HAR URLs
        self._populate_site_tree()

        # 4. Load custom attack scripts
        scripts_loaded = self._load_attack_scripts(strategies)
        results['scans']['scripts_loaded'] = scripts_loaded

        # 5. Discovery phase
        results['discovery'] = self._run_discovery()

        # 6. Scan phase
        results['scans'].update(self._run_scans(strategies))

        # 7. Collect all alerts
        results['alerts'] = self.get_alerts()
        results['summary'] = self._build_summary(results)

        logger.info("pipeline_complete", alerts=len(results['alerts']))
        return results

    @retry_zap_call(max_retries=3)
    def _create_context_from_har(self) -> str:
        """Create ZAP context with HAR domains as scope."""
        logger.info("creating_context")

        # Remove existing context if present
        try:
            self.zap.context.remove_context(self.context_name)
        except Exception:
            pass

        self.rate_limiter.acquire()
        context_id = self.zap.context.new_context(self.context_name)

        # Include domains from HAR
        domains = self.har_data.get('domains', set())
        scope_domains = self.config.get('scope_domains', [])

        # Use scope_domains if specified, else use HAR domains
        target_domains = scope_domains if scope_domains else list(domains)

        for domain in target_domains:
            try:
                self.rate_limiter.acquire()
                # Escape dots for regex
                pattern = f".*{domain.replace('.', '\\\\.')}.*"
                self.zap.context.include_in_context(self.context_name, pattern)
                logger.debug("domain_included", domain=domain)
            except Exception as e:
                logger.warning("domain_include_failed", domain=domain, error=str(e))

        # Exclude configured domains
        exclude_domains = self.config.get('exclude_domains', [])
        for domain in exclude_domains:
            try:
                self.rate_limiter.acquire()
                pattern = f".*{domain.replace('.', '\\\\.')}.*"
                self.zap.context.exclude_from_context(self.context_name, pattern)
            except Exception:
                pass

        logger.info("context_created", id=context_id, domains=len(target_domains))
        return context_id

    @retry_zap_call(max_retries=2)
    def _configure_auth(self):
        """Configure auth headers via ZAP replacer rules."""
        auth_headers = self.har_data.get('auth_headers', {})
        if not auth_headers:
            logger.debug("no_auth_headers")
            return

        logger.info("configuring_auth", headers=len(auth_headers))

        for header, value in auth_headers.items():
            try:
                self.rate_limiter.acquire()
                self.zap.replacer.add_rule(
                    description=f"HAR-Auth-{header}",
                    enabled=True,
                    matchtype='REQ_HEADER',
                    matchstring=header,
                    replacement=value
                )
                logger.debug("auth_rule_added", header=header)
            except Exception as e:
                logger.warning("auth_rule_failed", header=header, error=str(e))

    def _populate_site_tree(self):
        """Populate ZAP site tree with HAR URLs."""
        urls = list(self.har_data.get('urls', []))
        max_urls = self.config.get('max_urls', 100)
        urls = urls[:max_urls]

        logger.info("populating_site_tree", count=len(urls))

        for url in urls:
            try:
                self.rate_limiter.acquire()
                self.zap.core.access_url(url)
            except Exception:
                pass

    def _load_attack_scripts(self, strategies: Optional[List[str]] = None) -> Dict:
        """Load attack scripts for enabled strategies."""
        loaded = {'active': 0, 'passive': 0}

        # Get enabled strategies from config
        attack_strategies = self.config.get('attack_strategies', [])
        enabled_ids = [s['id'] for s in attack_strategies if s.get('enabled', True)]

        if strategies:
            enabled_ids = [s for s in enabled_ids if s in strategies]

        logger.info("loading_attack_scripts", strategies=enabled_ids)

        # Map strategy to script
        script_map = {
            'jwt': 'active/jwt_scanner.js',
            'cors': 'active/cors_scanner.js',
            'http_smuggling': 'active/smuggling_scanner.js',
            'cache_poison': 'active/cache_scanner.js',
            'redteam': 'active/redteam_scanner.js',
        }

        for strategy_id in enabled_ids:
            script_rel = script_map.get(strategy_id)
            if script_rel:
                script_path = self.scripts_dir / script_rel
                if script_path.exists():
                    if self.script_manager.load_script(str(script_path), 'active'):
                        self.script_manager.enable_script(script_path.stem)
                        loaded['active'] += 1

        # Load all passive scripts
        passive_dir = self.scripts_dir / 'passive'
        if passive_dir.exists():
            for script_path in passive_dir.glob('*.js'):
                if self.script_manager.load_script(str(script_path), 'passive'):
                    self.script_manager.enable_script(script_path.stem)
                    loaded['passive'] += 1

        return loaded

    def _run_discovery(self) -> Dict:
        """Run spider for URL discovery."""
        results = {'spider': {}, 'ajax_spider': {}}

        # Get first domain as base URL
        urls = list(self.har_data.get('urls', []))
        if not urls:
            return results

        base_url = urls[0]
        parsed = urlparse(base_url)
        target = f"{parsed.scheme}://{parsed.netloc}"

        # Traditional spider
        try:
            self.rate_limiter.acquire()
            scan_id = self.zap.spider.scan(
                url=target,
                contextname=self.context_name,
                recurse=True
            )
            self._wait_spider(scan_id)
            discovered = self.zap.spider.results(scan_id)
            results['spider'] = {'scan_id': scan_id, 'discovered': len(discovered)}
            logger.info("spider_complete", discovered=len(discovered))
        except Exception as e:
            logger.warning("spider_failed", error=str(e))

        return results

    def _run_scans(self, strategies: Optional[List[str]] = None) -> Dict:
        """Run passive and active scans."""
        results = {'passive': {}, 'active': {}}

        # Wait for passive scan
        logger.info("waiting_passive_scan")
        self._wait_passive_scan()
        results['passive']['complete'] = True

        # Active scan on fuzzable URLs
        fuzzable = self.har_data.get('fuzzable_urls', [])
        max_fuzzable = self.config.get('max_fuzzable_urls', 20)
        targets = fuzzable[:max_fuzzable]

        if not targets:
            # Fallback to API endpoints
            targets = self.har_data.get('api_endpoints', [])[:10]

        logger.info("active_scan_start", targets=len(targets))
        scan_ids = []

        for target in targets:
            url = target.get('url', '') if isinstance(target, dict) else target
            if not url:
                continue

            try:
                self.rate_limiter.acquire()
                scan_id = self.zap.ascan.scan(
                    url=url,
                    contextname=self.context_name,
                    recurse=False
                )
                scan_ids.append(scan_id)
            except Exception as e:
                logger.debug("ascan_failed", url=url[:50], error=str(e))

        # Wait for active scans
        for scan_id in scan_ids:
            self._wait_ascan(scan_id)

        results['active']['scans'] = len(scan_ids)
        return results

    def _wait_spider(self, scan_id: str, timeout: int = 120):
        """Wait for spider completion."""
        import time
        start = time.time()
        while time.time() - start < timeout:
            try:
                status = int(self.zap.spider.status(scan_id))
                if status >= 100:
                    return
                time.sleep(2)
            except Exception:
                break

    def _wait_passive_scan(self, timeout: int = 60):
        """Wait for passive scan queue to empty."""
        import time
        start = time.time()
        while time.time() - start < timeout:
            try:
                records = int(self.zap.pscan.records_to_scan)
                if records == 0:
                    return
                time.sleep(1)
            except Exception:
                break

    def _wait_ascan(self, scan_id: str, timeout: int = 300):
        """Wait for active scan completion."""
        import time
        start = time.time()
        while time.time() - start < timeout:
            try:
                self.rate_limiter.acquire()
                status = int(self.zap.ascan.status(scan_id))
                if status >= 100:
                    return
                time.sleep(3)
            except Exception:
                break

    @retry_zap_call(max_retries=2)
    def get_alerts(self, risk: Optional[str] = None) -> List[Dict]:
        """Get all ZAP alerts."""
        self.rate_limiter.acquire()
        alerts = self.zap.core.alerts()

        if risk:
            alerts = [a for a in alerts if a.get('risk', '').lower() == risk.lower()]

        return alerts

    def _build_summary(self, results: Dict) -> Dict:
        """Build summary from results."""
        alerts = results.get('alerts', [])

        by_risk = {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
        for alert in alerts:
            risk = alert.get('risk', 'Informational')
            by_risk[risk] = by_risk.get(risk, 0) + 1

        return {
            'total_alerts': len(alerts),
            'by_risk': by_risk,
            'urls_scanned': len(self.har_data.get('urls', [])),
            'context': self.context_name
        }

    def run_single_strategy(self, strategy_id: str) -> Dict:
        """Run a single attack strategy via ZAP."""
        logger.info("running_strategy", strategy=strategy_id)

        # Ensure context exists
        if not self.context_id:
            self.context_id = self._create_context_from_har()
            self._configure_auth()
            self._populate_site_tree()

        # Load strategy script
        self._load_attack_scripts([strategy_id])

        # Run active scan with script
        results = self._run_scans([strategy_id])
        alerts = self.get_alerts()

        return {
            'strategy': strategy_id,
            'scans': results,
            'alerts': alerts,
            'routed_via_zap': True
        }

    def run_fuzzing(self, targets: Optional[List[str]] = None) -> Dict:
        """Run ZAP fuzzer on extracted endpoints."""
        logger.info("fuzzing_start")

        # Build wordlists from HAR
        wordlists = self._build_wordlists_from_har()

        self.fuzzer = ZAPFuzzer(self.zap, wordlists, self.config)

        results = {'idor': [], 'auth': [], 'custom': []}

        # IDOR fuzzing on endpoints with ID params
        fuzzable = self.har_data.get('fuzzable_urls', [])
        idor_targets = [t for t in fuzzable if any('id' in p.lower() for p in t.get('params', []))]

        if idor_targets:
            results['idor'] = self.fuzzer.fuzz_idor_endpoints(idor_targets[:10])

        # Auth endpoint fuzzing
        auth_endpoints = [
            t for t in fuzzable
            if any(x in t.get('url', '').lower() for x in ['login', 'auth', 'signin', 'user'])
        ]
        if auth_endpoints:
            results['auth'] = self.fuzzer.fuzz_authentication(auth_endpoints[:5])

        # Custom fuzzing with payloads from config
        payloads = self.config.get('red_team_payloads', {})
        if targets and payloads:
            for target in targets[:5]:
                url = target.get('url', '') if isinstance(target, dict) else target
                params = target.get('params', ['q']) if isinstance(target, dict) else ['q']
                for param in params[:2]:
                    for payload_type in ['sqli', 'xss']:
                        if payload_type in payloads:
                            result = self.fuzzer.fuzz_with_payloads(
                                url, param,
                                payloads[payload_type][:50],
                                payload_type
                            )
                            results['custom'].append(result)

        logger.info("fuzzing_complete", idor=len(results['idor']), auth=len(results['auth']))
        return results

    def _build_wordlists_from_har(self) -> Dict[str, List[str]]:
        """Extract wordlists from HAR data."""
        wordlists = {'ids': [], 'usernames': [], 'tokens': []}

        # Extract IDs from URLs
        import re
        for url in self.har_data.get('urls', []):
            # UUID pattern
            uuids = re.findall(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', url, re.I)
            wordlists['ids'].extend(uuids)
            # Numeric IDs
            nums = re.findall(r'/(\d+)(?:/|$|\?)', url)
            wordlists['ids'].extend(nums)

        # Extract tokens
        wordlists['tokens'] = list(self.har_data.get('extracted_tokens', {}).values())

        # Dedupe
        wordlists['ids'] = list(set(wordlists['ids']))[:100]
        wordlists['tokens'] = list(set(wordlists['tokens']))[:50]

        return wordlists

    def configure_advanced_auth(self, auth_config: Dict):
        """Configure advanced authentication via ZAP."""
        self.advanced_config.configure_authentication(auth_config)

    def configure_session(self, session_config: Dict):
        """Configure session management."""
        self.advanced_config.configure_session_management(session_config)

    def configure_proxy_chain(self, proxy_config: Dict):
        """Configure upstream proxy (e.g., TOR)."""
        self.advanced_config.configure_proxy_chain(proxy_config)

    def run_ajax_spider(self, target_url: Optional[str] = None) -> Dict:
        """Run AJAX spider for JS-heavy apps."""
        urls = list(self.har_data.get('urls', []))
        if not urls and not target_url:
            return {'error': 'No target URL'}

        target = target_url or urls[0]
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        logger.info("ajax_spider_start", target=base)

        try:
            self.rate_limiter.acquire()
            self.zap.ajaxSpider.set_option_max_duration(10)
            self.zap.ajaxSpider.set_option_browser_id('firefox-headless')

            scan_id = self.zap.ajaxSpider.scan(url=base, inscope='true')

            # Wait for completion
            import time
            start = time.time()
            while time.time() - start < 660:  # 11 min max
                status = self.zap.ajaxSpider.status(scan_id)
                if status == 'stopped':
                    break
                time.sleep(5)

            results = self.zap.ajaxSpider.full_results(scan_id)
            discovered = [r.get('url') for r in results if isinstance(r, dict)]

            logger.info("ajax_spider_complete", discovered=len(discovered))
            return {'scan_id': scan_id, 'discovered_urls': discovered}

        except Exception as e:
            logger.error("ajax_spider_failed", error=str(e))
            return {'error': str(e)}

    def export_session(self, output_path: str) -> bool:
        """Export ZAP session for later reuse."""
        try:
            self.zap.core.save_session(name=output_path, overwrite='true')
            logger.info("session_exported", path=output_path)
            return True
        except Exception as e:
            logger.error("session_export_failed", error=str(e))
            return False

    def import_session(self, session_path: str) -> bool:
        """Import existing ZAP session."""
        try:
            self.zap.core.load_session(name=session_path)
            logger.info("session_imported", path=session_path)
            return True
        except Exception as e:
            logger.error("session_import_failed", error=str(e))
            return False

    def get_full_report(self) -> Dict:
        """Get comprehensive report with all ZAP data."""
        return {
            'alerts': self.get_alerts(),
            'sites': self.zap.core.sites,
            'urls': self.zap.core.urls(),
            'context': self.context_name,
            'messages_count': len(self.zap.core.messages(start=0, count=1000)),
            'scan_progress': {
                'passive_queue': self.zap.pscan.records_to_scan
            }
        }

    def shutdown(self):
        """Cleanup."""
        logger.info("shutdown")
        try:
            if self.fuzzer:
                self.fuzzer.stop_all()
            self.zap.replacer.remove_all_rules()
        except Exception:
            pass
