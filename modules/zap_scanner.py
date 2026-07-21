"""
ZAP Scanner - Professional DAST automation with retry, rate limiting, and structured logging.
"""
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

from zapv2 import ZAPv2

from .utils import (
    ZAPConnectionError, ZAPTimeoutError, ScanError,
    retry_zap_call, RateLimiter, get_logger
)

logger = get_logger("zap.scanner")


class ZAPScanner:
    """Professional-grade ZAP scanner with resilient API calls."""

    def __init__(self, zap_config: Dict, har_data: Dict, scan_config: Dict):
        self.zap = ZAPv2(
            apikey=zap_config['api_key'],
            proxies={
                'http': zap_config['zap_url'],
                'https': zap_config['zap_url']
            }
        )
        self.har_data = har_data
        self.scan_config = scan_config
        self.base_url = zap_config['zap_url']

        # Rate limiter from config
        self.rate_limiter = RateLimiter(
            requests_per_second=scan_config.get('rate_limit', 10.0),
            burst=scan_config.get('rate_burst', 20)
        )

        # Configurable limits
        self.max_urls = scan_config.get('max_urls', 100)
        self.max_fuzzable = scan_config.get('max_fuzzable_urls', 20)
        self.max_api_endpoints = scan_config.get('max_api_endpoints', 10)
        self.max_scan_time = scan_config.get('max_scan_time', 300)

    @retry_zap_call(max_retries=3)
    def configure_context(self):
        """Configure ZAP context and authentication headers."""
        logger.info("configuring_context")

        if self.har_data.get('auth_headers'):
            for header, value in self.har_data['auth_headers'].items():
                self.rate_limiter.acquire()
                self.zap.replacer.add_rule(
                    description=f"Auto-inject {header}",
                    enabled=True,
                    matchtype='REQ_HEADER',
                    matchstring=header,
                    replacement=value
                )
                logger.debug("auth_header_added", header=header)

        excluded_domains = self.scan_config.get('exclude_domains', [])
        for domain in excluded_domains:
            try:
                self.rate_limiter.acquire()
                self.zap.context.exclude_from_context(
                    contextname='Default Context',
                    regex=f".*{domain}.*"
                )
                logger.debug("domain_excluded", domain=domain)
            except Exception as e:
                logger.warning("domain_exclusion_failed", domain=domain, error=str(e))

    @retry_zap_call(max_retries=3)
    def populate_site_tree(self):
        """Populate ZAP site tree from HAR URLs."""
        urls = list(self.har_data.get('urls', []))[:self.max_urls]
        logger.info("populating_site_tree", url_count=len(urls))

        for url in urls:
            try:
                self.rate_limiter.acquire()
                self.zap.core.access_url(url)
            except Exception as e:
                logger.debug("url_access_failed", url=url[:50], error=str(e))

        time.sleep(2)

    @retry_zap_call(max_retries=2)
    def run_ajax_spider(
        self,
        target_url: str,
        context_name: Optional[str] = None,
        max_duration: int = 10
    ) -> Dict:
        """Execute Ajax Spider for JavaScript-heavy applications."""
        logger.info("ajax_spider_start", target=target_url[:50], max_duration=max_duration)

        self.rate_limiter.acquire()
        self.zap.ajaxSpider.set_option_max_duration(max_duration)
        self.zap.ajaxSpider.set_option_max_crawl_depth(5)
        self.zap.ajaxSpider.set_option_number_of_browsers(2)
        self.zap.ajaxSpider.set_option_browser_id('firefox-headless')

        scan_id = self.zap.ajaxSpider.scan(
            url=target_url,
            inscope='true',
            contextname=context_name
        )

        logger.debug("ajax_spider_started", scan_id=scan_id)

        start_time = time.time()
        max_wait = max_duration * 60 + 30

        while time.time() - start_time < max_wait:
            self.rate_limiter.acquire()
            status = self.zap.ajaxSpider.status(scan_id)

            if status == 'stopped':
                logger.info("ajax_spider_completed", scan_id=scan_id)
                break

            results_count = self.zap.ajaxSpider.number_of_results(scan_id)
            logger.debug("ajax_spider_progress", discovered=results_count)
            time.sleep(5)

        full_results = self.zap.ajaxSpider.full_results(scan_id)
        discovered_urls = []

        if full_results:
            for result in full_results:
                if isinstance(result, dict) and 'url' in result:
                    discovered_urls.append(result['url'])

        logger.info("ajax_spider_results", discovered_count=len(discovered_urls))

        return {
            'scan_id': scan_id,
            'discovered_urls': discovered_urls,
            'total_requests': self.zap.ajaxSpider.number_of_results(scan_id)
        }

    @retry_zap_call(max_retries=2)
    def run_platform_fingerprinting(self, target_url: str) -> Dict:
        """Platform fingerprinting via passive scanners."""
        logger.info("fingerprinting_start", target=target_url[:50])

        tech_scanners = ['10055', '10096', '10109']
        for scanner_id in tech_scanners:
            try:
                self.rate_limiter.acquire()
                self.zap.pscan.enable_scanners(scanner_id)
            except Exception:
                pass

        self.rate_limiter.acquire()
        self.zap.core.access_url(target_url)
        time.sleep(2)

        # Wait for passive scan
        timeout = 30
        start = time.time()
        while time.time() - start < timeout:
            records = int(self.zap.pscan.records_to_scan)
            if records == 0:
                break
            time.sleep(1)

        alerts = self.zap.core.alerts(baseurl=target_url)
        technologies = defaultdict(list)

        for alert in alerts:
            title = alert.get('alert', '').lower()
            evidence = alert.get('evidence', '')

            if any(x in title for x in ['server', 'technology', 'application']):
                tech_type = 'web_server'
                if 'language' in title or 'framework' in title:
                    tech_type = 'framework'
                elif 'database' in title:
                    tech_type = 'database'

                technologies[tech_type].append({
                    'name': alert.get('alert', ''),
                    'evidence': evidence,
                    'confidence': alert.get('confidence', '')
                })

        # Extract Server header
        try:
            sites = self.zap.core.sites
            for site in sites:
                if target_url in site:
                    messages = self.zap.core.messages(baseurl=site, start=0, count=5)
                    for msg in messages:
                        if 'responseHeader' in msg:
                            header = msg['responseHeader']
                            if 'Server:' in header:
                                server = header.split('Server:')[1].split('\n')[0].strip()
                                technologies['web_server'].append({
                                    'name': f'Server: {server}',
                                    'evidence': server,
                                    'confidence': 'High'
                                })
                                break
                    break
        except Exception:
            pass

        logger.info("fingerprinting_complete", categories=len(technologies))

        return {
            'target': target_url,
            'technologies': dict(technologies),
            'scanner_count': len(technologies)
        }

    @retry_zap_call(max_retries=2)
    def run_traditional_spider(
        self,
        target_url: str,
        context_name: Optional[str] = None,
        max_duration: int = 10
    ) -> Dict:
        """Execute traditional spider for static content discovery."""
        logger.info("spider_start", target=target_url[:50], max_duration=max_duration)

        self.rate_limiter.acquire()
        self.zap.spider.set_option_max_duration(max_duration)
        self.zap.spider.set_option_max_depth(5)
        self.zap.spider.set_option_max_children(10)

        scan_id = self.zap.spider.scan(
            url=target_url,
            maxchildren=10,
            recurse=True,
            contextname=context_name,
            subtreeonly=False
        )

        logger.debug("spider_started", scan_id=scan_id)

        # Garde temporelle : sans borne, un spider bloqué à un statut < 100
        # (cible hors scope, scan gelé côté ZAP) ferait boucler indéfiniment ce
        # pipeline synchrone. max_duration est en minutes ; on ajoute une marge.
        deadline = time.time() + max_duration * 60 + 30
        while int(self.zap.spider.status(scan_id)) < 100:
            if time.time() > deadline:
                logger.warning("spider_timeout", scan_id=scan_id,
                               progress=f"{self.zap.spider.status(scan_id)}%")
                break
            progress = self.zap.spider.status(scan_id)
            logger.debug("spider_progress", progress=f"{progress}%")
            time.sleep(2)

        discovered_urls = self.zap.spider.results(scan_id)
        logger.info("spider_complete", discovered_count=len(discovered_urls))

        return {
            'scan_id': scan_id,
            'discovered_urls': discovered_urls
        }

    def execute_targeted_scans(self, progress_callback=None) -> List[Dict]:
        """Execute targeted active scans on fuzzable URLs and API endpoints.

        Optional `progress_callback` receives a dict on every meaningful tick:
        {'phase': 'scanning' | 'target_done',
         'target_index': int, 'target_total': int,
         'url': str, 'type': 'fuzzable' | 'api',
         'scan_progress': int (0-100) | None}
        It lets the caller stream progress into a UI without changing the return
        contract of this method.
        """
        scan_results = []
        fuzzable = []
        apis = []

        if self.scan_config.get('scan_fuzzable_urls', True):
            fuzzable = self.har_data.get('fuzzable_urls', [])[:self.max_fuzzable]
            logger.info("scanning_fuzzable_urls", count=len(fuzzable))

        if self.scan_config.get('scan_api_endpoints', True):
            apis = self.har_data.get('api_endpoints', [])[:self.max_api_endpoints]
            logger.info("scanning_api_endpoints", count=len(apis))

        total = len(fuzzable) + len(apis)

        def _emit(event: Dict) -> None:
            if progress_callback is None:
                return
            try:
                progress_callback(event)
            except Exception as e:
                logger.debug("progress_callback_error", error=str(e))

        for i, target in enumerate(fuzzable):
            _emit({
                'phase': 'scanning',
                'target_index': i + 1, 'target_total': total,
                'url': target.get('url', ''), 'type': 'fuzzable',
                'scan_progress': 0,
            })
            result = self._scan_single_target(
                target, target_type='fuzzable', progress_callback=progress_callback,
                target_index=i + 1, target_total=total,
            )
            if result:
                scan_results.append(result)
            _emit({'phase': 'target_done', 'target_index': i + 1, 'target_total': total,
                   'url': target.get('url', ''), 'type': 'fuzzable', 'scan_progress': 100})

        for j, api in enumerate(apis):
            idx = len(fuzzable) + j + 1
            _emit({
                'phase': 'scanning',
                'target_index': idx, 'target_total': total,
                'url': api.get('url', ''), 'type': 'api', 'scan_progress': 0,
            })
            result = self._scan_single_target(
                api, target_type='api', progress_callback=progress_callback,
                target_index=idx, target_total=total,
            )
            if result:
                scan_results.append(result)
            _emit({'phase': 'target_done', 'target_index': idx, 'target_total': total,
                   'url': api.get('url', ''), 'type': 'api', 'scan_progress': 100})

        return scan_results

    def get_scan_progress(self) -> Dict:
        """Live snapshot of ZAP state — safe to poll from a UI loop.

        Returns a dict with passive queue, spider sites, alert counts by risk.
        Never raises: any ZAP hiccup yields an empty dict entry.
        """
        snapshot: Dict = {
            'passive_records_to_scan': None,
            'alerts_by_risk': {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0},
            'sites': [],
        }
        try:
            snapshot['passive_records_to_scan'] = int(self.zap.pscan.records_to_scan)
        except Exception:
            pass
        try:
            for alert in self.zap.core.alerts() or []:
                risk = alert.get('risk', 'Informational')
                snapshot['alerts_by_risk'][risk] = snapshot['alerts_by_risk'].get(risk, 0) + 1
        except Exception:
            pass
        try:
            snapshot['sites'] = list(self.zap.core.sites or [])[:20]
        except Exception:
            pass
        return snapshot

    @retry_zap_call(max_retries=2)
    def _scan_single_target(self, target: Dict, target_type: str = 'generic',
                            progress_callback=None,
                            target_index: Optional[int] = None,
                            target_total: Optional[int] = None) -> Optional[Dict]:
        """Scan a single target with appropriate policy."""
        url = target.get('url', '')
        params = target.get('params', [])

        logger.debug("scanning_target", url=url[:50], params=params, type=target_type)

        try:
            self.rate_limiter.acquire()
            policy = 'API-Minimal' if target_type == 'api' else self._get_policy_for_target(target)

            scan_id = self.zap.ascan.scan(
                url=url,
                recurse=False,
                inscopeonly=False,
                scanpolicyname=policy
            )

            self._wait_for_scan(
                scan_id, url,
                progress_callback=progress_callback,
                target_index=target_index, target_total=target_total,
            )

            return {
                'url': url,
                'scan_id': scan_id,
                'params': params,
                'type': target_type
            }

        except ZAPTimeoutError:
            logger.warning("scan_timeout", url=url[:50])
            return None
        except Exception as e:
            logger.error("scan_failed", url=url[:50], error=str(e))
            return None

    @staticmethod
    def _get_policy_for_target(target: Dict) -> str:
        """Select scan policy based on target parameters."""
        params = target.get('params', [])

        if any('sql' in p.lower() or 'id' in p.lower() for p in params):
            return 'SQL-Injection'
        elif any('file' in p.lower() or 'path' in p.lower() for p in params):
            return 'Path-Traversal'
        return 'Default Policy'

    def _wait_for_scan(self, scan_id: str, url: str,
                       progress_callback=None,
                       target_index: Optional[int] = None,
                       target_total: Optional[int] = None):
        """Wait for scan completion with timeout, emitting progress."""
        start_time = time.time()
        last_progress = -1

        while time.time() - start_time < self.max_scan_time:
            try:
                self.rate_limiter.acquire()
                status = int(self.zap.ascan.status(scan_id))

                if status != last_progress:
                    if progress_callback is not None:
                        try:
                            progress_callback({
                                'phase': 'scanning',
                                'target_index': target_index,
                                'target_total': target_total,
                                'url': url,
                                'scan_progress': status,
                            })
                        except Exception:
                            pass
                    if status % 20 == 0:
                        logger.debug("scan_progress", url=url[:30], progress=f"{status}%")
                    last_progress = status

                if status >= 100:
                    logger.info("scan_completed", url=url[:30])
                    return

                time.sleep(3)

            except Exception as e:
                logger.warning("scan_status_error", error=str(e))
                break

        logger.warning("scan_timeout", url=url[:30])

    @retry_zap_call(max_retries=2)
    def configure_scan_policies(self):
        """Configure ZAP scan policies."""
        logger.info("configuring_policies")

        try:
            policies = self.zap.ascan.scan_policy_names
            logger.debug("available_policies", policies=policies)

            # Disable noisy scanners
            disabled_scanners = ['10202', '10096', '10105']
            for scanner_id in disabled_scanners:
                try:
                    self.rate_limiter.acquire()
                    self.zap.ascan.set_scanner_alert_threshold(
                        id=scanner_id,
                        alertthreshold='OFF'
                    )
                except Exception:
                    pass

        except Exception as e:
            logger.warning("policy_config_failed", error=str(e))

    def get_alerts(self, risk_level: Optional[str] = None) -> List[Dict]:
        """Get alerts, optionally filtered by risk level."""
        self.rate_limiter.acquire()
        alerts = self.zap.core.alerts()

        if risk_level:
            alerts = [a for a in alerts if a.get('risk', '').lower() == risk_level.lower()]

        logger.info("alerts_retrieved", count=len(alerts), filter=risk_level)
        return alerts

    def load_custom_scripts(self, scripts_dir: Optional[Path] = None) -> Dict[str, int]:
        """Load custom ZAP scripts (.js) from scripts/{active,passive}/ directories."""
        if scripts_dir is None:
            scripts_dir = Path(__file__).parent.parent / 'scripts'

        stats = {'active': 0, 'passive': 0, 'failed': 0}
        if not scripts_dir.exists():
            logger.info("scripts_dir_missing", path=str(scripts_dir))
            return stats

        for script_type in ('active', 'passive'):
            type_dir = scripts_dir / script_type
            if not type_dir.exists():
                continue
            for script_file in type_dir.glob('*.js'):
                try:
                    self.rate_limiter.acquire()
                    self.zap.script.load(
                        scriptname=script_file.stem,
                        scripttype=script_type,
                        scriptengine='ECMAScript',
                        filename=str(script_file)
                    )
                    self.zap.script.enable(script_file.stem)
                    stats[script_type] += 1
                    logger.info("script_loaded", name=script_file.name, type=script_type)
                except Exception as e:
                    stats['failed'] += 1
                    logger.warning("script_load_failed", name=script_file.name, error=str(e))

        return stats

    def shutdown(self):
        """Shutdown ZAP gracefully."""
        logger.info("shutting_down")
        try:
            self.zap.core.shutdown()
        except Exception:
            pass
