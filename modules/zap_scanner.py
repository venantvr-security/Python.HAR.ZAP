import time
from collections import defaultdict
from typing import Dict, List

from zapv2 import ZAPv2


class ZAPScanner:

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

    def configure_context(self):
        print("[ZAP] Configuring context and authentication")

        if self.har_data['auth_headers']:
            for header, value in self.har_data['auth_headers'].items():
                try:
                    self.zap.replacer.add_rule(
                        description=f"Auto-inject {header}",
                        enabled=True,
                        matchtype='REQ_HEADER',
                        matchstring=header,
                        replacement=value
                    )
                    print(f"[ZAP] Added auth header: {header}")
                except Exception as e:
                    print(f"[ZAP] Warning: Could not add header rule: {e}")

    def populate_site_tree(self):
        print(f"[ZAP] Populating site tree with {len(self.har_data['urls'])} URLs")

        for url in list(self.har_data['urls'])[:100]:
            try:
                self.zap.core.access_url(url)
            except Exception as e:
                print(f"[ZAP] Warning accessing {url}: {e}")

        time.sleep(2)

    def run_ajax_spider(self, target_url: str, context_name: str = None, max_duration: int = 10) -> Dict:
        """
        Execute Ajax Spider for JavaScript-heavy applications.

        Arachni-inspired: DOM crawling, AJAX request interception.
        Discovers hidden endpoints not in HAR.
        """
        print(f"[ZAP] Starting Ajax Spider on {target_url}")

        try:
            # Configure Ajax Spider
            self.zap.ajaxSpider.set_option_max_duration(max_duration)
            self.zap.ajaxSpider.set_option_max_crawl_depth(5)
            self.zap.ajaxSpider.set_option_number_of_browsers(2)
            self.zap.ajaxSpider.set_option_browser_id('firefox-headless')

            # Start spider
            scan_id = self.zap.ajaxSpider.scan(
                url=target_url,
                inscope='true',
                contextname=context_name
            )

            print(f"[ZAP] Ajax Spider started (scan_id: {scan_id})")

            # Monitor progress (Ajax Spider doesn't have percentage)
            start_time = time.time()
            max_wait = max_duration * 60 + 30  # Convert to seconds + buffer

            while time.time() - start_time < max_wait:
                status = self.zap.ajaxSpider.status(scan_id)

                if status == 'stopped':
                    print("[ZAP] Ajax Spider completed")
                    break

                results_count = self.zap.ajaxSpider.number_of_results(scan_id)
                print(f"[ZAP] Ajax Spider running... ({results_count} requests discovered)")
                time.sleep(5)

            # Get results
            full_results = self.zap.ajaxSpider.full_results(scan_id)

            # Extract discovered URLs
            discovered_urls = []
            if full_results:
                for result in full_results:
                    if isinstance(result, dict) and 'url' in result:
                        discovered_urls.append(result['url'])

            print(f"[ZAP] Ajax Spider discovered {len(discovered_urls)} URLs")

            return {
                'scan_id': scan_id,
                'discovered_urls': discovered_urls,
                'total_requests': self.zap.ajaxSpider.number_of_results(scan_id)
            }

        except Exception as e:
            print(f"[ZAP] Ajax Spider error: {e}")
            return {'scan_id': None, 'discovered_urls': [], 'total_requests': 0}

    def run_platform_fingerprinting(self, target_url: str) -> Dict:
        """
        Platform fingerprinting (Arachni-inspired).
        Detects OS, web server, frameworks, languages via passive scanners.
        """
        print(f"[ZAP] Platform fingerprinting on {target_url}")

        try:
            # Enable tech detection passive scanners
            tech_scanners = ['10055', '10096', '10109']  # CSP, Timestamp, Wappalyzer
            for scanner_id in tech_scanners:
                try:
                    self.zap.pscan.enable_scanners(scanner_id)
                except Exception:
                    pass

            # Access target to generate traffic
            self.zap.core.access_url(target_url)
            time.sleep(2)

            # Wait for passive scan
            while int(self.zap.pscan.records_to_scan) > 0:
                time.sleep(1)

            # Extract technology info from alerts
            alerts = self.zap.core.alerts(baseurl=target_url)
            technologies = defaultdict(list)

            for alert in alerts:
                title = alert.get('alert', '').lower()
                evidence = alert.get('evidence', '')

                if 'server' in title or 'technology' in title or 'application' in title:
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

            # Also check Server headers from site tree
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
                                    'evidence': header,
                                    'confidence': 'High'
                                })
                                break
                    break

            fingerprint = {
                'target': target_url,
                'technologies': dict(technologies),
                'scanner_count': len(technologies)
            }

            print(f"[ZAP] Fingerprinting found {len(technologies)} technology categories")
            return fingerprint

        except Exception as e:
            print(f"[ZAP] Fingerprinting error: {e}")
            return {'target': target_url, 'technologies': {}, 'scanner_count': 0}

    def run_traditional_spider(self, target_url: str, context_name: str = None, max_duration: int = 10) -> Dict:
        """
        Execute traditional spider for static content discovery.
        """
        print(f"[ZAP] Starting traditional spider on {target_url}")

        try:
            # Configure spider
            self.zap.spider.set_option_max_duration(max_duration)
            self.zap.spider.set_option_max_depth(5)
            self.zap.spider.set_option_max_children(10)

            # Start spider
            scan_id = self.zap.spider.scan(
                url=target_url,
                maxchildren=10,
                recurse=True,
                contextname=context_name,
                subtreeonly=False
            )

            print(f"[ZAP] Spider started (scan_id: {scan_id})")

            # Monitor progress
            while int(self.zap.spider.status(scan_id)) < 100:
                progress = self.zap.spider.status(scan_id)
                print(f"[ZAP] Spider progress: {progress}%")
                time.sleep(2)

            # Get results
            discovered_urls = self.zap.spider.results(scan_id)

            print(f"[ZAP] Spider discovered {len(discovered_urls)} URLs")

            return {
                'scan_id': scan_id,
                'discovered_urls': discovered_urls
            }

        except Exception as e:
            print(f"[ZAP] Spider error: {e}")
            return {'scan_id': None, 'discovered_urls': []}

    def execute_targeted_scans(self) -> List[Dict]:
        scan_results = []

        if self.scan_config.get('scan_fuzzable_urls', True):
            print(f"[ZAP] Scanning {len(self.har_data['fuzzable_urls'])} fuzzable URLs")

            for target in self.har_data['fuzzable_urls'][:20]:
                url = target['url']
                params = target['params']

                print(f"[ZAP] Active scan on: {url} (params: {', '.join(params)})")

                try:
                    scan_id = self.zap.ascan.scan(
                        url=url,
                        recurse=False,
                        inscopeonly=False,
                        scanpolicyname=self._get_policy_for_target(target)
                    )

                    self._wait_for_scan(scan_id, url)

                    scan_results.append({
                        'url': url,
                        'scan_id': scan_id,
                        'params': params
                    })

                except Exception as e:
                    print(f"[ZAP] Error scanning {url}: {e}")

        if self.scan_config.get('scan_api_endpoints', True) and self.har_data['api_endpoints']:
            print(f"[ZAP] Scanning {len(self.har_data['api_endpoints'])} API endpoints")

            for api in self.har_data['api_endpoints'][:10]:
                url = api['url']
                print(f"[ZAP] API scan: {url}")

                try:
                    scan_id = self.zap.ascan.scan(
                        url=url,
                        recurse=False,
                        inscopeonly=False,
                        scanpolicyname='API-Minimal'
                    )

                    self._wait_for_scan(scan_id, url)

                    scan_results.append({
                        'url': url,
                        'scan_id': scan_id,
                        'type': 'api'
                    })

                except Exception as e:
                    print(f"[ZAP] Error scanning API {url}: {e}")

        return scan_results

    @staticmethod
    def _get_policy_for_target(target: Dict) -> str:
        params = target.get('params', [])

        if any('sql' in p.lower() or 'id' in p.lower() for p in params):
            return 'SQL-Injection'
        elif any('file' in p.lower() or 'path' in p.lower() for p in params):
            return 'Path-Traversal'
        else:
            return 'Default Policy'

    def _wait_for_scan(self, scan_id: str, url: str, max_wait: int = 300):
        start_time = time.time()
        last_progress = -1

        while time.time() - start_time < max_wait:
            try:
                status = int(self.zap.ascan.status(scan_id))

                if status != last_progress and status % 10 == 0:
                    print(f"[ZAP] Scan progress for {url}: {status}%")
                    last_progress = status

                if status >= 100:
                    print(f"[ZAP] Scan completed for {url}")
                    return

                time.sleep(3)

            except Exception as e:
                print(f"[ZAP] Error checking scan status: {e}")
                break

        print(f"[ZAP] Scan timeout or stopped for {url}")

    def configure_scan_policies(self):
        print("[ZAP] Configuring scan policies")

        try:
            policies = self.zap.ascan.scan_policy_names
            print(f"[ZAP] Available policies: {policies}")

            disabled_scanners = [
                '10202',  # Absence of Anti-CSRF Tokens
                '10096',  # Timestamp Disclosure
                '10105',  # Weak Authentication Method
            ]

            for scanner_id in disabled_scanners:
                try:
                    self.zap.ascan.set_scanner_alert_threshold(
                        id=scanner_id,
                        alertthreshold='OFF'
                    )
                except Exception:  # Broad exception for robustness
                    pass

        except Exception as e:
            print(f"[ZAP] Warning configuring policies: {e}")

    def get_alerts(self, risk_level: str = None) -> List[Dict]:
        alerts = self.zap.core.alerts()

        if risk_level:
            alerts = [a for a in alerts if a.get('risk', '').lower() == risk_level.lower()]

        return alerts

    def shutdown(self):
        print("[ZAP] Shutting down ZAP")
        try:
            self.zap.core.shutdown()
        except Exception:  # Broad exception for robustness
            pass
