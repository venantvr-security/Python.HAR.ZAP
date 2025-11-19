import time
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

    def _get_policy_for_target(self, target: Dict) -> str:
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
                except:
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
        except:
            pass
