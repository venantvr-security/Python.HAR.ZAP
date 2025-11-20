"""
Meta-Analysis Engine - Arachni Meta-Plugin inspired

Cross-endpoint correlation, pattern detection, and aggregate vulnerability analysis.
"""
import statistics
from collections import defaultdict
from typing import Dict, List
from urllib.parse import urlparse


class MetaAnalyzer:
    """
    Arachni Meta-Plugins: Uniform vulnerability detection across endpoints.

    Capabilities:
    - Detect parameters vulnerable across multiple endpoints
    - Identify application-wide misconfigurations
    - Correlate timing attack results
    - Find authentication bypass patterns
    """

    def __init__(self, alerts: List[Dict]):
        self.alerts = alerts
        self.patterns = defaultdict(list)

    def find_uniform_vulnerabilities(self) -> Dict[str, List[str]]:
        """
        Identify parameters vulnerable across multiple endpoints.

        Arachni Uniformity plugin: Compares by element_type + input_name + check_type.
        Indicates lack of central sanitization point.

        Example: 'id' parameter vulnerable to SQLi in 15 different URLs.
        This suggests application-wide vulnerable code pattern.
        """
        # Group by (check_type, input_name, element_type)
        vuln_groups = defaultdict(set)  # (check, param, elem_type) -> {urls}

        for alert in self.alerts:
            param = alert.get('param', '')
            url = alert.get('url', '')
            check_type = alert.get('alert', '')

            # Determine element type (Arachni: link, form, cookie, header)
            # ZAP doesn't always provide this, infer from attack type
            if alert.get('attack', ''):
                attack = alert.get('attack', '')
                if 'Cookie' in alert.get('evidence', ''):
                    element_type = 'cookie'
                elif param in ['Authorization', 'User-Agent', 'Referer']:
                    element_type = 'header'
                elif 'POST' in alert.get('method', 'GET'):
                    element_type = 'form'
                else:
                    element_type = 'link'
            else:
                element_type = 'passive'

            # Skip passive issues (Arachni uniformity plugin behavior)
            if element_type == 'passive':
                continue

            if param and url:
                key = (check_type, param, element_type)
                vuln_groups[key].add(url)

        # Filter: only flag if vulnerable in multiple pages (Arachni: 2+, we use 3+)
        uniform_vulns = {}
        for (check_type, param, elem_type), urls in vuln_groups.items():
            if len(urls) >= 3:
                key = f"{check_type} on {elem_type}:{param}"
                uniform_vulns[key] = {
                    'urls': list(urls),
                    'count': len(urls),
                    'element_type': elem_type,
                    'param': param,
                    'check_type': check_type,
                    'issue': 'Lack of central/single point of input sanitization'
                }

        if uniform_vulns:
            print(f"[Meta] Found {len(uniform_vulns)} uniform vulnerabilities")
            for key, data in uniform_vulns.items():
                print(f"[Meta]   {key}: {data['count']} pages")

        return uniform_vulns

    def detect_timing_anomalies(self, race_results: List[Dict] = None) -> Dict:
        """
        Flag inconsistent race condition or timing attack results.

        Arachni: Timing attack trustworthiness assessment via variance analysis.
        """
        if not race_results:
            # Fallback: analyze timing-based alerts
            timing_alerts = [
                a for a in self.alerts
                if 'timing' in a.get('alert', '').lower() or
                   'blind' in a.get('alert', '').lower()
            ]

            if not timing_alerts:
                return {'status': 'no_timing_attacks', 'anomalies': []}

            return {
                'status': 'alert_based',
                'count': len(timing_alerts),
                'recommendation': 'Manual verification required for timing-based findings'
            }

        # Analyze race condition results
        success_rates = [r.get('success_rate', 0) for r in race_results]

        if len(success_rates) < 2:
            return {'status': 'insufficient_data'}

        mean_rate = statistics.mean(success_rates)
        stdev = statistics.stdev(success_rates) if len(success_rates) > 1 else 0

        # High variance = inconsistent = likely false positive
        if stdev > 0.2:
            return {
                'status': 'high_variance',
                'mean': mean_rate,
                'stdev': stdev,
                'recommendation': 'Race condition results inconsistent - retest or discard'
            }

        return {
            'status': 'consistent',
            'mean': mean_rate,
            'stdev': stdev
        }

    def find_authentication_patterns(self) -> Dict:
        """
        Detect authentication bypass patterns across endpoints.

        Patterns:
        - Multiple endpoints accessible without auth
        - Session fixation across multiple forms
        - Weak auth affecting entire subdomain
        """
        auth_issues = defaultdict(list)

        for alert in self.alerts:
            title = alert.get('alert', '').lower()
            url = alert.get('url', '')

            if any(keyword in title for keyword in ['auth', 'session', 'login', 'bypass']):
                auth_issues[title].append(url)

        # Group by domain
        domain_auth_issues = defaultdict(int)
        for urls in auth_issues.values():
            for url in urls:
                domain = urlparse(url).netloc
                domain_auth_issues[domain] += 1

        # Flag domains with 3+ different auth issues
        critical_domains = {
            domain: count
            for domain, count in domain_auth_issues.items()
            if count >= 3
        }

        if critical_domains:
            print(f"[Meta] Critical auth issues on {len(critical_domains)} domains")

        return {
            'auth_issues_by_type': {k: len(v) for k, v in auth_issues.items()},
            'critical_domains': critical_domains,
            'total_auth_alerts': sum(len(v) for v in auth_issues.values())
        }

    def deduplicate_alerts(self) -> List[Dict]:
        """
        Remove duplicate alerts keeping only highest confidence instance.

        Deduplication key: (alert_name, url, param)
        """
        unique_alerts = {}

        confidence_rank = {'Confirmed': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Tentative': 0}

        for alert in self.alerts:
            key = (
                alert.get('alert', ''),
                alert.get('url', ''),
                alert.get('param', '')
            )

            current_conf = confidence_rank.get(alert.get('confidence', 'Low'), 1)

            if key not in unique_alerts:
                unique_alerts[key] = alert
            else:
                existing_conf = confidence_rank.get(
                    unique_alerts[key].get('confidence', 'Low'), 1
                )
                if current_conf > existing_conf:
                    unique_alerts[key] = alert

        deduplicated = list(unique_alerts.values())
        removed = len(self.alerts) - len(deduplicated)

        if removed > 0:
            print(f"[Meta] Deduplicated {removed} alerts ({len(self.alerts)} → {len(deduplicated)})")

        return deduplicated

    def find_cascading_vulnerabilities(self) -> List[Dict]:
        """
        Identify vulnerability chains that compound severity.

        Examples:
        - XSS + missing CSP = Critical (easier exploitation)
        - IDOR + predictable session IDs = Critical (session hijacking)
        - SQLi + error disclosure = Critical (easier exploitation)
        """
        cascades = []

        # Build vulnerability map by URL
        url_vulns = defaultdict(set)
        for alert in self.alerts:
            url = alert.get('url', '')
            vuln_type = alert.get('alert', '').lower()
            url_vulns[url].add(vuln_type)

        # Define cascade patterns
        cascade_patterns = [
            ({'xss', 'cross-site scripting'}, {'csp', 'content security policy'}, 'XSS without CSP'),
            ({'sql injection', 'sqli'}, {'error', 'disclosure'}, 'SQLi with error disclosure'),
            ({'idor', 'insecure direct object'}, {'session', 'predictable'}, 'IDOR with weak sessions'),
            ({'csrf', 'cross-site request forgery'}, {'session fixation'}, 'CSRF + Session Fixation'),
        ]

        for url, vulns in url_vulns.items():
            for pattern_a, pattern_b, cascade_name in cascade_patterns:
                has_a = any(p in v for p in pattern_a for v in vulns)
                has_b = any(p in v for p in pattern_b for v in vulns)

                if has_a and has_b:
                    cascades.append({
                        'url': url,
                        'cascade_type': cascade_name,
                        'vulnerabilities': list(vulns),
                        'severity': 'CRITICAL'
                    })

        if cascades:
            print(f"[Meta] Found {len(cascades)} cascading vulnerabilities")

        return cascades

    def aggregate_by_severity(self) -> Dict[str, int]:
        """Group alerts by risk level"""
        severity_counts = defaultdict(int)

        for alert in self.alerts:
            risk = alert.get('risk', 'Informational')
            severity_counts[risk] += 1

        return dict(severity_counts)

    def aggregate_by_endpoint(self) -> Dict[str, List[Dict]]:
        """Group alerts by endpoint for focused remediation"""
        endpoint_alerts = defaultdict(list)

        for alert in self.alerts:
            url = alert.get('url', '')
            # Normalize URL (remove query params)
            base_url = url.split('?')[0]
            endpoint_alerts[base_url].append(alert)

        # Sort by alert count
        sorted_endpoints = dict(
            sorted(endpoint_alerts.items(), key=lambda x: len(x[1]), reverse=True)
        )

        print(f"[Meta] Aggregated alerts across {len(sorted_endpoints)} endpoints")
        return sorted_endpoints

    def generate_meta_report(self) -> Dict:
        """
        Generate comprehensive meta-analysis report.

        Returns all analysis results in structured format.
        """
        report = {
            'total_alerts': len(self.alerts),
            'uniform_vulnerabilities': self.find_uniform_vulnerabilities(),
            'authentication_patterns': self.find_authentication_patterns(),
            'cascading_vulnerabilities': self.find_cascading_vulnerabilities(),
            'severity_distribution': self.aggregate_by_severity(),
            'top_vulnerable_endpoints': dict(
                list(self.aggregate_by_endpoint().items())[:10]
            ),
            'deduplicated_count': len(self.deduplicate_alerts())
        }

        print(f"\n[Meta] Meta-Analysis Complete")
        print(f"[Meta]   Uniform vulns: {len(report['uniform_vulnerabilities'])}")
        print(f"[Meta]   Cascades: {len(report['cascading_vulnerabilities'])}")
        print(f"[Meta]   Auth issues: {report['authentication_patterns']['total_auth_alerts']}")

        return report
