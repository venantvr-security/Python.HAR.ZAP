"""
Reporter - Multi-format security reports with OWASP mapping, timeline, and cURL reproduction.
"""
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse, parse_qs

from .utils import get_logger
from .owasp_mapper import OWASPMapper

logger = get_logger("reporter")

try:
    from .utils.masking import mask_sensitive_data, mask_string
except ImportError:
    def mask_sensitive_data(d): return d
    def mask_string(s): return s


class Reporter:
    """Security report generator with multiple output formats."""

    def __init__(self, output_dir: str = './output', config: Optional[Dict] = None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.config = config or {}

        self.include_curl = self.config.get('include_curl', True)
        self.include_timeline = self.config.get('include_timeline', True)
        self.include_owasp = self.config.get('include_owasp', True)

        self.owasp_mapper = OWASPMapper(self.config.get('owasp', {}))
        self.timeline: List[Dict] = []

    def add_timeline_event(self, event_type: str, description: str, data: Optional[Dict] = None):
        """Add event to scan timeline."""
        self.timeline.append({
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'type': event_type,
            'description': description,
            'data': data
        })

    def generate_console_report(self, alerts: List[Dict]):
        """Print console summary."""
        high = [a for a in alerts if a.get('risk') == 'High']
        medium = [a for a in alerts if a.get('risk') == 'Medium']
        low = [a for a in alerts if a.get('risk') == 'Low']
        info = [a for a in alerts if a.get('risk') == 'Informational']

        print("\n" + "=" * 80)
        print("SECURITY SCAN RESULTS")
        print("=" * 80)
        print(f"Total Alerts: {len(alerts)}")
        print(f"  High:   {len(high)}")
        print(f"  Medium: {len(medium)}")
        print(f"  Low:    {len(low)}")
        print(f"  Info:   {len(info)}")
        print("=" * 80)

        if high:
            print("\n[!] HIGH RISK ALERTS:")
            for alert in high:
                self._print_alert(alert)

        if medium:
            print("\n[!] MEDIUM RISK ALERTS:")
            for alert in medium[:10]:
                self._print_alert(alert)
            if len(medium) > 10:
                print(f"... and {len(medium) - 10} more medium alerts")

        # OWASP summary
        if self.include_owasp and alerts:
            owasp_report = self.owasp_mapper.map_alerts(alerts)
            print("\n" + "-" * 40)
            print(owasp_report.overall_score)
            if owasp_report.failed_categories:
                print(f"Failed: {', '.join(owasp_report.failed_categories)}")

    @staticmethod
    def _print_alert(alert: Dict):
        print(f"\n  [{alert.get('risk', 'Unknown')}] {alert.get('alert', 'No name')}")
        print(f"  URL: {mask_string(alert.get('url', 'N/A'))}")
        print(f"  CWE: {alert.get('cweid', 'N/A')}")
        desc = alert.get('description', 'N/A')
        print(f"  Description: {mask_string(desc[:200] if desc else 'N/A')}...")

    def save_json_report(self, alerts: List[Dict], har_summary: str = '') -> str:
        """Save JSON report with OWASP mapping and cURL commands."""
        masked_alerts = [mask_sensitive_data(alert) for alert in alerts]

        # Add cURL commands
        if self.include_curl:
            for alert in masked_alerts:
                alert['curl_command'] = self._generate_curl(alert)

        # Build report
        report_data = {
            'timestamp': self.timestamp,
            'generated_at': datetime.utcnow().isoformat() + 'Z',
            'har_analysis': mask_string(har_summary) if har_summary else None,
            'summary': {
                'total_alerts': len(alerts),
                'high': len([a for a in alerts if a.get('risk') == 'High']),
                'medium': len([a for a in alerts if a.get('risk') == 'Medium']),
                'low': len([a for a in alerts if a.get('risk') == 'Low']),
                'informational': len([a for a in alerts if a.get('risk') == 'Informational'])
            },
            'alerts': masked_alerts
        }

        # Add OWASP mapping
        if self.include_owasp:
            owasp_report = self.owasp_mapper.map_alerts(alerts)
            report_data['owasp_compliance'] = self.owasp_mapper.generate_report(owasp_report)

        # Add timeline
        if self.include_timeline and self.timeline:
            report_data['timeline'] = self.timeline

        output_file = self.output_dir / f"scan_report_{self.timestamp}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)

        logger.info("json_report_saved", path=str(output_file))
        print(f"\n[Report] JSON saved: {output_file}")
        return str(output_file)

    def save_sarif_report(self, alerts: List[Dict]) -> str:
        """Save SARIF format report for GitHub Security."""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "HAR-ZAP",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/your-repo/harzap",
                        "rules": self._generate_sarif_rules(alerts)
                    }
                },
                "results": self._generate_sarif_results(alerts)
            }]
        }

        output_file = self.output_dir / f"results_{self.timestamp}.sarif"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(sarif, f, indent=2)

        logger.info("sarif_report_saved", path=str(output_file))
        return str(output_file)

    def _generate_sarif_rules(self, alerts: List[Dict]) -> List[Dict]:
        """Generate SARIF rule definitions."""
        rules = {}
        for alert in alerts:
            rule_id = str(alert.get('pluginId', 'unknown'))
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": alert.get('alert', 'Unknown'),
                    "shortDescription": {"text": alert.get('alert', '')[:100]},
                    "fullDescription": {"text": alert.get('description', '')[:500]},
                    "helpUri": f"https://www.zaproxy.org/docs/alerts/{rule_id}/",
                    "defaultConfiguration": {
                        "level": self._risk_to_sarif_level(alert.get('risk'))
                    },
                    "properties": {
                        "tags": ["security"],
                        "security-severity": self._risk_to_severity_score(alert.get('risk'))
                    }
                }
        return list(rules.values())

    def _generate_sarif_results(self, alerts: List[Dict]) -> List[Dict]:
        """Generate SARIF results."""
        results = []
        for alert in alerts:
            parsed = urlparse(alert.get('url', ''))
            results.append({
                "ruleId": str(alert.get('pluginId', 'unknown')),
                "level": self._risk_to_sarif_level(alert.get('risk')),
                "message": {
                    "text": f"{alert.get('alert', 'Unknown')}: {alert.get('description', '')[:200]}"
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": parsed.path or "/",
                            "uriBaseId": f"{parsed.scheme}://{parsed.netloc}"
                        }
                    }
                }],
                "fingerprints": {
                    "primary": f"{alert.get('pluginId')}_{hash(alert.get('url', ''))}"
                }
            })
        return results

    @staticmethod
    def _risk_to_sarif_level(risk: str) -> str:
        return {'High': 'error', 'Medium': 'warning', 'Low': 'note'}.get(risk, 'none')

    @staticmethod
    def _risk_to_severity_score(risk: str) -> str:
        return {'High': '8.0', 'Medium': '5.0', 'Low': '2.0'}.get(risk, '0.0')

    def save_html_report(self, zap_client=None, output_file: str = None) -> Optional[str]:
        """Save HTML report (ZAP native or custom)."""
        if not output_file:
            output_file = str(self.output_dir / f"scan_report_{self.timestamp}.html")

        if zap_client:
            try:
                html_report = zap_client.core.htmlreport()
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(html_report)
                logger.info("html_report_saved", path=output_file)
                print(f"[Report] HTML saved: {output_file}")
                return output_file
            except Exception as e:
                logger.error("html_report_error", error=str(e))
                return None
        return None

    def save_critical_findings(self, alerts: List[Dict]) -> Optional[str]:
        """Save critical findings with cURL reproduction commands."""
        critical = [a for a in alerts if a.get('risk') in ['High', 'Medium']]

        if not critical:
            logger.info("no_critical_findings")
            return None

        output_file = self.output_dir / f"critical_findings_{self.timestamp}.txt"

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("CRITICAL SECURITY FINDINGS\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated: {datetime.utcnow().isoformat()}Z\n")
            f.write("=" * 80 + "\n\n")

            for i, alert in enumerate(critical, 1):
                masked = mask_sensitive_data(alert)

                f.write(f"{i}. [{masked.get('risk')}] {masked.get('alert')}\n")
                f.write(f"   URL: {masked.get('url')}\n")
                f.write(f"   CWE: {masked.get('cweid')}\n")
                f.write(f"   WASC: {masked.get('wascid', 'N/A')}\n")
                f.write(f"   Description: {masked.get('description')}\n")
                f.write(f"   Solution: {masked.get('solution', 'N/A')}\n")

                if self.include_curl:
                    curl = self._generate_curl(alert)
                    f.write(f"\n   Reproduce with cURL:\n   {curl}\n")

                f.write("\n" + "-" * 80 + "\n\n")

        logger.info("critical_findings_saved", path=str(output_file), count=len(critical))
        print(f"[Report] Critical findings saved: {output_file}")
        return str(output_file)

    def _generate_curl(self, alert: Dict) -> str:
        """Generate cURL command to reproduce the vulnerability."""
        url = alert.get('url', '')
        method = alert.get('method', 'GET')
        attack = alert.get('attack', '')
        param = alert.get('param', '')
        evidence = alert.get('evidence', '')

        cmd_parts = ['curl']

        # Method
        if method != 'GET':
            cmd_parts.append(f'-X {method}')

        # Headers
        cmd_parts.append("-H 'User-Agent: HAR-ZAP-Reproduction'")

        # Data for POST
        if method in ['POST', 'PUT', 'PATCH']:
            if attack:
                cmd_parts.append(f"-d '{param}={attack}'")
            cmd_parts.append("-H 'Content-Type: application/x-www-form-urlencoded'")

        # URL with attack payload in query if GET
        if method == 'GET' and attack and param:
            if '?' in url:
                url += f'&{param}={attack}'
            else:
                url += f'?{param}={attack}'

        cmd_parts.append(f"'{url}'")

        # Add comment with evidence
        if evidence:
            cmd_parts.append(f"# Evidence: {evidence[:50]}")

        return ' '.join(cmd_parts)

    def generate_executive_summary(self, alerts: List[Dict], scan_duration: Optional[str] = None) -> Dict:
        """Generate executive summary for management."""
        high = [a for a in alerts if a.get('risk') == 'High']
        medium = [a for a in alerts if a.get('risk') == 'Medium']

        owasp_report = self.owasp_mapper.map_alerts(alerts)

        summary = {
            'scan_date': datetime.utcnow().isoformat() + 'Z',
            'duration': scan_duration,
            'risk_level': 'CRITICAL' if high else 'HIGH' if medium else 'LOW',
            'total_findings': len(alerts),
            'critical_findings': len(high),
            'high_findings': len(medium),
            'owasp_score': round(owasp_report.overall_score, 1),
            'owasp_status': 'PASS' if owasp_report.passed else 'FAIL',
            'top_issues': [],
            'immediate_actions': []
        }

        # Top issues
        issue_counts = {}
        for alert in alerts:
            name = alert.get('alert', 'Unknown')
            issue_counts[name] = issue_counts.get(name, 0) + 1

        summary['top_issues'] = sorted(
            [{'name': k, 'count': v} for k, v in issue_counts.items()],
            key=lambda x: x['count'],
            reverse=True
        )[:5]

        # Immediate actions
        if high:
            summary['immediate_actions'].append(
                f"Address {len(high)} high-severity vulnerabilities immediately"
            )
        for cat in owasp_report.failed_categories:
            remediation = self.owasp_mapper.get_remediation(cat)
            summary['immediate_actions'].append(remediation['summary'])

        return summary

    def save_all_reports(
        self,
        alerts: List[Dict],
        har_summary: str = '',
        zap_client=None,
        formats: Optional[List[str]] = None
    ) -> Dict[str, str]:
        """Save all requested report formats."""
        formats = formats or self.config.get('formats', ['json', 'sarif'])
        saved = {}

        if 'json' in formats:
            saved['json'] = self.save_json_report(alerts, har_summary)

        if 'sarif' in formats:
            saved['sarif'] = self.save_sarif_report(alerts)

        if 'html' in formats and zap_client:
            result = self.save_html_report(zap_client)
            if result:
                saved['html'] = result

        if 'critical' in formats or self.config.get('save_critical', True):
            result = self.save_critical_findings(alerts)
            if result:
                saved['critical'] = result

        logger.info("reports_saved", formats=list(saved.keys()))
        return saved
