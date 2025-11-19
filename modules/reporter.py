import json
from datetime import datetime
from typing import List, Dict


class Reporter:

    def __init__(self, output_dir: str = './output'):
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    def generate_console_report(self, alerts: List[Dict]):
        high_alerts = [a for a in alerts if a.get('risk') == 'High']
        medium_alerts = [a for a in alerts if a.get('risk') == 'Medium']
        low_alerts = [a for a in alerts if a.get('risk') == 'Low']
        info_alerts = [a for a in alerts if a.get('risk') == 'Informational']

        print("\n" + "=" * 80)
        print("SECURITY SCAN RESULTS")
        print("=" * 80)
        print(f"Total Alerts: {len(alerts)}")
        print(f"  High:   {len(high_alerts)}")
        print(f"  Medium: {len(medium_alerts)}")
        print(f"  Low:    {len(low_alerts)}")
        print(f"  Info:   {len(info_alerts)}")
        print("=" * 80)

        if high_alerts:
            print("\n[!] HIGH RISK ALERTS:")
            for alert in high_alerts:
                self._print_alert(alert)

        if medium_alerts:
            print("\n[!] MEDIUM RISK ALERTS:")
            for alert in medium_alerts[:10]:
                self._print_alert(alert)

            if len(medium_alerts) > 10:
                print(f"... and {len(medium_alerts) - 10} more medium alerts")

    def _print_alert(self, alert: Dict):
        print(f"\n  [{alert.get('risk', 'Unknown')}] {alert.get('alert', 'No name')}")
        print(f"  URL: {alert.get('url', 'N/A')}")
        print(f"  CWE: {alert.get('cweid', 'N/A')}")
        print(f"  Description: {alert.get('description', 'N/A')[:200]}...")

    def save_json_report(self, alerts: List[Dict], har_summary: str):
        report_data = {
            'timestamp': self.timestamp,
            'har_analysis': har_summary,
            'total_alerts': len(alerts),
            'alerts_by_risk': {
                'high': len([a for a in alerts if a.get('risk') == 'High']),
                'medium': len([a for a in alerts if a.get('risk') == 'Medium']),
                'low': len([a for a in alerts if a.get('risk') == 'Low']),
                'informational': len([a for a in alerts if a.get('risk') == 'Informational'])
            },
            'alerts': alerts
        }

        output_file = f"{self.output_dir}/scan_report_{self.timestamp}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)

        print(f"\n[Report] JSON saved: {output_file}")
        return output_file

    def save_html_report(self, zap_client, output_file: str = None):
        if not output_file:
            output_file = f"{self.output_dir}/scan_report_{self.timestamp}.html"

        try:
            html_report = zap_client.core.htmlreport()

            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_report)

            print(f"[Report] HTML saved: {output_file}")
            return output_file

        except Exception as e:
            print(f"[Report] Error generating HTML: {e}")
            return None

    def save_critical_findings(self, alerts: List[Dict]):
        critical = [a for a in alerts if a.get('risk') in ['High', 'Medium']]

        if not critical:
            print("[Report] No critical findings to save")
            return

        output_file = f"{self.output_dir}/critical_findings_{self.timestamp}.txt"

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("CRITICAL SECURITY FINDINGS\n")
            f.write("=" * 80 + "\n\n")

            for i, alert in enumerate(critical, 1):
                f.write(f"{i}. [{alert.get('risk')}] {alert.get('alert')}\n")
                f.write(f"   URL: {alert.get('url')}\n")
                f.write(f"   CWE: {alert.get('cweid')}\n")
                f.write(f"   Description: {alert.get('description')}\n")
                f.write(f"   Solution: {alert.get('solution', 'N/A')}\n")
                f.write("\n" + "-" * 80 + "\n\n")

        print(f"[Report] Critical findings saved: {output_file}")
        return output_file
