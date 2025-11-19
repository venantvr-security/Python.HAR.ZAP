from typing import List, Dict, Any
from modules.idor_detector import IDORStatus


class AcceptanceEngine:
    """Engine for evaluating security acceptance criteria"""

    def __init__(self, criteria: List[Dict]):
        self.criteria = criteria

    def evaluate(self, scan_results: Dict[str, Any]) -> Dict:
        """Evaluate all criteria against scan results"""
        results = []
        all_passed = True

        for criterion in self.criteria:
            result = self._evaluate_criterion(criterion, scan_results)
            results.append(result)
            if not result['passed']:
                all_passed = False

        return {
            'passed': all_passed,
            'results': results,
            'summary': self._generate_summary(results)
        }

    def _evaluate_criterion(self, criterion: Dict, scan_results: Dict) -> Dict:
        """Evaluate a single criterion"""
        ctype = criterion.get('type')

        if ctype == 'max_high':
            return self._check_max_high(criterion, scan_results)
        elif ctype == 'max_medium':
            return self._check_max_medium(criterion, scan_results)
        elif ctype == 'no_idor':
            return self._check_no_idor(criterion, scan_results)
        elif ctype == 'clean_url':
            return self._check_clean_url(criterion, scan_results)
        elif ctype == 'max_total_alerts':
            return self._check_max_total(criterion, scan_results)
        elif ctype == 'no_sql_injection':
            return self._check_no_sql_injection(criterion, scan_results)
        elif ctype == 'no_xss':
            return self._check_no_xss(criterion, scan_results)
        else:
            return {
                'criterion': str(criterion),
                'passed': False,
                'message': f'Unknown criterion type: {ctype}'
            }

    def _check_max_high(self, criterion: Dict, results: Dict) -> Dict:
        """Check maximum high severity alerts"""
        threshold = criterion.get('threshold', 0)
        alerts = results.get('zap_alerts', [])
        high_alerts = [a for a in alerts if a.get('risk') == 'High']
        count = len(high_alerts)

        passed = count <= threshold

        return {
            'criterion': f'Max High Alerts ≤ {threshold}',
            'passed': passed,
            'message': f'Found {count} high alerts (threshold: {threshold})',
            'details': {
                'count': count,
                'threshold': threshold,
                'alerts': [a.get('alert') for a in high_alerts]
            }
        }

    def _check_max_medium(self, criterion: Dict, results: Dict) -> Dict:
        """Check maximum medium severity alerts"""
        threshold = criterion.get('threshold', 0)
        alerts = results.get('zap_alerts', [])
        medium_alerts = [a for a in alerts if a.get('risk') == 'Medium']
        count = len(medium_alerts)

        passed = count <= threshold

        return {
            'criterion': f'Max Medium Alerts ≤ {threshold}',
            'passed': passed,
            'message': f'Found {count} medium alerts (threshold: {threshold})',
            'details': {
                'count': count,
                'threshold': threshold
            }
        }

    def _check_no_idor(self, criterion: Dict, results: Dict) -> Dict:
        """Check for IDOR vulnerabilities"""
        idor_results = results.get('idor_results', [])
        vulnerable = [r for r in idor_results if r.status == IDORStatus.VULNERABLE]
        count = len(vulnerable)

        passed = count == 0

        return {
            'criterion': 'No IDOR Vulnerabilities',
            'passed': passed,
            'message': f'Found {count} IDOR vulnerabilities',
            'details': {
                'count': count,
                'vulnerable_urls': [r.url for r in vulnerable]
            }
        }

    def _check_clean_url(self, criterion: Dict, results: Dict) -> Dict:
        """Check if specific URL pattern has no alerts"""
        pattern = criterion.get('pattern', '')
        alerts = results.get('zap_alerts', [])

        matching_alerts = [
            a for a in alerts
            if pattern in a.get('url', '')
            and a.get('risk') in ['High', 'Medium']
        ]

        count = len(matching_alerts)
        passed = count == 0

        return {
            'criterion': f'URL Pattern Clean: {pattern}',
            'passed': passed,
            'message': f'Found {count} alerts matching pattern',
            'details': {
                'pattern': pattern,
                'count': count,
                'alerts': [a.get('alert') for a in matching_alerts]
            }
        }

    def _check_max_total(self, criterion: Dict, results: Dict) -> Dict:
        """Check maximum total alerts"""
        threshold = criterion.get('threshold', 0)
        alerts = results.get('zap_alerts', [])
        count = len([a for a in alerts if a.get('risk') in ['High', 'Medium']])

        passed = count <= threshold

        return {
            'criterion': f'Max Total Critical Alerts ≤ {threshold}',
            'passed': passed,
            'message': f'Found {count} critical alerts (threshold: {threshold})',
            'details': {
                'count': count,
                'threshold': threshold
            }
        }

    def _check_no_sql_injection(self, criterion: Dict, results: Dict) -> Dict:
        """Check for SQL injection vulnerabilities"""
        alerts = results.get('zap_alerts', [])
        sql_alerts = [
            a for a in alerts
            if 'sql' in a.get('alert', '').lower()
            and a.get('risk') in ['High', 'Medium']
        ]
        count = len(sql_alerts)

        passed = count == 0

        return {
            'criterion': 'No SQL Injection',
            'passed': passed,
            'message': f'Found {count} SQL injection alerts',
            'details': {
                'count': count,
                'alerts': [a.get('alert') for a in sql_alerts]
            }
        }

    def _check_no_xss(self, criterion: Dict, results: Dict) -> Dict:
        """Check for XSS vulnerabilities"""
        alerts = results.get('zap_alerts', [])
        xss_alerts = [
            a for a in alerts
            if 'xss' in a.get('alert', '').lower() or 'cross site scripting' in a.get('alert', '').lower()
            and a.get('risk') in ['High', 'Medium']
        ]
        count = len(xss_alerts)

        passed = count == 0

        return {
            'criterion': 'No XSS',
            'passed': passed,
            'message': f'Found {count} XSS alerts',
            'details': {
                'count': count,
                'alerts': [a.get('alert') for a in xss_alerts]
            }
        }

    def _generate_summary(self, results: List[Dict]) -> str:
        """Generate human-readable summary"""
        total = len(results)
        passed = len([r for r in results if r['passed']])
        failed = total - passed

        summary = f"Acceptance Criteria: {passed}/{total} passed"

        if failed > 0:
            summary += f" ({failed} failed)"

        return summary

    def export_junit_xml(self, evaluation: Dict, output_path: str):
        """Export results as JUnit XML for CI/CD integration"""
        import xml.etree.ElementTree as ET

        testsuite = ET.Element('testsuite', {
            'name': 'Security Acceptance Tests',
            'tests': str(len(evaluation['results'])),
            'failures': str(len([r for r in evaluation['results'] if not r['passed']])),
        })

        for result in evaluation['results']:
            testcase = ET.SubElement(testsuite, 'testcase', {
                'name': result['criterion'],
                'classname': 'SecurityTests'
            })

            if not result['passed']:
                failure = ET.SubElement(testcase, 'failure', {
                    'message': result['message']
                })
                failure.text = str(result.get('details', {}))

        tree = ET.ElementTree(testsuite)
        tree.write(output_path, encoding='utf-8', xml_declaration=True)

    def export_sarif(self, scan_results: Dict, output_path: str):
        """Export results as SARIF format for GitHub Security"""
        import json

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "DAST Security Platform",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/yourusername/dast-platform"
                        }
                    },
                    "results": []
                }
            ]
        }

        alerts = scan_results.get('zap_alerts', [])
        for alert in alerts:
            sarif_result = {
                "ruleId": alert.get('pluginId', 'unknown'),
                "level": self._map_risk_to_sarif_level(alert.get('risk', 'Low')),
                "message": {
                    "text": alert.get('alert', 'Security vulnerability detected')
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": alert.get('url', '')
                            }
                        }
                    }
                ],
                "properties": {
                    "cweid": alert.get('cweid', ''),
                    "description": alert.get('description', ''),
                    "solution": alert.get('solution', '')
                }
            }
            sarif['runs'][0]['results'].append(sarif_result)

        with open(output_path, 'w') as f:
            json.dump(sarif, f, indent=2)

    def _map_risk_to_sarif_level(self, risk: str) -> str:
        """Map ZAP risk levels to SARIF severity levels"""
        mapping = {
            'High': 'error',
            'Medium': 'warning',
            'Low': 'note',
            'Informational': 'none'
        }
        return mapping.get(risk, 'warning')
