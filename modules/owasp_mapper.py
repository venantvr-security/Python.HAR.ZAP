"""
OWASP Top 10 Mapper - Map ZAP alerts to OWASP categories with compliance scoring.
"""
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

from .utils import get_logger

logger = get_logger("owasp.mapper")

# OWASP Top 10 2021 with CWE mappings
OWASP_TOP_10_2021 = {
    'A01:2021': {
        'name': 'Broken Access Control',
        'description': 'Access control enforces policy such that users cannot act outside of their intended permissions.',
        'cwes': [22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377,
                 402, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706,
                 862, 863, 913, 922, 1275],
        'zap_alerts': ['10010', '10011', '10020', '10021', '10025', '10032', '10105',
                       '40012', '40016', '90030'],
        'keywords': ['idor', 'access control', 'authorization', 'csrf', 'directory traversal',
                     'path traversal', 'privilege', 'forced browsing'],
    },
    'A02:2021': {
        'name': 'Cryptographic Failures',
        'description': 'Failures related to cryptography which often leads to sensitive data exposure.',
        'cwes': [261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330,
                 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916],
        'zap_alerts': ['10202', '10024', '10035', '10040', '90003', '90033'],
        'keywords': ['ssl', 'tls', 'cipher', 'crypto', 'encryption', 'hash', 'certificate',
                     'cleartext', 'plaintext', 'weak algorithm'],
    },
    'A03:2021': {
        'name': 'Injection',
        'description': 'Injection flaws, such as SQL, NoSQL, OS, and LDAP injection.',
        'cwes': [20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97,
                 98, 99, 100, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917],
        'zap_alerts': ['40018', '40019', '40020', '40021', '40022', '40024', '40025',
                       '40026', '40027', '40012', '40014', '40016', '40017', '90018',
                       '90019', '90020', '90021', '90023', '90024', '90025', '90026'],
        'keywords': ['sql injection', 'xss', 'cross-site scripting', 'command injection',
                     'code injection', 'ldap injection', 'xpath injection', 'nosql',
                     'os command', 'shell injection', 'ssti', 'template injection'],
    },
    'A04:2021': {
        'name': 'Insecure Design',
        'description': 'Missing or ineffective control design.',
        'cwes': [73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316,
                 419, 430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642,
                 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173],
        'zap_alerts': ['10015', '10017', '10019', '10023', '10027'],
        'keywords': ['design', 'business logic', 'rate limit', 'brute force', 'enumeration'],
    },
    'A05:2021': {
        'name': 'Security Misconfiguration',
        'description': 'Insecure default configurations, incomplete or ad hoc configurations.',
        'cwes': [2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756,
                 776, 942, 1004, 1032, 1174],
        'zap_alerts': ['10009', '10010', '10012', '10015', '10017', '10019', '10023',
                       '10024', '10025', '10027', '10028', '10029', '10030', '10031',
                       '10034', '10035', '10036', '10037', '10038', '10039', '10040',
                       '10041', '10042', '10043', '10044', '10045', '10046', '10047',
                       '10048', '10049', '10050', '10051', '10052', '10053', '10054',
                       '10055', '10056', '10057', '10058', '10096', '10098', '10105',
                       '10108', '10109', '90001', '90002', '90003', '90011', '90022',
                       '90028', '90033'],
        'keywords': ['header', 'cors', 'csp', 'x-frame', 'x-content-type', 'hsts',
                     'cookie', 'configuration', 'default', 'debug', 'verbose', 'error message'],
    },
    'A06:2021': {
        'name': 'Vulnerable and Outdated Components',
        'description': 'Using components with known vulnerabilities.',
        'cwes': [1035, 1104],
        'zap_alerts': ['10055', '10096', '10109'],
        'keywords': ['outdated', 'vulnerable component', 'library', 'framework', 'version'],
    },
    'A07:2021': {
        'name': 'Identification and Authentication Failures',
        'description': 'Authentication and session management vulnerabilities.',
        'cwes': [255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346,
                 384, 521, 613, 620, 640, 798, 940, 1216],
        'zap_alerts': ['10011', '10012', '10020', '10054', '10057', '10058', '10105',
                       '40014', '90030'],
        'keywords': ['authentication', 'session', 'password', 'credential', 'login',
                     'logout', 'jwt', 'token', 'cookie', 'fixation', 'brute force'],
    },
    'A08:2021': {
        'name': 'Software and Data Integrity Failures',
        'description': 'Code and infrastructure that does not protect against integrity violations.',
        'cwes': [345, 353, 426, 494, 502, 565, 784, 829, 830, 913],
        'zap_alerts': ['10017', '10019', '90030'],
        'keywords': ['integrity', 'deserialization', 'signature', 'checksum', 'update'],
    },
    'A09:2021': {
        'name': 'Security Logging and Monitoring Failures',
        'description': 'Insufficient logging, detection, monitoring, and active response.',
        'cwes': [117, 223, 532, 778],
        'zap_alerts': [],
        'keywords': ['logging', 'monitoring', 'audit', 'detection'],
    },
    'A10:2021': {
        'name': 'Server-Side Request Forgery (SSRF)',
        'description': 'SSRF flaws occur whenever a web application fetches a remote resource without validating the user-supplied URL.',
        'cwes': [918],
        'zap_alerts': ['40046'],
        'keywords': ['ssrf', 'server-side request', 'url fetch', 'remote resource'],
    },
}

# OWASP API Security Top 10 2023.
# `native_types` are this tool's own finding tags (IDOR / Red Team / passive),
# so native findings map here without depending on ZAP plugin ids.
API_TOP_10_2023 = {
    'API1:2023': {
        'name': 'Broken Object Level Authorization',
        'description': 'APIs expose object identifiers, letting a user access objects belonging to others (BOLA/IDOR).',
        'cwes': [284, 285, 639, 863],
        'zap_alerts': [],
        'keywords': ['idor', 'bola', 'object level', 'access control', 'authorization', 'forced browsing'],
        'native_types': ['idor'],
    },
    'API2:2023': {
        'name': 'Broken Authentication',
        'description': 'Weak or missing authentication lets attackers assume other identities or reach authenticated endpoints.',
        'cwes': [287, 288, 290, 294, 306, 307, 345, 384, 521, 613, 798],
        'zap_alerts': [],
        'keywords': ['authentication', 'unauthenticated', 'jwt', 'token', 'session', 'credential', 'login'],
        'native_types': ['unauth_replay', 'broken_auth', 'weak_token'],
    },
    'API3:2023': {
        'name': 'Broken Object Property Level Authorization',
        'description': 'Mass assignment or excessive data exposure at the property level (merges 2019 A03 + A06).',
        'cwes': [200, 213, 915],
        'zap_alerts': [],
        'keywords': ['mass assignment', 'excessive data', 'data exposure', 'data leakage', 'property'],
        'native_types': ['mass_assignment', 'sensitive_data'],
    },
    'API4:2023': {
        'name': 'Unrestricted Resource Consumption',
        'description': 'Missing rate limiting / quotas allow resource exhaustion and cost/DoS abuse.',
        'cwes': [400, 770, 799],
        'zap_alerts': [],
        'keywords': ['rate limit', 'throttl', 'resource consumption', 'quota', 'flood'],
        'native_types': ['no_rate_limit'],
    },
    'API5:2023': {
        'name': 'Broken Function Level Authorization',
        'description': 'Users reach admin/privileged functions or hidden modes they should not (BFLA).',
        'cwes': [285, 862, 863],
        'zap_alerts': [],
        'keywords': ['function level', 'admin', 'privilege', 'hidden param', 'debug', 'bfla'],
        'native_types': ['hidden_params', 'bfla'],
    },
    'API6:2023': {
        'name': 'Unrestricted Access to Sensitive Business Flows',
        'description': 'Business flows (transfer, coupon, checkout) abusable without limits, incl. race conditions.',
        'cwes': [362, 367, 799, 841],
        'zap_alerts': [],
        'keywords': ['business flow', 'race condition', 'toctou', 'automation abuse'],
        'native_types': ['race_condition'],
    },
    'API7:2023': {
        'name': 'Server-Side Request Forgery',
        'description': 'API fetches a remote resource from a user-supplied URL without validation.',
        'cwes': [918],
        'zap_alerts': ['40046'],
        'keywords': ['ssrf', 'server-side request', 'url fetch', 'remote resource'],
        'native_types': ['ssrf'],
    },
    'API8:2023': {
        'name': 'Security Misconfiguration',
        'description': 'Missing hardening: security headers, CORS, verbose errors, insecure cookies, defaults.',
        'cwes': [16, 209, 611, 614, 776, 942, 1004],
        'zap_alerts': ['10009', '10015', '10017', '10019', '10020', '10021', '10023',
                       '10035', '10036', '10037', '10038', '10098', '90022', '90033'],
        'keywords': ['header', 'cors', 'csp', 'x-frame', 'hsts', 'cookie', 'misconfig',
                     'default', 'debug', 'verbose', 'error message', 'stack trace', 'disclosure'],
        'native_types': ['security_misconfig', 'info_disclosure'],
    },
    'API9:2023': {
        'name': 'Improper Inventory Management',
        'description': 'Undocumented, deprecated or shadow endpoints and unmanaged API versions.',
        'cwes': [1059],
        'zap_alerts': [],
        'keywords': ['inventory', 'deprecated', 'shadow', 'undocumented', 'version', 'debug endpoint'],
        'native_types': ['shadow_endpoint'],
    },
    'API10:2023': {
        'name': 'Unsafe Consumption of APIs',
        'description': 'Blindly trusting data from third-party/upstream APIs without validation.',
        'cwes': [20, 74, 918],
        'zap_alerts': [],
        'keywords': ['third-party', 'upstream', 'unsafe consumption', 'downstream'],
        'native_types': ['unsafe_consumption'],
    },
}

# Selectable catalogs by version string.
CATALOGS = {
    '2021': OWASP_TOP_10_2021,
    'api-2023': API_TOP_10_2023,
}

# Native severity -> normalized risk bucket used by the mapper.
_RISK_FROM_SEVERITY = {
    'CRITICAL': 'High', 'HIGH': 'High', 'MEDIUM': 'Medium',
    'LOW': 'Low', 'INFO': 'Informational', 'INFORMATIONAL': 'Informational',
}


def _risk_from_confidence(confidence: float) -> str:
    if confidence >= 0.8:
        return 'High'
    if confidence >= 0.5:
        return 'Medium'
    return 'Low'


def normalize_findings(idor_results=None, redteam_results=None,
                       passive_issues=None) -> List[Dict]:
    """Adapter: turn native findings into normalized alert dicts the mapper reads.

    Each alert dict carries: alert, risk, cweid, native_type, url, confidence.
    Only vulnerable/positive findings are emitted.
    """
    from .redteam_attacks import AttackType

    redteam_native = {
        AttackType.UNAUTH_REPLAY: 'unauth_replay',
        AttackType.BROKEN_AUTH: 'broken_auth',
        AttackType.MASS_ASSIGNMENT: 'mass_assignment',
        AttackType.HIDDEN_PARAMS: 'hidden_params',
        AttackType.RACE_CONDITION: 'race_condition',
    }
    passive_native = {
        'Missing Security Header': 'security_misconfig',
        'Weak Security Header': 'security_misconfig',
        'Insecure Cookie': 'security_misconfig',
        'Information Disclosure': 'info_disclosure',
        'Data Leakage': 'sensitive_data',
        'Weak Token': 'weak_token',
    }

    alerts: List[Dict] = []

    for r in idor_results or []:
        status = getattr(getattr(r, 'status', None), 'value', getattr(r, 'status', ''))
        if str(status).lower() not in ('vulnerable', 'confirmed'):
            continue
        conf = getattr(r, 'confidence', 1.0) or 1.0
        alerts.append({
            'alert': 'IDOR / Broken Object Level Authorization',
            'risk': _risk_from_confidence(conf),
            'cweid': 639,
            'native_type': 'idor',
            'url': getattr(r, 'url', ''),
            'confidence': conf,
        })

    for r in redteam_results or []:
        if not getattr(r, 'vulnerable', False):
            continue
        conf = getattr(r, 'confidence', 0.5) or 0.5
        alerts.append({
            'alert': getattr(r.attack_type, 'value', str(r.attack_type)),
            'risk': _risk_from_confidence(conf),
            'cweid': 0,
            'native_type': redteam_native.get(r.attack_type, ''),
            'url': getattr(r, 'url', ''),
            'confidence': conf,
        })

    for issue in passive_issues or []:
        category = getattr(issue, 'category', '')
        alerts.append({
            'alert': getattr(issue, 'title', category),
            'risk': _RISK_FROM_SEVERITY.get(str(getattr(issue, 'severity', '')).upper(), 'Low'),
            'cweid': 0,
            'native_type': passive_native.get(category, 'security_misconfig'),
            'url': getattr(issue, 'evidence', {}).get('url', '') if isinstance(getattr(issue, 'evidence', {}), dict) else '',
            'confidence': 1.0,
        })

    return alerts


@dataclass
class OWASPMapping:
    category: str
    category_name: str
    alerts: List[Dict] = field(default_factory=list)
    severity_counts: Dict[str, int] = field(default_factory=dict)
    score: float = 0.0


@dataclass
class ComplianceReport:
    version: str = '2021'
    mappings: Dict[str, OWASPMapping] = field(default_factory=dict)
    unmapped_alerts: List[Dict] = field(default_factory=list)
    overall_score: float = 100.0
    passed: bool = True
    failed_categories: List[str] = field(default_factory=list)


class OWASPMapper:
    """Map ZAP alerts to OWASP Top 10 categories."""

    def __init__(self, config: Optional[Dict] = None, enricher=None):
        self.config = config or {}
        self.version = self.config.get('version', '2021')
        if self.version not in CATALOGS:
            raise ValueError(
                f"Unknown OWASP version '{self.version}'. Choose one of: {', '.join(CATALOGS)}"
            )
        self.catalog = CATALOGS[self.version]
        self.fail_on_categories = self.config.get('fail_on_categories', [])
        # Optional classifier (e.g. OWASPLLMClassifier) for alerts the rules miss.
        self.enricher = enricher

    def map_alerts(self, alerts: List[Dict]) -> ComplianceReport:
        """Map ZAP alerts to OWASP Top 10 categories."""
        logger.info("mapping_alerts", count=len(alerts))

        report = ComplianceReport(version=self.version)

        # Initialize all categories
        for cat_id, cat_info in self.catalog.items():
            report.mappings[cat_id] = OWASPMapping(
                category=cat_id,
                category_name=cat_info['name'],
                severity_counts={'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
            )

        # Map each alert
        for alert in alerts:
            mapped = self._map_single_alert(alert)

            if not mapped and self.enricher is not None and getattr(self.enricher, 'available', False):
                # AI fallback: let the LLM place alerts the rules could not.
                verdict = self.enricher.classify_owasp(
                    alert, {cid: c['name'] for cid, c in self.catalog.items()})
                if verdict:
                    mapped = verdict['category']
                    alert = {**alert, 'owasp_ai_reason': verdict.get('reason', '')}

            if mapped:
                category = mapped
                report.mappings[category].alerts.append(alert)

                severity = alert.get('risk', 'Informational')
                if severity in report.mappings[category].severity_counts:
                    report.mappings[category].severity_counts[severity] += 1
            else:
                report.unmapped_alerts.append(alert)

        # Calculate scores
        self._calculate_scores(report)

        # Check compliance
        self._check_compliance(report)

        logger.info(
            "mapping_complete",
            overall_score=report.overall_score,
            passed=report.passed,
            unmapped=len(report.unmapped_alerts)
        )

        return report

    def _map_single_alert(self, alert: Dict) -> Optional[str]:
        """Map a single alert to an OWASP category."""
        alert_id = str(alert.get('pluginId', ''))
        alert_name = alert.get('alert', '').lower()
        # L'API ZAP renvoie `cweid` en chaîne (ex. '79') ; les listes cibles sont
        # des entiers. Sans conversion, `cweid in cat_info['cwes']` est toujours
        # faux → le mapping par CWE est mort et des alertes tombent en « unmapped ».
        try:
            cweid = int(alert.get('cweid') or 0)
        except (ValueError, TypeError):
            cweid = 0

        # First try: native finding type match
        native_type = alert.get('native_type')
        if native_type:
            for cat_id, cat_info in self.catalog.items():
                if native_type in cat_info.get('native_types', []):
                    return cat_id

        # Second try: direct alert ID match
        for cat_id, cat_info in self.catalog.items():
            if alert_id in cat_info['zap_alerts']:
                return cat_id

        # Third try: CWE match
        if cweid:
            for cat_id, cat_info in self.catalog.items():
                if cweid in cat_info['cwes']:
                    return cat_id

        # Fourth try: keyword match
        for cat_id, cat_info in self.catalog.items():
            for keyword in cat_info['keywords']:
                if keyword in alert_name:
                    return cat_id

        return None

    def _calculate_scores(self, report: ComplianceReport):
        """Calculate compliance scores per category and overall."""
        total_score = 0
        categories_with_issues = 0

        severity_weights = {
            'High': 10,
            'Medium': 5,
            'Low': 2,
            'Informational': 0.5
        }

        for cat_id, mapping in report.mappings.items():
            if not mapping.alerts:
                mapping.score = 100.0
                total_score += 100
            else:
                penalty = 0
                for severity, count in mapping.severity_counts.items():
                    penalty += count * severity_weights.get(severity, 1)

                mapping.score = max(0, 100 - penalty)
                total_score += mapping.score
                categories_with_issues += 1

        report.overall_score = total_score / len(self.catalog)

    def _check_compliance(self, report: ComplianceReport):
        """Check if scan passes compliance requirements."""
        report.passed = True
        report.failed_categories = []

        for cat_id in self.fail_on_categories:
            if cat_id in report.mappings:
                mapping = report.mappings[cat_id]
                if mapping.alerts:
                    report.passed = False
                    report.failed_categories.append(cat_id)

        # Also fail if any High severity
        for cat_id, mapping in report.mappings.items():
            if mapping.severity_counts.get('High', 0) > 0:
                if cat_id not in report.failed_categories:
                    report.failed_categories.append(cat_id)
                report.passed = False

    def generate_report(self, compliance_report: ComplianceReport) -> Dict[str, Any]:
        """Generate a detailed OWASP compliance report."""
        return {
            'owasp_version': compliance_report.version,
            'overall_score': round(compliance_report.overall_score, 2),
            'passed': compliance_report.passed,
            'failed_categories': compliance_report.failed_categories,
            'categories': {
                cat_id: {
                    'name': mapping.category_name,
                    'score': round(mapping.score, 2),
                    'alerts_count': len(mapping.alerts),
                    'severity_breakdown': mapping.severity_counts,
                    'status': 'PASS' if mapping.score >= 80 else 'WARN' if mapping.score >= 50 else 'FAIL'
                }
                for cat_id, mapping in compliance_report.mappings.items()
            },
            'unmapped_alerts_count': len(compliance_report.unmapped_alerts),
            'summary': self._generate_summary(compliance_report)
        }

    def _generate_summary(self, report: ComplianceReport) -> str:
        """Generate executive summary."""
        if report.passed:
            return f"OWASP Top 10 {report.version} compliance: PASSED with score {report.overall_score:.1f}/100"

        failed_names = [
            self.catalog[cat]['name']
            for cat in report.failed_categories
            if cat in self.catalog
        ]

        return (
            f"OWASP Top 10 {report.version} compliance: FAILED with score {report.overall_score:.1f}/100. "
            f"Issues in: {', '.join(failed_names)}"
        )

    def get_remediation(self, category: str) -> Dict[str, str]:
        """Get remediation guidance for a category."""
        remediations = {
            'A01:2021': {
                'summary': 'Implement proper access controls',
                'steps': [
                    'Deny by default except for public resources',
                    'Implement access control mechanisms once and reuse',
                    'Enforce record ownership',
                    'Disable web server directory listing',
                    'Log access control failures and alert on repeated failures'
                ]
            },
            'A02:2021': {
                'summary': 'Protect data in transit and at rest',
                'steps': [
                    'Classify sensitive data',
                    'Encrypt all sensitive data at rest',
                    'Use strong encryption algorithms (AES-256, RSA-2048+)',
                    'Enforce HTTPS with HSTS',
                    'Disable caching for sensitive data'
                ]
            },
            'A03:2021': {
                'summary': 'Prevent injection attacks',
                'steps': [
                    'Use parameterized queries/prepared statements',
                    'Use positive input validation',
                    'Escape special characters for the interpreter',
                    'Use LIMIT and other SQL controls',
                    'Implement Content Security Policy'
                ]
            },
            'A05:2021': {
                'summary': 'Secure configurations',
                'steps': [
                    'Remove unused features and frameworks',
                    'Review and harden default configurations',
                    'Implement security headers',
                    'Automate configuration verification',
                    'Use segmented architecture'
                ]
            },
            'A07:2021': {
                'summary': 'Implement strong authentication',
                'steps': [
                    'Implement multi-factor authentication',
                    'Use secure session management',
                    'Implement account lockout policies',
                    'Use secure password storage (bcrypt, Argon2)',
                    'Invalidate sessions on logout'
                ]
            },
            'A10:2021': {
                'summary': 'Prevent SSRF',
                'steps': [
                    'Sanitize and validate all client-supplied input',
                    'Use allowlists for URL schemas and destinations',
                    'Disable HTTP redirections',
                    'Use network segmentation',
                    'Do not send raw responses to clients'
                ]
            },
            'API1:2023': {
                'summary': 'Enforce object-level authorization (BOLA)',
                'steps': [
                    'Check the caller owns/has rights to every object id on every request',
                    'Use random/unpredictable ids (UUID) instead of sequential ones',
                    'Centralize authorization checks; never trust client-supplied ids',
                ]
            },
            'API2:2023': {
                'summary': 'Harden authentication',
                'steps': [
                    'Require auth on every non-public endpoint',
                    'Validate JWT signature/alg/exp; reject alg=none',
                    'Rate-limit and lock out credential-stuffing/brute-force',
                ]
            },
            'API3:2023': {
                'summary': 'Authorize object properties (BOPLA)',
                'steps': [
                    'Allowlist writable fields; reject unexpected properties (no blind bind)',
                    'Return only the fields the caller is entitled to (no over-exposure)',
                    'Validate request/response schemas',
                ]
            },
            'API4:2023': {
                'summary': 'Limit resource consumption',
                'steps': [
                    'Enforce rate limits, quotas and payload/size caps',
                    'Set timeouts and pagination limits',
                    'Alert on abnormal consumption',
                ]
            },
            'API5:2023': {
                'summary': 'Enforce function-level authorization (BFLA)',
                'steps': [
                    'Deny by default; grant admin/privileged functions explicitly by role',
                    'Do not rely on hidden/undocumented endpoints for protection',
                    'Test each function with a low-privileged and anonymous caller',
                ]
            },
            'API6:2023': {
                'summary': 'Protect sensitive business flows',
                'steps': [
                    'Add anti-automation on sensitive flows (transfer, checkout, coupon)',
                    'Use idempotency keys / locks to prevent race conditions (TOCTOU)',
                    'Detect and throttle scripted/abusive usage',
                ]
            },
            'API7:2023': {
                'summary': 'Prevent SSRF',
                'steps': [
                    'Validate and allowlist user-supplied URLs (scheme, host, port)',
                    'Disable redirects; block internal/link-local ranges',
                    'Never return raw upstream responses to the client',
                ]
            },
            'API8:2023': {
                'summary': 'Fix security misconfiguration',
                'steps': [
                    'Set security headers (HSTS, CSP, X-Content-Type-Options)',
                    'Lock down CORS; secure cookies (Secure, HttpOnly, SameSite)',
                    'Disable verbose errors/stack traces in production',
                ]
            },
            'API9:2023': {
                'summary': 'Manage API inventory',
                'steps': [
                    'Maintain an up-to-date inventory of hosts, endpoints and versions',
                    'Retire deprecated/shadow endpoints; block debug/staging in prod',
                    'Document every exposed API and its data classification',
                ]
            },
            'API10:2023': {
                'summary': 'Consume third-party APIs safely',
                'steps': [
                    'Validate and sanitize data received from upstream/third-party APIs',
                    'Use TLS and allowlists for outbound API calls; disable blind redirects',
                    'Do not blindly forward third-party responses to your clients',
                ]
            },
        }

        return remediations.get(category, {
            'summary': 'Review OWASP guidance for this category',
            'steps': ['Consult OWASP Top 10 documentation']
        })


def _extract_json(raw):
    """Best-effort JSON extraction from an LLM response (may wrap in ```json)."""
    if not raw:
        return None
    raw = raw.strip()
    if raw.startswith('```'):
        raw = raw.split('```', 2)[1]
        if raw.startswith('json'):
            raw = raw[4:]
        raw = raw.strip('`').strip()
    import json as _json
    try:
        return _json.loads(raw)
    except ValueError:
        for opener, closer in (('{', '}'), ('[', ']')):
            start, end = raw.find(opener), raw.rfind(closer)
            if start != -1 and end > start:
                try:
                    return _json.loads(raw[start:end + 1])
                except ValueError:
                    continue
    return None


class OWASPLLMClassifier:
    """Classify OWASP-unmapped alerts with the shared modules.llm client.

    A no-op when no API key/provider is configured, so scans stay green without
    an LLM. Reuses the project's existing LLMClient rather than a parallel one.
    """

    def __init__(self, config: Optional[Dict] = None):
        self._client = None
        try:
            # Passe par le factory partagé pour bénéficier du record/replay LLM.
            from .llm.adaptive_idor import client_from_config
            self._client = client_from_config(config or {})
        except Exception as e:  # missing key, missing subsystem, bad config
            logger.info("owasp_llm_classifier_unavailable", reason=str(e))
            self._client = None

    @property
    def available(self) -> bool:
        return self._client is not None

    def classify_owasp(self, alert: Dict, categories: Dict[str, str]) -> Optional[Dict]:
        """Return {'category': id, 'reason': str} or None."""
        if not self._client:
            return None
        import json as _json
        keep = ('alert', 'name', 'risk', 'severity', 'native_type', 'url', 'cweid')
        slim = {k: alert[k] for k in keep if k in alert}
        from .llm.prompts import get_prompt
        system, user = get_prompt('owasp_classify').render(
            categories=_json.dumps(categories), finding=_json.dumps(slim))
        try:
            resp = self._client.complete(user, system=system)
            data = _extract_json(getattr(resp, 'content', None))
        except Exception as e:
            logger.warning("owasp_llm_classify_failed", error=str(e))
            return None
        if isinstance(data, dict) and data.get('category') in categories:
            return {'category': data['category'], 'reason': data.get('reason', '')}
        return None
