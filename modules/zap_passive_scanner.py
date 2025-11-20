"""
ZAP Native Passive Scanner - Replaces custom regex-based analysis

Leverages ZAP's 50+ built-in passive scanners while keeping custom token entropy analysis.
"""
import math
import re
import time
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Optional

from zapv2 import ZAPv2


@dataclass
class SecurityIssue:
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    title: str
    description: str
    evidence: Dict
    remediation: str
    zap_plugin_id: Optional[str] = None


class ZAPPassiveScanner:
    """
    Orchestrates ZAP native passive scanning with custom token entropy analysis.

    Uses ZAP for:
    - Security headers (CSP, HSTS, X-Frame-Options, etc.)
    - Cookie security (Secure, HttpOnly, SameSite)
    - PII detection (emails, SSN, credit cards)
    - Information disclosure (comments, stack traces)
    - Technology detection (Wappalyzer)

    Keeps custom:
    - Token entropy analysis (no ZAP equivalent)
    """

    # Key passive scanners to enable
    SCANNER_IDS = {
        '10010': 'Cookie No HttpOnly Flag',
        '10011': 'Cookie Without Secure Flag',
        '10015': 'Incomplete or No Cache-control',
        '10017': 'Cross-Domain JavaScript Source',
        '10020': 'X-Frame-Options Header',
        '10021': 'X-Content-Type-Options Header',
        '10023': 'Information Disclosure - Debug Errors',
        '10027': 'Information Disclosure - Suspicious Comments',
        '10035': 'Strict-Transport-Security Header',
        '10038': 'Content Security Policy (CSP) Header Not Set',
        '10055': 'CSP Header Not Set',
        '10096': 'Timestamp Disclosure',
        '10109': 'Modern Web Application',  # Wappalyzer
        '10202': 'Absence of Anti-CSRF Tokens',
        '90033': 'Loosely Scoped Cookie',
    }

    def __init__(self, zap_client: ZAPv2, har_data: Optional[Dict] = None):
        self.zap = zap_client
        self.har_data = har_data
        self.issues = []

    def configure(self):
        """Configure ZAP passive scanners"""
        # Enable all passive scanners
        self.zap.pscan.enable_all_scanners()

        # Set thresholds for key scanners
        for scanner_id in self.SCANNER_IDS.keys():
            try:
                # MEDIUM threshold = reduce false positives
                self.zap.pscan.set_scanner_alert_threshold(scanner_id, 'MEDIUM')
            except Exception as e:
                print(f"[ZAP Passive] Warning: Could not configure scanner {scanner_id}: {e}")

        # Disable noisy scanners if needed
        # self.zap.pscan.disable_scanners('10027')  # Suspicious comments

        print(f"[ZAP Passive] Configured {len(self.SCANNER_IDS)} passive scanners")

    def wait_for_completion(self, max_wait: int = 300):
        """Wait for passive scan queue to drain"""
        print("[ZAP Passive] Waiting for passive scan completion...")
        start_time = time.time()

        while time.time() - start_time < max_wait:
            records_to_scan = int(self.zap.pscan.records_to_scan)

            if records_to_scan == 0:
                print("[ZAP Passive] Passive scan completed")
                return True

            print(f"[ZAP Passive] Remaining records: {records_to_scan}")
            time.sleep(2)

        print(f"[ZAP Passive] Warning: Timeout after {max_wait}s")
        return False

    def get_alerts(self, baseurl: Optional[str] = None) -> List[SecurityIssue]:
        """Retrieve ZAP passive scan alerts"""
        raw_alerts = self.zap.core.alerts(baseurl=baseurl) if baseurl else self.zap.core.alerts()

        issues = []
        for alert in raw_alerts:
            # Map ZAP severity to our format
            severity_map = {
                'Informational': 'INFO',
                'Low': 'LOW',
                'Medium': 'MEDIUM',
                'High': 'HIGH'
            }

            issues.append(SecurityIssue(
                severity=severity_map.get(alert.get('risk', 'Low'), 'LOW'),
                category='ZAP Passive Scan',
                title=alert.get('alert', 'Unknown'),
                description=alert.get('description', ''),
                evidence={
                    'url': alert.get('url', ''),
                    'param': alert.get('param', ''),
                    'attack': alert.get('attack', ''),
                    'evidence': alert.get('evidence', ''),
                    'confidence': alert.get('confidence', ''),
                    'cweid': alert.get('cweid', ''),
                    'wascid': alert.get('wascid', ''),
                },
                remediation=alert.get('solution', ''),
                zap_plugin_id=alert.get('pluginId', '')
            ))

        print(f"[ZAP Passive] Found {len(issues)} alerts")
        return issues

    def analyze_token_entropy(self) -> List[SecurityIssue]:
        """
        Custom token entropy analysis (no ZAP equivalent).
        Checks JWT tokens, session IDs, API keys for predictability.
        """
        if not self.har_data:
            return []

        analyzer = TokenEntropyAnalyzer(self.har_data)
        return analyzer.analyze()

    def scan_full(self, baseurl: Optional[str] = None) -> List[SecurityIssue]:
        """
        Complete passive scan workflow:
        1. Configure ZAP passive scanners
        2. Wait for completion
        3. Get ZAP alerts
        4. Run custom token entropy analysis
        """
        self.configure()
        self.wait_for_completion()

        # ZAP native alerts
        zap_issues = self.get_alerts(baseurl)

        # Custom token entropy
        entropy_issues = self.analyze_token_entropy()

        all_issues = zap_issues + entropy_issues
        print(f"[ZAP Passive] Total issues: {len(all_issues)} ({len(zap_issues)} ZAP + {len(entropy_issues)} custom)")

        return all_issues


class TokenEntropyAnalyzer:
    """
    Custom token entropy analysis (kept from original passive_analysis.py).

    ZAP has no equivalent for statistical analysis of token predictability.
    """

    TOKEN_PATTERNS = {
        'jwt': re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
        'session_id': re.compile(r'(?i)(sessionid|session[_-]?token|sid)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})'),
        'api_key': re.compile(r'(?i)(api[_-]?key|apikey|bearer)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})'),
        'csrf_token': re.compile(r'(?i)(csrf[_-]?token|xsrf[_-]?token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})'),
    }

    ENTROPY_THRESHOLDS = {
        'jwt': 4.0,  # JWTs should have high entropy
        'session_id': 4.5,  # Session IDs must be unpredictable
        'api_key': 4.0,  # API keys should be random
        'csrf_token': 4.0,  # CSRF tokens must be random
    }

    def __init__(self, har_data: Dict):
        self.har_data = har_data

    # noinspection PyMethodMayBeStatic
    def calculate_entropy(self, token: str) -> float:
        """Calculate Shannon entropy of token"""
        if not token:
            return 0.0

        counter = Counter(token)
        length = len(token)
        entropy = -sum((count / length) * math.log2(count / length) for count in counter.values())

        return entropy

    def analyze(self) -> List[SecurityIssue]:
        """Analyze tokens in HAR for low entropy"""
        issues = []
        entries = self.har_data.get('log', {}).get('entries', [])

        checked_tokens = set()

        for entry in entries:
            # Check request headers
            request = entry.get('request', {})
            for header in request.get('headers', []):
                if header['name'].lower() in ['authorization', 'x-api-key', 'x-csrf-token']:
                    token = header['value']
                    if token and token not in checked_tokens:
                        checked_tokens.add(token)
                        issue = self._check_token(token, 'header', request.get('url', ''))
                        if issue:
                            issues.append(issue)

            # Check response cookies
            response = entry.get('response', {})
            for header in response.get('headers', []):
                if header['name'].lower() == 'set-cookie':
                    cookie_value = header['value']
                    token = cookie_value.split(';')[0].split('=')[-1]
                    if token and token not in checked_tokens:
                        checked_tokens.add(token)
                        issue = self._check_token(token, 'cookie', request.get('url', ''))
                        if issue:
                            issues.append(issue)

            # Check response body tokens
            content = response.get('content', {}).get('text', '')
            for token_type, pattern in self.TOKEN_PATTERNS.items():
                matches = pattern.findall(content)
                for match in matches:
                    token = match if isinstance(match, str) else match[-1]
                    if token and token not in checked_tokens:
                        checked_tokens.add(token)
                        issue = self._check_token(token, token_type, request.get('url', ''))
                        if issue:
                            issues.append(issue)

        return issues

    def _check_token(self, token: str, token_type: str, url: str) -> Optional[SecurityIssue]:
        """Check if token has sufficient entropy"""
        # Skip very short tokens (likely not actual tokens)
        if len(token) < 8:
            return None

        # Skip tokens with obvious structure (timestamps, UUIDs)
        if re.match(r'^\d+$', token):  # Pure numeric
            return None
        if re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', token.lower()):  # UUID
            return None

        entropy = self.calculate_entropy(token)
        threshold = self.ENTROPY_THRESHOLDS.get(token_type, 4.0)

        if entropy < threshold:
            severity = 'HIGH' if entropy < 3.0 else 'MEDIUM'

            return SecurityIssue(
                severity=severity,
                category='Low Token Entropy',
                title=f'Predictable {token_type.replace("_", " ").title()}',
                description=f'Token has entropy {entropy:.2f} (threshold: {threshold}), may be predictable',
                evidence={
                    'url': url,
                    'token_type': token_type,
                    'token_preview': token[:10] + '...' if len(token) > 10 else token,
                    'entropy': f'{entropy:.2f}',
                    'threshold': str(threshold),
                    'length': len(token)
                },
                remediation='Use cryptographically secure random number generators (CSPRNG) for token generation'
            )

        return None


class PassiveAnalysisOrchestrator:
    """
    Orchestrates both ZAP passive scanning and custom analysis.

    Provides backward-compatible interface with original passive_analysis.py.
    """

    def __init__(self, zap_client: ZAPv2, har_data: Dict):
        self.zap_scanner = ZAPPassiveScanner(zap_client, har_data)

    def run_all(self, baseurl: Optional[str] = None) -> Dict[str, List[SecurityIssue]]:
        """
        Run all passive analysis and return categorized results.

        Returns:
            {
                'headers': [issues],
                'cookies': [issues],
                'sensitive_data': [issues],
                'token_entropy': [issues],
                'information_disclosure': [issues],
                'technology': [issues]
            }
        """
        all_issues = self.zap_scanner.scan_full(baseurl)

        # Categorize issues
        categorized = {
            'headers': [],
            'cookies': [],
            'sensitive_data': [],
            'token_entropy': [],
            'information_disclosure': [],
            'technology': []
        }

        for issue in all_issues:
            if 'entropy' in issue.category.lower():
                categorized['token_entropy'].append(issue)
            elif 'cookie' in issue.title.lower():
                categorized['cookies'].append(issue)
            elif 'header' in issue.title.lower():
                categorized['headers'].append(issue)
            elif 'disclosure' in issue.title.lower():
                categorized['information_disclosure'].append(issue)
            elif 'technology' in issue.title.lower() or 'web application' in issue.title.lower():
                categorized['technology'].append(issue)
            else:
                categorized['sensitive_data'].append(issue)

        return categorized

    # noinspection PyMethodMayBeStatic
    def get_summary(self, results: Dict[str, List[SecurityIssue]]) -> Dict:
        """Generate summary statistics"""
        total = sum(len(issues) for issues in results.values())

        severity_counts = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }

        for issues in results.values():
            for issue in issues:
                severity_counts[issue.severity] += 1

        return {
            'total_issues': total,
            'by_severity': severity_counts,
            'by_category': {cat: len(issues) for cat, issues in results.items()}
        }
