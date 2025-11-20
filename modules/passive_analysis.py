"""
Passive Security Analysis - Headers, Leaks, Token Entropy
"""
import math
import re
from dataclasses import dataclass
from typing import Dict, List


@dataclass
class SecurityIssue:
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    title: str
    description: str
    evidence: Dict
    remediation: str


class SecurityHeadersAnalyzer:
    """Analyze security headers presence and configuration"""

    REQUIRED_HEADERS = {
        'Strict-Transport-Security': {
            'severity': 'HIGH',
            'description': 'HSTS header missing - allows protocol downgrade attacks',
            'remediation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'
        },
        'Content-Security-Policy': {
            'severity': 'HIGH',
            'description': 'CSP header missing - vulnerable to XSS attacks',
            'remediation': "Add: Content-Security-Policy: default-src 'self'"
        },
        'X-Frame-Options': {
            'severity': 'MEDIUM',
            'description': 'X-Frame-Options missing - vulnerable to clickjacking',
            'remediation': 'Add: X-Frame-Options: DENY'
        },
        'X-Content-Type-Options': {
            'severity': 'MEDIUM',
            'description': 'X-Content-Type-Options missing - vulnerable to MIME sniffing',
            'remediation': 'Add: X-Content-Type-Options: nosniff'
        },
        'Referrer-Policy': {
            'severity': 'LOW',
            'description': 'Referrer-Policy missing - may leak sensitive URLs',
            'remediation': 'Add: Referrer-Policy: no-referrer'
        },
        'Permissions-Policy': {
            'severity': 'LOW',
            'description': 'Permissions-Policy missing - browser features not restricted',
            'remediation': 'Add: Permissions-Policy: geolocation=(), microphone=(), camera=()'
        }
    }

    def __init__(self, har_data: Dict):
        self.har_data = har_data
        self.issues = []

    def analyze(self) -> List[SecurityIssue]:
        """Analyze all responses for security headers"""
        entries = self.har_data.get('log', {}).get('entries', [])

        checked_domains = set()

        for entry in entries:
            response = entry.get('response', {})
            url = entry.get('request', {}).get('url', '')

            from urllib.parse import urlparse

            domain = urlparse(url).netloc

            if domain in checked_domains:
                continue

            checked_domains.add(domain)

            headers = {
                h['name'].lower(): h['value']
                for h in response.get('headers', [])
            }

            for required_header, config in self.REQUIRED_HEADERS.items():
                if required_header.lower() not in headers:
                    self.issues.append(SecurityIssue(
                        severity=config['severity'],
                        category='Missing Security Header',
                        title=f"Missing {required_header}",
                        description=config['description'],
                        evidence={
                            'domain': domain,
                            'url': url,
                            'header': required_header
                        },
                        remediation=config['remediation']
                    ))

            self._check_weak_csp(headers, url)
            self._check_insecure_cookies(entry, url)

        return self.issues

    def _check_weak_csp(self, headers: Dict, url: str):
        """Check for weak CSP configurations"""
        csp = headers.get('content-security-policy', '')

        if csp:
            weak_patterns = [
                ("'unsafe-inline'", "CSP allows unsafe-inline scripts"),
                ("'unsafe-eval'", "CSP allows unsafe-eval"),
                ("*", "CSP uses wildcard source")
            ]

            for pattern, description in weak_patterns:
                if pattern in csp:
                    self.issues.append(SecurityIssue(
                        severity='MEDIUM',
                        category='Weak Security Header',
                        title='Weak Content-Security-Policy',
                        description=description,
                        evidence={
                            'url': url,
                            'csp': csp,
                            'weakness': pattern
                        },
                        remediation=f"Remove {pattern} from CSP directive"
                    ))

    def _check_insecure_cookies(self, entry: Dict, url: str):
        """Check for cookies without Secure or HttpOnly flags"""
        response = entry.get('response', {})

        for header in response.get('headers', []):
            if header['name'].lower() == 'set-cookie':
                cookie = header['value']

                if 'secure' not in cookie.lower():
                    self.issues.append(SecurityIssue(
                        severity='HIGH',
                        category='Insecure Cookie',
                        title='Cookie missing Secure flag',
                        description='Cookie can be transmitted over unencrypted connections',
                        evidence={
                            'url': url,
                            'cookie': cookie[:100]
                        },
                        remediation='Add Secure flag to all cookies'
                    ))

                if 'httponly' not in cookie.lower():
                    self.issues.append(SecurityIssue(
                        severity='MEDIUM',
                        category='Insecure Cookie',
                        title='Cookie missing HttpOnly flag',
                        description='Cookie accessible via JavaScript (XSS risk)',
                        evidence={
                            'url': url,
                            'cookie': cookie[:100]
                        },
                        remediation='Add HttpOnly flag to session cookies'
                    ))


class SensitiveDataScanner:
    """Scan for PII, API keys, credentials in responses"""

    PATTERNS = {
        'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'phone': re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),
        'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        'credit_card': re.compile(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'),
        'api_key': re.compile(r'(?i)(api[_-]?key|apikey|api[_-]?secret)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})'),
        'aws_key': re.compile(r'AKIA[0-9A-Z]{16}'),
        'jwt': re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
        'password': re.compile(r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^"\'\s]{6,})'),
        'private_key': re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----')
    }

    def __init__(self, har_data: Dict):
        self.har_data = har_data
        self.findings = []

    def scan(self) -> List[SecurityIssue]:
        """Scan all responses for sensitive data"""
        entries = self.har_data.get('log', {}).get('entries', [])

        for entry in entries:
            response = entry.get('response', {})
            content = response.get('content', {}).get('text', '')
            url = entry.get('request', {}).get('url', '')

            if not content:
                continue

            for data_type, pattern in self.PATTERNS.items():
                matches = pattern.findall(content)

                if matches:
                    severity = self._get_severity(data_type)

                    self.findings.append(SecurityIssue(
                        severity=severity,
                        category='Data Leakage',
                        title=f'{data_type.replace("_", " ").title()} exposed in response',
                        description=f'Found {len(matches)} instance(s) of {data_type} in response body',
                        evidence={
                            'url': url,
                            'data_type': data_type,
                            'count': len(matches),
                            'sample': str(matches[0])[:50] + '...' if matches else ''
                        },
                        remediation=f'Remove {data_type} from response or implement proper masking'
                    ))

            self._check_stack_traces(content, url)

        return self.findings

    @staticmethod
    def _get_severity(data_type: str) -> str:
        """Determine severity based on data type"""
        critical_types = ['password', 'private_key', 'api_key', 'aws_key', 'ssn', 'credit_card']
        high_types = ['email', 'phone', 'jwt']

        if data_type in critical_types:
            return 'CRITICAL'
        elif data_type in high_types:
            return 'HIGH'
        else:
            return 'MEDIUM'

    def _check_stack_traces(self, content: str, url: str):
        """Check for stack traces in responses"""
        stack_trace_patterns = [
            r'at\s+[\w.$]+\([^)]+\.java:\d+\)',
            r'File\s+"[^"]+",\s+line\s+\d+',
            r'Traceback\s+\(most\s+recent\s+call\s+last\)',
            r'System\.Exception:',
            r'Fatal error:.*in\s+\/\w+'
        ]

        for pattern in stack_trace_patterns:
            if re.search(pattern, content):
                self.findings.append(SecurityIssue(
                    severity='MEDIUM',
                    category='Information Disclosure',
                    title='Stack trace exposed in response',
                    description='Detailed error information reveals internal application structure',
                    evidence={
                        'url': url,
                        'pattern': pattern
                    },
                    remediation='Disable debug mode and implement custom error pages'
                ))
                break


class TokenEntropyAnalyzer:
    """Analyze session tokens and API keys for predictability"""

    def __init__(self, har_data: Dict):
        self.har_data = har_data
        self.tokens = []

    def extract_tokens(self) -> List[Dict]:
        """Extract tokens from requests"""
        entries = self.har_data.get('log', {}).get('entries', [])

        for entry in entries:
            request = entry.get('request', {})
            headers = {h['name']: h['value'] for h in request.get('headers', [])}

            if 'Authorization' in headers:
                token = headers['Authorization'].replace('Bearer ', '').strip()
                self.tokens.append({
                    'type': 'Bearer Token',
                    'value': token,
                    'url': request.get('url')
                })

            if 'Cookie' in headers:
                cookies = headers['Cookie'].split(';')
                for cookie in cookies:
                    if '=' in cookie:
                        name, value = cookie.split('=', 1)
                        if 'session' in name.lower() or 'token' in name.lower():
                            self.tokens.append({
                                'type': f'Cookie: {name.strip()}',
                                'value': value.strip(),
                                'url': request.get('url')
                            })

        return self.tokens

    @staticmethod
    def calculate_entropy(token: str) -> float:
        """Calculate Shannon entropy of token"""
        if not token:
            return 0.0

        entropy = 0
        for x in range(256):
            p_x = token.count(chr(x)) / len(token)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)

        return entropy

    def analyze(self) -> List[SecurityIssue]:
        """Analyze token strength"""
        self.extract_tokens()
        issues = []

        for token_info in self.tokens:
            token = token_info['value']

            entropy = self.calculate_entropy(token)
            length = len(token)

            is_weak = entropy < 4.0 or length < 16

            if is_weak:
                issues.append(SecurityIssue(
                    severity='HIGH' if entropy < 3.0 else 'MEDIUM',
                    category='Weak Token',
                    title=f'Weak {token_info["type"]}',
                    description=f'Token has low entropy ({entropy:.2f} bits) and may be predictable',
                    evidence={
                        'type': token_info['type'],
                        'length': length,
                        'entropy': entropy,
                        'url': token_info['url']
                    },
                    remediation='Use cryptographically secure random token generation (min 128 bits)'
                ))

        return issues


class PassiveAnalysisOrchestrator:
    """Orchestrate all passive analysis modules"""

    def __init__(self, har_data: Dict):
        self.har_data = har_data
        self.results = {}

    def run_all_checks(self) -> Dict:
        """Run all passive security checks"""
        print("\n" + "=" * 80)
        print("PASSIVE SECURITY ANALYSIS")
        print("=" * 80)

        print("[Passive] Analyzing security headers...")
        self.results['headers'] = SecurityHeadersAnalyzer(self.har_data).analyze()

        print("[Passive] Scanning for sensitive data leakage...")
        self.results['data_leaks'] = SensitiveDataScanner(self.har_data).scan()

        print("[Passive] Analyzing token entropy...")
        self.results['token_strength'] = TokenEntropyAnalyzer(self.har_data).analyze()

        return self.results

    def get_critical_issues(self) -> List[SecurityIssue]:
        """Get all critical and high severity issues"""
        critical = []

        for check_type, issues in self.results.items():
            for issue in issues:
                if issue.severity in ['CRITICAL', 'HIGH']:
                    critical.append(issue)

        return sorted(critical, key=lambda x: (x.severity, x.title))

    def generate_summary(self) -> Dict:
        """Generate summary statistics"""
        all_issues = []
        for issues in self.results.values():
            all_issues.extend(issues)

        severity_counts = {
            'CRITICAL': len([i for i in all_issues if i.severity == 'CRITICAL']),
            'HIGH': len([i for i in all_issues if i.severity == 'HIGH']),
            'MEDIUM': len([i for i in all_issues if i.severity == 'MEDIUM']),
            'LOW': len([i for i in all_issues if i.severity == 'LOW']),
            'INFO': len([i for i in all_issues if i.severity == 'INFO'])
        }

        category_counts = {}
        for issue in all_issues:
            category_counts[issue.category] = category_counts.get(issue.category, 0) + 1

        return {
            'total_issues': len(all_issues),
            'by_severity': severity_counts,
            'by_category': category_counts
        }
