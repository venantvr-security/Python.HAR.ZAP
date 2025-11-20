"""
Token/Value Dictionary Extractor from HAR
Builds fuzzing wordlists from real application values
"""
import re
from collections import defaultdict
from typing import Dict, List, Set
from urllib.parse import urlparse, parse_qs


class TokenExtractor:
    """Extract tokens, IDs, and values from HAR for intelligent fuzzing"""

    def __init__(self, har_data: Dict):
        self.har_data = har_data
        self.tokens = {
            'ids': set(),  # Numeric/UUID identifiers
            'usernames': set(),  # Username patterns
            'emails': set(),  # Email addresses
            'api_keys': set(),  # API key patterns
            'session_tokens': set(),  # Session identifiers
            'paths': set(),  # URL paths
            'params': set(),  # Parameter names
            'values': defaultdict(set),  # param -> values mapping
            'headers': defaultdict(set),  # header -> values mapping
        }

    def extract_all(self) -> Dict[str, Set]:
        """Extract all token types from HAR"""
        entries = self.har_data.get('log', {}).get('entries', [])

        for entry in entries:
            request = entry.get('request', {})
            response = entry.get('response', {})

            self._extract_from_request(request)
            self._extract_from_response(response)

        return self._to_wordlists()

    def _extract_from_request(self, request: Dict):
        """Extract tokens from request"""
        # URL params
        url = request.get('url', '')
        parsed = urlparse(url)

        # Path segments as potential IDs
        path_parts = [p for p in parsed.path.split('/') if p]
        for part in path_parts:
            if self._is_id(part):
                self.tokens['ids'].add(part)
            self.tokens['paths'].add(part)

        # Query parameters
        params = parse_qs(parsed.query)
        for param, values in params.items():
            self.tokens['params'].add(param)
            for value in values:
                self._categorize_value(param, value)

        # Headers
        for header in request.get('headers', []):
            name = header['name']
            value = header['value']

            if name.lower() in ['authorization', 'cookie', 'x-api-key', 'x-auth-token']:
                self._extract_auth_tokens(name, value)

            self.tokens['headers'][name].add(value)

        # POST body
        post_data = request.get('postData', {})
        if post_data.get('mimeType') == 'application/json':
            import json

            try:
                body = json.loads(post_data.get('text', '{}'))
                self._extract_from_json(body)
            except Exception:  # Broad exception for robustness
                pass

    def _extract_from_response(self, response: Dict):
        """Extract tokens from response"""
        # Response headers (Set-Cookie, etc)
        for header in response.get('headers', []):
            name = header['name']
            value = header['value']

            if name.lower() == 'set-cookie':
                self._extract_cookies(value)

        # Response body
        content = response.get('content', {})
        if content.get('mimeType', '').startswith('application/json'):
            import json

            try:
                body = json.loads(content.get('text', '{}'))
                self._extract_from_json(body)
            except Exception:  # Broad exception for robustness
                pass

    def _extract_from_json(self, obj, prefix=''):
        """Recursively extract values from JSON"""
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, (str, int, float)):
                    self._categorize_value(key, str(value))
                elif isinstance(value, (dict, list)):
                    self._extract_from_json(value, f"{prefix}{key}.")
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    self._extract_from_json(item, prefix)

    def _categorize_value(self, param: str, value: str):
        """Categorize value by pattern"""
        param_lower = param.lower()

        # Store param->value mapping
        self.tokens['values'][param].add(value)

        # IDs
        if 'id' in param_lower or self._is_id(value):
            self.tokens['ids'].add(value)

        # Emails
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            self.tokens['emails'].add(value)

        # Usernames
        if param_lower in ['username', 'user', 'login', 'account']:
            self.tokens['usernames'].add(value)

        # API keys (32+ hex/base64)
        if len(value) > 20 and re.match(r'^[A-Za-z0-9+/=_-]+$', value):
            if 'key' in param_lower or 'token' in param_lower:
                self.tokens['api_keys'].add(value)

    def _extract_auth_tokens(self, header_name: str, value: str):
        """Extract authentication tokens"""
        # Bearer tokens
        if value.startswith('Bearer '):
            token = value[7:]
            self.tokens['session_tokens'].add(token)

        # Basic auth
        elif value.startswith('Basic '):
            self.tokens['api_keys'].add(value[6:])

        # Cookies
        elif header_name.lower() == 'cookie':
            self._extract_cookies(value)

    def _extract_cookies(self, cookie_str: str):
        """Extract session tokens from cookies"""
        for part in cookie_str.split(';'):
            if '=' in part:
                name, value = part.split('=', 1)
                name = name.strip()
                value = value.strip()

                if any(s in name.lower() for s in ['session', 'token', 'auth', 'sid']):
                    self.tokens['session_tokens'].add(value)

    @staticmethod
    def _is_id(value: str) -> bool:
        """Check if value looks like an ID"""
        # UUID
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.I):
            return True

        # Numeric ID
        if value.isdigit() and len(value) < 20:
            return True

        # MongoDB ObjectId
        if len(value) == 24 and re.match(r'^[0-9a-f]{24}$', value, re.I):
            return True

        return False

    def _to_wordlists(self) -> Dict[str, List[str]]:
        """Convert sets to sorted lists for fuzzing"""
        return {
            'ids': sorted(self.tokens['ids']),
            'usernames': sorted(self.tokens['usernames']),
            'emails': sorted(self.tokens['emails']),
            'api_keys': sorted(self.tokens['api_keys'])[:10],  # Limit sensitive
            'session_tokens': sorted(self.tokens['session_tokens'])[:5],
            'paths': sorted(self.tokens['paths']),
            'params': sorted(self.tokens['params']),
            'values': {k: sorted(v) for k, v in self.tokens['values'].items()},
            'headers': {k: sorted(v) for k, v in self.tokens['headers'].items()},
        }

    def export_for_zap_fuzzer(self, output_dir: str = './wordlists'):
        """Export wordlists in format compatible with ZAP fuzzer"""
        import os

        os.makedirs(output_dir, exist_ok=True)

        wordlists = self._to_wordlists()

        # Export each category
        for category, items in wordlists.items():
            if isinstance(items, list) and items:
                filepath = os.path.join(output_dir, f'{category}.txt')
                with open(filepath, 'w') as f:
                    f.write('\n'.join(str(item) for item in items))
                print(f"[TokenExtractor] Exported {len(items)} {category} to {filepath}")

            elif isinstance(items, dict):
                # Export param-specific wordlists
                for param, values in items.items():
                    if values:
                        safe_param = re.sub(r'[^a-zA-Z0-9_-]', '_', param)
                        filepath = os.path.join(output_dir, f'{category}_{safe_param}.txt')
                        with open(filepath, 'w') as f:
                            f.write('\n'.join(str(v) for v in values))

    def get_fuzzing_recommendations(self) -> List[Dict]:
        """Recommend fuzzing targets based on extracted data"""
        recommendations = []

        # High-value fuzzing targets
        if self.tokens['ids']:
            recommendations.append({
                'target': 'IDOR Testing',
                'params': ['id', 'user_id', 'account_id'],
                'wordlist': list(self.tokens['ids']),
                'priority': 'CRITICAL',
                'reason': f"Found {len(self.tokens['ids'])} unique IDs in traffic"
            })

        if self.tokens['usernames']:
            recommendations.append({
                'target': 'Username Enumeration',
                'params': ['username', 'user', 'email'],
                'wordlist': list(self.tokens['usernames']),
                'priority': 'HIGH',
                'reason': f"Found {len(self.tokens['usernames'])} usernames"
            })

        # Parameter-specific fuzzing
        for param, values in self.tokens['values'].items():
            if len(values) > 5:  # Interesting if multiple values seen
                recommendations.append({
                    'target': f'Parameter Fuzzing: {param}',
                    'params': [param],
                    'wordlist': list(values),
                    'priority': 'MEDIUM',
                    'reason': f"{len(values)} distinct values observed"
                })

        return recommendations
