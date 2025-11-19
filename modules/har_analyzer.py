import json
import re
from typing import List, Dict, Set, Optional
from urllib.parse import urlparse, parse_qs


class HARAnalyzer:
    SUSPICIOUS_PARAMS = [
        'id', 'user_id', 'userId', 'uid', 'account',
        'file', 'path', 'url', 'redirect', 'next',
        'cmd', 'command', 'exec', 'query', 'search',
        'admin', 'debug', 'test', 'api_key', 'token'
    ]

    STATIC_EXTENSIONS = {
        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
        '.css', '.js', '.woff', '.woff2', '.ttf', '.eot',
        '.mp4', '.mp3', '.pdf', '.zip'
    }

    def __init__(self, har_path: str, config: Dict):
        self.har_path = har_path
        self.config = config
        self.entries = []
        self.parsed_data = {
            'urls': set(),
            'api_endpoints': [],
            'fuzzable_urls': [],
            'auth_headers': {},
            'domains': set()
        }

    def load_har(self) -> Dict:
        with open(self.har_path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def analyze(self) -> Dict:
        har_data = self.load_har()
        self.entries = har_data.get('log', {}).get('entries', [])

        for entry in self.entries:
            request = entry.get('request', {})

            if not self._should_process(request):
                continue

            url = request.get('url', '')
            method = request.get('method', 'GET')
            headers = {h['name']: h['value'] for h in request.get('headers', [])}

            parsed_url = urlparse(url)
            self.parsed_data['domains'].add(parsed_url.netloc)

            if self._is_static_resource(url):
                continue

            self.parsed_data['urls'].add(url)

            if self._is_api_endpoint(url, headers):
                self.parsed_data['api_endpoints'].append({
                    'url': url,
                    'method': method,
                    'headers': headers
                })

            fuzzable_params = self._extract_fuzzable_params(request)
            if fuzzable_params:
                self.parsed_data['fuzzable_urls'].append({
                    'url': url,
                    'method': method,
                    'params': fuzzable_params,
                    'body': self._get_request_body(request)
                })

            auth_data = self._extract_auth(headers)
            if auth_data:
                self.parsed_data['auth_headers'].update(auth_data)

        return self.parsed_data

    def _should_process(self, request: Dict) -> bool:
        url = request.get('url', '')
        method = request.get('method', 'GET')

        scope_domains = self.config.get('scope_domains', [])
        if scope_domains:
            if not any(domain in url for domain in scope_domains):
                return False

        exclude_domains = self.config.get('exclude_domains', [])
        if any(domain in url for domain in exclude_domains):
            return False

        allowed_methods = self.config.get('allowed_methods', ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
        if method not in allowed_methods:
            return False

        return True

    def _is_static_resource(self, url: str) -> bool:
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        return any(path_lower.endswith(ext) for ext in self.STATIC_EXTENSIONS)

    def _is_api_endpoint(self, url: str, headers: Dict) -> bool:
        content_type = headers.get('Content-Type', '').lower()
        if 'application/json' in content_type or 'application/xml' in content_type:
            return True

        if '/api/' in url or url.endswith('/api'):
            return True

        return False

    def _extract_fuzzable_params(self, request: Dict) -> List[str]:
        fuzzable = []
        url = request.get('url', '')
        parsed = urlparse(url)

        query_params = parse_qs(parsed.query)
        for param in query_params.keys():
            if self._is_suspicious_param(param):
                fuzzable.append(param)

        post_data = request.get('postData', {})
        if post_data:
            text = post_data.get('text', '')
            if text:
                try:
                    body = json.loads(text)
                    if isinstance(body, dict):
                        for key in body.keys():
                            if self._is_suspicious_param(key):
                                fuzzable.append(f"body.{key}")
                except:
                    params = parse_qs(text)
                    for param in params.keys():
                        if self._is_suspicious_param(param):
                            fuzzable.append(f"form.{param}")

        return fuzzable

    def _is_suspicious_param(self, param: str) -> bool:
        param_lower = param.lower()
        return any(suspect in param_lower for suspect in self.SUSPICIOUS_PARAMS)

    def _get_request_body(self, request: Dict) -> Optional[str]:
        post_data = request.get('postData', {})
        return post_data.get('text') if post_data else None

    def _extract_auth(self, headers: Dict) -> Dict:
        auth_data = {}

        if 'Authorization' in headers:
            auth_data['Authorization'] = headers['Authorization']

        if 'Cookie' in headers:
            auth_data['Cookie'] = headers['Cookie']

        for key, value in headers.items():
            if 'token' in key.lower() or 'auth' in key.lower():
                auth_data[key] = value

        return auth_data

    def get_summary(self) -> str:
        return f"""HAR Analysis Summary:
- Total URLs: {len(self.parsed_data['urls'])}
- API Endpoints: {len(self.parsed_data['api_endpoints'])}
- Fuzzable URLs: {len(self.parsed_data['fuzzable_urls'])}
- Domains: {', '.join(self.parsed_data['domains'])}
- Auth Headers Found: {len(self.parsed_data['auth_headers'])}
"""
