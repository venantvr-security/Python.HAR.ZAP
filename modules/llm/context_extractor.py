"""
HAR Context Extractor - Privacy-safe extraction for LLM analysis.
Extracts only keys/schemas/patterns, never actual values.
"""
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Any, Optional
from urllib.parse import urlparse, parse_qs


@dataclass
class HARContext:
    """Privacy-safe HAR context for LLM analysis."""
    har_hash: str
    endpoints: List[str]
    param_names: List[str]
    json_keys: List[str]
    json_schemas: Dict[str, str]
    domains: List[str]
    methods_used: Dict[str, int]
    auth_types: List[str]
    id_patterns: List[Dict[str, str]]
    request_flows: List[List[str]]
    content_types: List[str]

    def to_prompt_context(self) -> str:
        """Format for LLM prompt."""
        return json.dumps({
            "endpoints": self.endpoints[:50],
            "param_names": self.param_names[:100],
            "json_keys": self.json_keys[:200],
            "json_schemas": dict(list(self.json_schemas.items())[:20]),
            "domains": self.domains,
            "methods": self.methods_used,
            "auth_types": self.auth_types,
            "id_patterns": self.id_patterns[:30],
            "request_flows": self.request_flows[:10]
        }, indent=2)


class HARContextExtractor:
    """
    Extract privacy-safe context from HAR.
    NEVER sends actual values, only keys/schemas/patterns.
    """

    ID_PATTERNS = {
        'numeric_sequential': r'^\d{1,10}$',
        'uuid_v4': r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        'uuid_any': r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        'mongo_objectid': r'^[0-9a-f]{24}$',
        'base64': r'^[A-Za-z0-9+/]{20,}=*$',
        'prefixed_id': r'^[A-Z]{2,4}[-_]\d+$',
        'opaque_token': r'^[A-Za-z0-9_-]{20,}$'
    }

    def __init__(self, har_data: Dict):
        self.har_data = har_data
        self.entries = har_data.get('log', {}).get('entries', [])

    def extract(self) -> HARContext:
        """Extract all context in one pass."""
        endpoints: Set[str] = set()
        param_names: Set[str] = set()
        json_keys: Set[str] = set()
        json_schemas: Dict[str, str] = {}
        domains: Set[str] = set()
        methods: Dict[str, int] = {}
        auth_types: Set[str] = set()
        id_patterns: List[Dict[str, str]] = []
        request_sequence: List[str] = []
        content_types: Set[str] = set()

        for entry in self.entries:
            request = entry.get('request', {})
            response = entry.get('response', {})
            url = request.get('url', '')
            method = request.get('method', 'GET')

            parsed = urlparse(url)
            domains.add(parsed.netloc)

            # Normalize endpoint
            endpoint = self._normalize_endpoint(parsed.path)
            endpoints.add(f"{method} {endpoint}")
            request_sequence.append(f"{method} {endpoint}")

            methods[method] = methods.get(method, 0) + 1

            # Extract query param names only
            for key in parse_qs(parsed.query).keys():
                param_names.add(key)

            # Also from queryString array
            for p in request.get('queryString', []):
                param_names.add(p.get('name', ''))

            # Detect auth types
            headers = {
                h.get('name', '').lower(): h.get('value', '')
                for h in request.get('headers', [])
            }
            self._detect_auth_types(headers, auth_types)

            # Extract JSON keys from request body
            post_data = request.get('postData', {})
            if 'json' in post_data.get('mimeType', '').lower():
                try:
                    body = json.loads(post_data.get('text', '{}'))
                    keys = self._extract_keys_recursive(body)
                    json_keys.update(keys)
                    json_schemas[endpoint] = self._get_schema(body)
                except (json.JSONDecodeError, TypeError):
                    pass

            # Extract JSON keys from response
            content = response.get('content', {})
            mime = content.get('mimeType', 'unknown')
            content_types.add(mime)
            if 'json' in mime.lower():
                try:
                    body = json.loads(content.get('text', '{}'))
                    keys = self._extract_keys_recursive(body)
                    json_keys.update(keys)
                except (json.JSONDecodeError, TypeError):
                    pass

            # Analyze ID patterns in path segments
            path_parts = [p for p in parsed.path.split('/') if p]
            for i, part in enumerate(path_parts):
                pattern_info = self._classify_id_pattern(part)
                if pattern_info:
                    id_patterns.append({
                        'position': f'path[{i}]',
                        'pattern_type': pattern_info,
                        'endpoint': endpoint
                    })

        # Build request flows
        flows = self._extract_flows(request_sequence)

        # Compute HAR hash for caching
        har_hash = self._compute_har_hash()

        return HARContext(
            har_hash=har_hash,
            endpoints=sorted(endpoints)[:50],
            param_names=sorted(param_names),
            json_keys=sorted(json_keys),
            json_schemas=json_schemas,
            domains=list(domains),
            methods_used=methods,
            auth_types=list(auth_types),
            id_patterns=id_patterns,
            request_flows=flows,
            content_types=list(content_types)
        )

    def _normalize_endpoint(self, path: str) -> str:
        """Normalize path to pattern (replace IDs with placeholders)."""
        path = re.sub(r'/\d+(?=/|$)', '/{id}', path)
        path = re.sub(
            r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            '/{uuid}', path, flags=re.I
        )
        path = re.sub(r'/[0-9a-f]{24}(?=/|$)', '/{objectid}', path, flags=re.I)
        return path

    def _extract_keys_recursive(self, obj: Any, prefix: str = '') -> Set[str]:
        """Extract all keys from nested JSON."""
        keys: Set[str] = set()
        if isinstance(obj, dict):
            for key in obj.keys():
                full_key = f"{prefix}.{key}" if prefix else key
                keys.add(full_key)
                if isinstance(obj[key], dict):
                    keys.update(self._extract_keys_recursive(obj[key], full_key))
                elif isinstance(obj[key], list) and obj[key]:
                    if isinstance(obj[key][0], dict):
                        keys.update(self._extract_keys_recursive(obj[key][0], f"{full_key}[]"))
        return keys

    def _get_schema(self, obj: Any) -> str:
        """Get JSON schema structure (types only)."""
        if isinstance(obj, dict):
            return json.dumps({k: type(v).__name__ for k, v in obj.items()})
        return str(type(obj).__name__)

    def _classify_id_pattern(self, value: str) -> Optional[str]:
        """Classify value as ID pattern type."""
        for pattern_name, regex in self.ID_PATTERNS.items():
            if re.match(regex, value, re.I):
                return pattern_name
        return None

    def _detect_auth_types(self, headers: Dict[str, str], auth_types: Set[str]):
        """Detect authentication types from headers."""
        if 'authorization' in headers:
            auth_value = headers['authorization'].lower()
            if 'bearer' in auth_value:
                auth_types.add('Bearer')
            elif 'basic' in auth_value:
                auth_types.add('Basic')
            else:
                auth_types.add('Other')
        if 'cookie' in headers:
            auth_types.add('Cookie')
        for h in headers.keys():
            if 'api' in h and 'key' in h:
                auth_types.add('API-Key')
                break

    def _extract_flows(self, sequence: List[str]) -> List[List[str]]:
        """Extract request flow patterns."""
        if len(sequence) < 3:
            return [sequence] if sequence else []

        flows = []
        window_size = 5
        for i in range(0, len(sequence) - window_size + 1, window_size):
            flows.append(sequence[i:i + window_size])
        return flows[:10]

    def _compute_har_hash(self) -> str:
        """Compute stable hash for HAR content."""
        content = json.dumps({
            'entries_count': len(self.entries),
            'endpoints': sorted(set(
                self._normalize_endpoint(urlparse(e.get('request', {}).get('url', '')).path)
                for e in self.entries
            ))
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]
