"""
Pattern Extractor - Extract patterns from HAR for payload enrichment.
"""
import re
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Set, Optional
from urllib.parse import urlparse, parse_qs


class PatternType(Enum):
    NUMERIC_ID = "numeric_id"
    UUID = "uuid"
    EMAIL = "email"
    JWT = "jwt"
    FILE_PATH = "file_path"
    MONGO_ID = "mongo_id"


@dataclass
class InjectionPoint:
    url: str
    method: str
    location: str  # query, body, header, path
    param_name: str
    original_value: str
    pattern_type: PatternType


@dataclass
class ExtractionResult:
    pattern_type: PatternType
    values: Set[str] = field(default_factory=set)
    injection_points: List[InjectionPoint] = field(default_factory=list)


DEFAULT_PATTERNS = {
    'numeric_id': r'\b\d{1,10}\b',
    'uuid': r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    'jwt': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
    'file_path': r'(?:\.\.\/)+|(?:\/[a-zA-Z0-9_-]+)+',
    'mongo_id': r'[0-9a-f]{24}',
}


class PatternExtractor:
    """Extract patterns from HAR and identify injection points."""

    def __init__(self, har_data: Dict, config: Dict = None):
        self.har_data = har_data
        self.config = config or {}
        self.patterns = self._load_patterns()
        self.results: Dict[str, ExtractionResult] = {}

    def _load_patterns(self) -> Dict[str, re.Pattern]:
        """Load patterns from config or use defaults."""
        pattern_strings = self.config.get('extraction_patterns', DEFAULT_PATTERNS)
        compiled = {}
        for name, pattern in pattern_strings.items():
            try:
                compiled[name] = re.compile(pattern, re.IGNORECASE)
            except re.error:
                compiled[name] = re.compile(DEFAULT_PATTERNS.get(name, r'.*'))
        return compiled

    def extract_from_har(self) -> Dict[str, ExtractionResult]:
        """Extract all pattern matches from HAR."""
        # Initialize results
        for pattern_name in self.patterns:
            try:
                ptype = PatternType(pattern_name)
            except ValueError:
                ptype = PatternType.NUMERIC_ID  # fallback
            self.results[pattern_name] = ExtractionResult(pattern_type=ptype)

        entries = self.har_data.get('log', {}).get('entries', [])
        for entry in entries:
            request = entry.get('request', {})
            response = entry.get('response', {})
            self._extract_from_request(request)
            self._extract_from_response(response)

        return self.results

    def _extract_from_request(self, request: Dict):
        """Extract patterns from request."""
        url = request.get('url', '')
        method = request.get('method', 'GET')
        parsed = urlparse(url)

        # Path segments
        path_parts = [p for p in parsed.path.split('/') if p]
        for i, part in enumerate(path_parts):
            self._match_and_record(part, url, method, 'path', f'path[{i}]')

        # Query parameters
        params = parse_qs(parsed.query)
        for param, values in params.items():
            for value in values:
                self._match_and_record(value, url, method, 'query', param)

        # Headers
        for header in request.get('headers', []):
            name = header.get('name', '')
            value = header.get('value', '')
            self._match_and_record(value, url, method, 'header', name)

        # POST body
        post_data = request.get('postData', {})
        self._extract_from_body(post_data, url, method)

    def _extract_from_response(self, response: Dict):
        """Extract patterns from response (values only, no injection points)."""
        content = response.get('content', {})
        text = content.get('text', '')
        if text:
            self._match_values_only(text)

    def _extract_from_body(self, post_data: Dict, url: str, method: str):
        """Extract patterns from request body."""
        mime = post_data.get('mimeType', '')
        text = post_data.get('text', '')
        params = post_data.get('params', [])

        # Handle form params (may exist without text)
        if 'form' in mime and params:
            for param in params:
                name = param.get('name', '')
                value = param.get('value', '')
                self._match_and_record(value, url, method, 'body', name)
            return

        if not text:
            return

        if 'json' in mime:
            try:
                body = json.loads(text)
                self._extract_from_json(body, url, method, 'body')
            except json.JSONDecodeError:
                self._match_values_only(text)
        else:
            self._match_values_only(text)

    def _extract_from_json(self, obj, url: str, method: str, location: str, prefix: str = ''):
        """Recursively extract from JSON."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                path = f"{prefix}.{key}" if prefix else key
                if isinstance(value, str):
                    self._match_and_record(value, url, method, location, path)
                elif isinstance(value, (int, float)):
                    self._match_and_record(str(value), url, method, location, path)
                elif isinstance(value, (dict, list)):
                    self._extract_from_json(value, url, method, location, path)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                path = f"{prefix}[{i}]"
                if isinstance(item, str):
                    self._match_and_record(item, url, method, location, path)
                elif isinstance(item, (dict, list)):
                    self._extract_from_json(item, url, method, location, path)

    def _match_and_record(self, value: str, url: str, method: str, location: str, param_name: str):
        """Match value against patterns and record injection points."""
        if not value:
            return

        for pattern_name, regex in self.patterns.items():
            if regex.fullmatch(value):
                result = self.results.get(pattern_name)
                if result:
                    result.values.add(value)
                    try:
                        ptype = PatternType(pattern_name)
                    except ValueError:
                        ptype = PatternType.NUMERIC_ID
                    result.injection_points.append(InjectionPoint(
                        url=url,
                        method=method,
                        location=location,
                        param_name=param_name,
                        original_value=value,
                        pattern_type=ptype
                    ))

    def _match_values_only(self, text: str):
        """Extract pattern matches without creating injection points."""
        for pattern_name, regex in self.patterns.items():
            matches = regex.findall(text)
            result = self.results.get(pattern_name)
            if result:
                result.values.update(matches)

    def identify_injection_points(self) -> List[InjectionPoint]:
        """Return all identified injection points."""
        if not self.results:
            self.extract_from_har()

        points = []
        for result in self.results.values():
            points.extend(result.injection_points)
        return points

    def get_summary(self) -> Dict:
        """Get extraction summary for API response."""
        if not self.results:
            self.extract_from_har()

        summary = {
            'total_values': 0,
            'total_injection_points': 0,
            'patterns': {}
        }

        for pattern_name, result in self.results.items():
            values_list = sorted(result.values)
            points_count = len(result.injection_points)
            summary['patterns'][pattern_name] = {
                'values_count': len(values_list),
                'values': values_list[:50],  # Limit for response size
                'injection_points_count': points_count,
                'injection_points': [
                    {
                        'url': p.url[:100],
                        'method': p.method,
                        'location': p.location,
                        'param': p.param_name,
                        'value': p.original_value
                    }
                    for p in result.injection_points[:20]
                ]
            }
            summary['total_values'] += len(values_list)
            summary['total_injection_points'] += points_count

        return summary

    def get_injection_points_by_pattern(self, pattern_type: str) -> List[InjectionPoint]:
        """Get injection points for a specific pattern type."""
        if not self.results:
            self.extract_from_har()

        result = self.results.get(pattern_type)
        if result:
            return result.injection_points
        return []

    def get_values_by_pattern(self, pattern_type: str) -> List[str]:
        """Get extracted values for a specific pattern type."""
        if not self.results:
            self.extract_from_har()

        result = self.results.get(pattern_type)
        if result:
            return sorted(result.values)
        return []
