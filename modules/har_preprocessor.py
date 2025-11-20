"""
HAR Preprocessor - Unified HAR processing and extraction
Centralizes all HAR parsing, filtering, extraction into a single output file
"""
import json
import re
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Any
from urllib.parse import urlparse, parse_qs


@dataclass
class PreprocessedHAR:
    """Unified preprocessed HAR data structure"""
    metadata: Dict[str, Any]
    endpoints: List[Dict[str, Any]]
    querystrings: Dict[str, List[Dict[str, Any]]]
    payloads: Dict[str, List[Dict[str, Any]]]
    dictionaries: Dict[str, Any]
    statistics: Dict[str, Any]


class HARPreprocessor:
    """
    Unified HAR preprocessing pipeline
    Extracts everything in one pass, outputs single JSON file
    """

    def __init__(self, har_path: str = None, har_data: Dict = None):
        """Initialize with either file path or HAR data"""
        if har_path:
            with open(har_path, 'r') as f:
                self.har_data = json.load(f)
        elif har_data:
            self.har_data = har_data
        else:
            raise ValueError("Provide either har_path or har_data")

        self.filters = {
            'methods': None,  # None = all, or list like ['GET', 'POST']
            'domains': None,  # None = all, or list of domains
            'exclude_domains': [],
            'status_codes': None,  # None = all, or list like [200, 201]
            'content_types': None,  # None = all, or list like ['application/json']
            'min_response_size': 0,
            'max_response_size': None,
            'exclude_static': True  # Exclude .js, .css, images
        }

        # Extracted data
        self.endpoints: List[Dict] = []
        self.querystrings: Dict[str, List[Dict]] = defaultdict(list)
        self.payloads: Dict[str, List[Dict]] = defaultdict(list)
        # noinspection PyTypeChecker
        self.dictionaries = {
            'keys': {},
            'values': defaultdict(set),
            'parameters': defaultdict(set),
            'headers': defaultdict(set),
            'cookies': defaultdict(set)
        }

    def set_filters(self, **kwargs):
        """Configure filters"""
        self.filters.update(kwargs)
        return self

    def process(self) -> PreprocessedHAR:
        """
        Main processing pipeline
        Single pass through HAR, extract everything
        """
        entries = self.har_data.get('log', {}).get('entries', [])

        print(f"[HARPreprocessor] Processing {len(entries)} entries...")

        for idx, entry in enumerate(entries):
            if not self._should_process(entry):
                continue

            request = entry.get('request', {})
            response = entry.get('response', {})

            # Extract all data in one pass
            endpoint_data = self._extract_endpoint(request, response, idx)
            self.endpoints.append(endpoint_data)

            # Extract querystrings
            self._extract_querystrings(request, endpoint_data['endpoint'])

            # Extract payloads (request + response)
            self._extract_payloads(request, response, endpoint_data['endpoint'])

            # Build dictionaries
            self._build_dictionaries(request, response, endpoint_data['endpoint'])

        # Generate final output
        result = PreprocessedHAR(
            metadata=self._generate_metadata(),
            endpoints=self.endpoints,
            querystrings=dict(self.querystrings),
            payloads=dict(self.payloads),
            dictionaries=self._finalize_dictionaries(),
            statistics=self._generate_statistics()
        )

        print(f"[HARPreprocessor] Processed {len(self.endpoints)} endpoints")
        print(f"  - {len(self.querystrings)} unique querystring patterns")
        print(f"  - {len(self.payloads)} unique payload patterns")
        print(f"  - {len(self.dictionaries['keys'])} unique keys extracted")

        return result

    def _should_process(self, entry: Dict) -> bool:
        """Apply filters to entry"""
        request = entry.get('request', {})
        response = entry.get('response', {})

        url = request.get('url', '')
        method = request.get('method', '')

        # Method filter
        if self.filters['methods'] and method not in self.filters['methods']:
            return False

        # Domain filter
        domain = urlparse(url).netloc
        if self.filters['domains'] and not any(d in domain for d in self.filters['domains']):
            return False

        if domain in self.filters['exclude_domains']:
            return False

        # Status code filter
        status = response.get('status', 0)
        if self.filters['status_codes'] and status not in self.filters['status_codes']:
            return False

        # Content type filter
        content_type = self._get_content_type(response)
        if self.filters['content_types'] and not any(ct in content_type for ct in self.filters['content_types']):
            return False

        # Response size filter
        size = response.get('content', {}).get('size', 0)
        if size < self.filters['min_response_size']:
            return False
        if self.filters['max_response_size'] and size > self.filters['max_response_size']:
            return False

        # Exclude static resources
        if self.filters['exclude_static']:
            static_extensions = ['.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg',
                                 '.ico', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3']
            if any(url.lower().endswith(ext) for ext in static_extensions):
                return False

        return True

    def _extract_endpoint(self, request: Dict, response: Dict, idx: int) -> Dict:
        """Extract endpoint information"""
        url = request.get('url', '')
        method = request.get('method', '')
        status = response.get('status', 0)

        parsed = urlparse(url)
        endpoint_pattern = self._normalize_endpoint(parsed.path)

        headers = {h['name']: h['value'] for h in request.get('headers', [])}

        # Extract authentication info
        auth_headers = {}
        for header in ['authorization', 'cookie', 'x-api-key', 'x-auth-token']:
            if header in [h.lower() for h in headers.keys()]:
                actual_header = [h for h in headers.keys() if h.lower() == header][0]
                auth_headers[actual_header] = headers[actual_header]

        return {
            'id': idx,
            'url': url,
            'endpoint': endpoint_pattern,
            'method': method,
            'domain': parsed.netloc,
            'path': parsed.path,
            'query_string': parsed.query,
            'status_code': status,
            'content_type': self._get_content_type(response),
            'response_size': response.get('content', {}).get('size', 0),
            'has_auth': bool(auth_headers),
            'auth_headers': auth_headers,
            'timestamp': request.get('startedDateTime', '')
        }

    def _extract_querystrings(self, request: Dict, endpoint: str):
        """Extract querystring parameters"""
        url = request.get('url', '')
        parsed = urlparse(url)

        if not parsed.query:
            return

        params = parse_qs(parsed.query)

        for param_name, values in params.items():
            for value in values:
                self.querystrings[endpoint].append({
                    'parameter': param_name,
                    'value': value,
                    'full_query': parsed.query
                })

    def _extract_payloads(self, request: Dict, response: Dict, endpoint: str):
        """Extract JSON payloads from request and response"""
        method = request.get('method', '')

        # Request payload
        post_data = request.get('postData', {})
        if post_data.get('mimeType') == 'application/json':
            text = post_data.get('text', '')
            try:
                payload = json.loads(text)
                self.payloads[endpoint].append({
                    'direction': 'request',
                    'method': method,
                    'content_type': 'application/json',
                    'payload': payload,
                    'size': len(text)
                })
            except Exception:  # Broad exception for robustness
                pass

        # Response payload
        content = response.get('content', {})
        if content.get('mimeType', '').startswith('application/json'):
            text = content.get('text', '')
            try:
                payload = json.loads(text)
                self.payloads[endpoint].append({
                    'direction': 'response',
                    'method': method,
                    'content_type': content.get('mimeType', ''),
                    'payload': payload,
                    'size': len(text)
                })
            except Exception:  # Broad exception for robustness
                pass

    def _build_dictionaries(self, request: Dict, response: Dict, endpoint: str):
        """Build comprehensive dictionaries"""
        # From URL parameters
        url = request.get('url', '')
        parsed = urlparse(url)

        if parsed.query:
            params = parse_qs(parsed.query)
            for param, values in params.items():
                self.dictionaries['parameters'][param].update(values)

        # From headers
        for header in request.get('headers', []):
            name = header['name']
            value = header['value']
            self.dictionaries['headers'][name].add(value)

        # From cookies
        for cookie in request.get('cookies', []):
            name = cookie['name']
            value = cookie['value']
            self.dictionaries['cookies'][name].add(value)

        # From JSON payloads
        post_data = request.get('postData', {})
        if post_data.get('mimeType') == 'application/json':
            try:
                payload = json.loads(post_data.get('text', '{}'))
                self._extract_keys_recursive(payload, endpoint)
            except Exception:  # Broad exception for robustness
                pass

        content = response.get('content', {})
        if content.get('mimeType', '').startswith('application/json'):
            try:
                payload = json.loads(content.get('text', '{}'))
                self._extract_keys_recursive(payload, endpoint)
            except Exception:  # Broad exception for robustness
                pass

    def _extract_keys_recursive(self, obj: Any, endpoint: str, path: str = ''):
        """Recursively extract keys and values from JSON"""
        if isinstance(obj, dict):
            for key, value in obj.items():
                full_key = f"{path}.{key}" if path else key

                # Store key metadata
                if full_key not in self.dictionaries['keys']:
                    self.dictionaries['keys'][full_key] = {
                        'type': type(value).__name__,
                        'endpoints': set(),
                        'examples': []
                    }

                self.dictionaries['keys'][full_key]['endpoints'].add(endpoint)

                # Store value examples
                if not isinstance(value, (dict, list)):
                    if len(self.dictionaries['keys'][full_key]['examples']) < 10:
                        self.dictionaries['keys'][full_key]['examples'].append(value)
                    self.dictionaries['values'][full_key].add(str(value))

                # Recurse
                if isinstance(value, dict):
                    self._extract_keys_recursive(value, endpoint, full_key)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            self._extract_keys_recursive(item, endpoint, full_key)

        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    self._extract_keys_recursive(item, endpoint, path)

    @staticmethod
    def _normalize_endpoint(path: str) -> str:
        """Normalize URL path to pattern"""
        # Replace numeric IDs
        path = re.sub(r'/\d+', '/{id}', path)
        # Replace UUIDs
        path = re.sub(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                      '/{uuid}', path, flags=re.I)
        # Replace MongoDB ObjectIds
        path = re.sub(r'/[0-9a-f]{24}', '/{objectid}', path, flags=re.I)
        return path

    @staticmethod
    def _get_content_type(response: Dict) -> str:
        """Extract content type from response"""
        content = response.get('content', {})
        return content.get('mimeType', 'unknown')

    def _finalize_dictionaries(self) -> Dict[str, Any]:
        """Convert sets to lists for JSON serialization"""
        return {
            'keys': {
                k: {
                    'type': v['type'],
                    'endpoints': list(v['endpoints']) if isinstance(v['endpoints'], set) else v['endpoints'],
                    'examples': v['examples']
                }
                for k, v in self.dictionaries['keys'].items()
            },
            'values': {k: list(v) if isinstance(v, set) else v for k, v in self.dictionaries['values'].items()},
            'parameters': {k: list(v) if isinstance(v, set) else v for k, v in self.dictionaries['parameters'].items()},
            'headers': {k: list(v) if isinstance(v, set) else v for k, v in self.dictionaries['headers'].items()},
            'cookies': {k: list(v) if isinstance(v, set) else v for k, v in self.dictionaries['cookies'].items()}
        }

    def _generate_metadata(self) -> Dict:
        """Generate metadata about the HAR file"""
        log = self.har_data.get('log', {})

        return {
            'source': 'HAR file',
            'processed_at': datetime.now().isoformat(),
            'har_creator': log.get('creator', {}),
            'har_version': log.get('version', 'unknown'),
            'filters_applied': self.filters,
            'total_entries': len(self.har_data.get('log', {}).get('entries', []))
        }

    def _generate_statistics(self) -> Dict:
        """Generate processing statistics"""
        methods = defaultdict(int)
        domains = defaultdict(int)
        status_codes = defaultdict(int)

        for endpoint in self.endpoints:
            methods[endpoint['method']] += 1
            domains[endpoint['domain']] += 1
            status_codes[endpoint['status_code']] += 1

        return {
            'total_endpoints': len(self.endpoints),
            'unique_endpoint_patterns': len(set(e['endpoint'] for e in self.endpoints)),
            'methods': dict(methods),
            'domains': dict(domains),
            'status_codes': dict(status_codes),
            'total_querystrings': sum(len(v) for v in self.querystrings.values()),
            'unique_querystring_params': len(set(
                qs['parameter']
                for qss in self.querystrings.values()
                for qs in qss
            )),
            'total_payloads': sum(len(v) for v in self.payloads.values()),
            'total_unique_keys': len(self.dictionaries['keys']),
            'total_unique_values': sum(len(v) for v in self.dictionaries['values'].values())
        }

    def save(self, output_path: str) -> str:
        """
        Process and save to single JSON file
        This is the main output consumed by all other modules
        """
        result = self.process()

        # Convert dataclass to dict
        output = asdict(result)

        with open(output_path, 'w') as f:
            json.dump(output, f, indent=2, default=str)

        print(f"\n[HARPreprocessor] ✓ Saved preprocessed HAR to: {output_path}")
        print(f"  File size: {os.path.getsize(output_path) / 1024:.2f} KB")

        return output_path

    def save_extracts(self, base_path: str):
        """
        Save individual extracts as separate files (optional)
        For users who want granular access
        """
        import os

        os.makedirs(base_path, exist_ok=True)

        result = self.process()

        # Save each component separately
        components = {
            'metadata.json': result.metadata,
            'endpoints.json': result.endpoints,
            'querystrings.json': result.querystrings,
            'payloads.json': result.payloads,
            'dictionaries.json': result.dictionaries,
            'statistics.json': result.statistics
        }

        for filename, data in components.items():
            path = os.path.join(base_path, filename)
            with open(path, 'w') as f:
                json.dump(data, f, indent=2, default=str)

        print(f"\n[HARPreprocessor] ✓ Saved extracts to: {base_path}/")
        for filename in components.keys():
            print(f"  - {filename}")

    def print_summary(self):
        """Print processing summary"""
        result = self.process()

        print("\n" + "=" * 60)
        print("HAR PREPROCESSING SUMMARY")
        print("=" * 60)

        print("\n📊 STATISTICS:")
        for key, value in result.statistics.items():
            if isinstance(value, dict):
                print(f"  {key}:")
                for k, v in value.items():
                    print(f"    - {k}: {v}")
            else:
                print(f"  {key}: {value}")

        print("\n🔑 DICTIONARIES:")
        print(f"  Unique keys: {len(result.dictionaries['keys'])}")
        print(f"  Unique parameters: {len(result.dictionaries['parameters'])}")
        print(f"  Unique headers: {len(result.dictionaries['headers'])}")
        print(f"  Unique cookies: {len(result.dictionaries['cookies'])}")

        print("\n🎯 TOP ENDPOINTS:")
        endpoint_counts = defaultdict(int)
        for e in result.endpoints:
            endpoint_counts[e['endpoint']] += 1

        for endpoint, count in sorted(endpoint_counts.items(),
                                      key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {endpoint}: {count} requests")

        print("\n" + "=" * 60)


import os
