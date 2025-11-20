"""
Advanced Payload Analyzer - Extract and reconstruct JSON payloads
Builds comprehensive dictionaries for attack reconstruction
"""
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Set, Any


@dataclass
class PayloadSchema:
    """Represents the structure of a JSON payload"""
    endpoint: str
    method: str
    schema: Dict[str, Any]  # Field name -> type/example
    samples: List[Dict]  # Sample payloads observed
    frequency: int = 1
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class KeyValuePair:
    """Represents a key-value pair with metadata"""
    key: str
    value: Any
    value_type: str  # 'string', 'int', 'bool', 'float', 'list', 'dict'
    endpoint: str
    method: str
    frequency: int = 1
    variations: Set[str] = field(default_factory=set)  # All observed values for this key


class PayloadAnalyzer:
    """
    Extracts and analyzes JSON payloads from HAR
    Builds comprehensive dictionaries for payload reconstruction
    """

    def __init__(self, har_data: Dict):
        self.har_data = har_data
        self.schemas: Dict[str, PayloadSchema] = {}  # endpoint+method -> schema
        self.key_value_dictionary: Dict[str, KeyValuePair] = {}  # key -> KV pair
        self.payload_templates: Dict[str, List[Dict]] = defaultdict(list)  # endpoint -> templates
        self.nested_structures: Dict[str, Dict] = {}  # Complex nested objects
        self.array_patterns: Dict[str, List] = defaultdict(list)  # Array structure patterns

    def analyze(self) -> Dict[str, Any]:
        """Main analysis method"""
        entries = self.har_data.get('log', {}).get('entries', [])

        for entry in entries:
            request = entry.get('request', {})
            response = entry.get('response', {})

            # Analyze request payloads
            self._analyze_request_payload(request)

            # Analyze response payloads
            self._analyze_response_payload(request, response)

        return {
            'schemas': {k: self._schema_to_dict(v) for k, v in self.schemas.items()},
            'key_value_dictionary': {k: self._kv_to_dict(v) for k, v in self.key_value_dictionary.items()},
            'payload_templates': dict(self.payload_templates),
            'nested_structures': self.nested_structures,
            'array_patterns': dict(self.array_patterns),
            'statistics': self._generate_statistics()
        }

    def _analyze_request_payload(self, request: Dict):
        """Extract and analyze request payload"""
        url = request.get('url', '')
        method = request.get('method', 'GET')
        endpoint = self._normalize_endpoint(url)

        post_data = request.get('postData', {})
        if post_data.get('mimeType') == 'application/json':
            text = post_data.get('text', '{}')
            try:
                payload = json.loads(text)
                self._process_payload(payload, endpoint, method, 'request')
            except Exception:  # Broad exception for robustness
                pass

    def _analyze_response_payload(self, request: Dict, response: Dict):
        """Extract and analyze response payload"""
        url = request.get('url', '')
        method = request.get('method', 'GET')
        endpoint = self._normalize_endpoint(url)

        content = response.get('content', {})
        if content.get('mimeType', '').startswith('application/json'):
            text = content.get('text', '{}')
            try:
                payload = json.loads(text)
                self._process_payload(payload, endpoint, method, 'response')
            except Exception:  # Broad exception for robustness
                pass

    def _process_payload(self, payload: Dict, endpoint: str, method: str, direction: str):
        """Process a JSON payload and extract patterns"""
        if not isinstance(payload, dict):
            return

        key = f"{endpoint}:{method}:{direction}"

        # Update or create schema
        if key not in self.schemas:
            self.schemas[key] = PayloadSchema(
                endpoint=endpoint,
                method=method,
                schema={},
                samples=[]
            )

        schema = self.schemas[key]
        schema.frequency += 1
        schema.last_seen = datetime.now().isoformat()

        # Add sample (keep max 10 samples per schema)
        if len(schema.samples) < 10:
            schema.samples.append(payload)

        # Extract schema structure
        self._extract_schema(payload, schema.schema, endpoint, method)

        # Extract key-value pairs
        self._extract_key_values(payload, endpoint, method)

        # Store as template
        self.payload_templates[endpoint].append({
            'method': method,
            'direction': direction,
            'payload': payload
        })

    def _extract_schema(self, obj: Any, schema: Dict, endpoint: str, method: str, path: str = ''):
        """Recursively extract schema from JSON object"""
        if isinstance(obj, dict):
            for key, value in obj.items():
                full_path = f"{path}.{key}" if path else key

                if key not in schema:
                    schema[key] = {
                        'type': type(value).__name__,
                        'examples': [],
                        'nested': {}
                    }

                # Add example
                if len(schema[key]['examples']) < 5:
                    if not isinstance(value, (dict, list)):
                        schema[key]['examples'].append(value)

                # Recurse for nested structures
                if isinstance(value, dict):
                    self._extract_schema(value, schema[key]['nested'], endpoint, method, full_path)
                    # Store complex nested structure
                    self.nested_structures[full_path] = value

                elif isinstance(value, list) and value:
                    # Analyze array patterns
                    self.array_patterns[full_path].append({
                        'length': len(value),
                        'item_type': type(value[0]).__name__ if value else 'unknown',
                        'sample': value[:3]  # First 3 items
                    })

        elif isinstance(obj, list):
            for item in obj:
                self._extract_schema(item, schema, endpoint, method, path)

    def _extract_key_values(self, obj: Any, endpoint: str, method: str, parent_key: str = ''):
        """Extract all key-value pairs with context"""
        if isinstance(obj, dict):
            for key, value in obj.items():
                full_key = f"{parent_key}.{key}" if parent_key else key

                # Create or update KV pair
                if full_key not in self.key_value_dictionary:
                    self.key_value_dictionary[full_key] = KeyValuePair(
                        key=full_key,
                        value=value,
                        value_type=type(value).__name__,
                        endpoint=endpoint,
                        method=method,
                        variations=set()
                    )

                kv = self.key_value_dictionary[full_key]
                kv.frequency += 1

                # Track variations (for simple types only)
                if not isinstance(value, (dict, list)):
                    kv.variations.add(str(value))

                # Recurse
                if isinstance(value, dict):
                    self._extract_key_values(value, endpoint, method, full_key)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            self._extract_key_values(item, endpoint, method, full_key)

        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict):
                    self._extract_key_values(item, endpoint, method, parent_key)

    @staticmethod
    def _normalize_endpoint(url: str) -> str:
        """Normalize URL to endpoint pattern"""
        from urllib.parse import urlparse

        parsed = urlparse(url)
        path = parsed.path

        # Replace numeric IDs with placeholders
        path = re.sub(r'/\d+', '/{id}', path)

        # Replace UUIDs with placeholders
        path = re.sub(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '/{uuid}', path, flags=re.I)

        # Replace MongoDB ObjectIds
        path = re.sub(r'/[0-9a-f]{24}', '/{objectid}', path, flags=re.I)

        return path

    @staticmethod
    def _schema_to_dict(schema: PayloadSchema) -> Dict:
        """Convert schema to serializable dict"""
        return {
            'endpoint': schema.endpoint,
            'method': schema.method,
            'schema': schema.schema,
            'samples': schema.samples[:3],  # Limit samples in export
            'frequency': schema.frequency,
            'first_seen': schema.first_seen,
            'last_seen': schema.last_seen
        }

    @staticmethod
    def _kv_to_dict(kv: KeyValuePair) -> Dict:
        """Convert KV pair to serializable dict"""
        return {
            'key': kv.key,
            'value': kv.value if not isinstance(kv.value, (dict, list)) else str(kv.value)[:100],
            'value_type': kv.value_type,
            'endpoint': kv.endpoint,
            'method': kv.method,
            'frequency': kv.frequency,
            'variations': list(kv.variations)[:20]  # Limit variations
        }

    def _generate_statistics(self) -> Dict:
        """Generate analysis statistics"""
        return {
            'total_schemas': len(self.schemas),
            'total_unique_keys': len(self.key_value_dictionary),
            'total_templates': sum(len(t) for t in self.payload_templates.values()),
            'endpoints_analyzed': len(self.payload_templates),
            'nested_structures': len(self.nested_structures),
            'array_patterns': len(self.array_patterns)
        }

    def get_reconstruction_templates(self) -> Dict[str, List[Dict]]:
        """Get templates suitable for payload reconstruction"""
        templates = {}

        for endpoint, payloads in self.payload_templates.items():
            templates[endpoint] = []

            for p in payloads:
                if p['direction'] == 'request':  # Focus on request templates
                    template = self._create_template(p['payload'])
                    templates[endpoint].append({
                        'method': p['method'],
                        'template': template,
                        'original': p['payload']
                    })

        return templates

    def _create_template(self, payload: Dict) -> Dict:
        """Create a template with placeholders for fuzzing"""
        template = {}

        for key, value in payload.items():
            if isinstance(value, dict):
                template[key] = self._create_template(value)
            elif isinstance(value, list):
                template[key] = [self._create_template(v) if isinstance(v, dict) else '{{LIST_ITEM}}' for v in value[:1]]
            elif isinstance(value, str):
                template[key] = f"{{{{{key.upper()}}}}}"
            elif isinstance(value, int):
                template[key] = f"{{{{{key.upper()}_INT}}}}"
            elif isinstance(value, bool):
                template[key] = f"{{{{{key.upper()}_BOOL}}}}"
            else:
                template[key] = value

        return template

    def export_for_attack(self, output_path: str):
        """Export analysis results for attack module"""
        analysis = self.analyze()

        with open(output_path, 'w') as f:
            json.dump(analysis, f, indent=2, default=str)

        print(f"[PayloadAnalyzer] Exported analysis to {output_path}")
        print(f"  - {analysis['statistics']['total_schemas']} schemas")
        print(f"  - {analysis['statistics']['total_unique_keys']} unique keys")
        print(f"  - {analysis['statistics']['total_templates']} payload templates")

    def get_extensible_dictionary(self) -> Dict[str, Any]:
        """
        Get dictionary structure optimized for extension
        Allows users to add custom key-value pairs
        """
        return {
            'keys': {
                key: {
                    'type': kv.value_type,
                    'examples': list(kv.variations)[:10],
                    'frequency': kv.frequency,
                    'context': {
                        'endpoint': kv.endpoint,
                        'method': kv.method
                    }
                }
                for key, kv in self.key_value_dictionary.items()
            },
            'custom_keys': {},  # User can extend here
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_keys': len(self.key_value_dictionary),
                'extensible': True
            }
        }

    def merge_custom_dictionary(self, custom_dict: Dict[str, Any]):
        """
        Merge custom user-provided dictionary with extracted data
        """
        for key, value_info in custom_dict.items():
            if key not in self.key_value_dictionary:
                # Add new custom key
                self.key_value_dictionary[key] = KeyValuePair(
                    key=key,
                    value=value_info.get('value', ''),
                    value_type=value_info.get('type', 'string'),
                    endpoint='custom',
                    method='custom',
                    variations=set(value_info.get('examples', []))
                )
            else:
                # Extend existing key with custom variations
                kv = self.key_value_dictionary[key]
                if 'examples' in value_info:
                    kv.variations.update(value_info['examples'])
