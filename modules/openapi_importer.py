import yaml
import json
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin


class OpenAPIImporter:
    """Import and parse OpenAPI/Swagger specifications for ZAP scanning"""

    def __init__(self, zap_client=None):
        self.zap = zap_client
        self.spec = None
        self.endpoints = []

    def load_from_url(self, url: str) -> Dict:
        """Load OpenAPI spec from URL"""
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            content_type = response.headers.get('Content-Type', '')

            if 'json' in content_type:
                self.spec = response.json()
            elif 'yaml' in content_type or 'yml' in url:
                self.spec = yaml.safe_load(response.text)
            else:
                try:
                    self.spec = response.json()
                except:
                    self.spec = yaml.safe_load(response.text)

            return self.spec

        except Exception as e:
            raise Exception(f"Failed to load OpenAPI spec from URL: {e}")

    def load_from_file(self, file_path: str) -> Dict:
        """Load OpenAPI spec from file"""
        try:
            with open(file_path, 'r') as f:
                if file_path.endswith('.json'):
                    self.spec = json.load(f)
                else:
                    self.spec = yaml.safe_load(f)

            return self.spec

        except Exception as e:
            raise Exception(f"Failed to load OpenAPI spec from file: {e}")

    def parse_endpoints(self) -> List[Dict]:
        """Extract all endpoints from OpenAPI spec"""
        if not self.spec:
            raise Exception("No OpenAPI spec loaded")

        endpoints = []

        version = self._detect_version()
        base_url = self._extract_base_url(version)

        paths = self.spec.get('paths', {})

        for path, methods in paths.items():
            for method, details in methods.items():
                if method.upper() not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                    continue

                endpoint = {
                    'path': path,
                    'method': method.upper(),
                    'full_url': urljoin(base_url, path.lstrip('/')),
                    'summary': details.get('summary', ''),
                    'description': details.get('description', ''),
                    'parameters': self._extract_parameters(details),
                    'request_body': self._extract_request_body(details),
                    'responses': details.get('responses', {}),
                    'security': details.get('security', []),
                    'tags': details.get('tags', [])
                }

                endpoints.append(endpoint)

        self.endpoints = endpoints
        return endpoints

    def _detect_version(self) -> str:
        """Detect OpenAPI/Swagger version"""
        if 'openapi' in self.spec:
            return 'openapi3'
        elif 'swagger' in self.spec:
            return 'swagger2'
        else:
            return 'unknown'

    def _extract_base_url(self, version: str) -> str:
        """Extract base URL from spec"""
        if version == 'openapi3':
            servers = self.spec.get('servers', [])
            if servers:
                return servers[0].get('url', '')

        elif version == 'swagger2':
            schemes = self.spec.get('schemes', ['https'])
            host = self.spec.get('host', '')
            base_path = self.spec.get('basePath', '')

            if host:
                return f"{schemes[0]}://{host}{base_path}"

        return ''

    def _extract_parameters(self, operation: Dict) -> List[Dict]:
        """Extract parameters from operation"""
        params = []

        for param in operation.get('parameters', []):
            params.append({
                'name': param.get('name'),
                'in': param.get('in'),
                'required': param.get('required', False),
                'type': param.get('type') or param.get('schema', {}).get('type'),
                'description': param.get('description', '')
            })

        return params

    def _extract_request_body(self, operation: Dict) -> Optional[Dict]:
        """Extract request body schema"""
        request_body = operation.get('requestBody')

        if not request_body:
            return None

        content = request_body.get('content', {})

        for content_type, schema_info in content.items():
            return {
                'content_type': content_type,
                'schema': schema_info.get('schema', {}),
                'required': request_body.get('required', False)
            }

        return None

    def import_to_zap(self, target_url: str = None) -> bool:
        """Import OpenAPI spec directly into ZAP"""
        if not self.zap:
            raise Exception("ZAP client not configured")

        if not self.spec:
            raise Exception("No OpenAPI spec loaded")

        try:
            spec_content = json.dumps(self.spec)

            self.zap.openapi.import_url(
                url=target_url or self._extract_base_url(self._detect_version()),
                hostoverride=target_url
            )

            return True

        except AttributeError:
            print("[OpenAPI] ZAP openapi plugin not available, using manual import")
            return self._manual_import_to_zap(target_url)

        except Exception as e:
            print(f"[OpenAPI] Import failed: {e}")
            return False

    def _manual_import_to_zap(self, target_url: str = None) -> bool:
        """Manually import endpoints to ZAP site tree"""
        if not self.endpoints:
            self.parse_endpoints()

        base_url = target_url or self._extract_base_url(self._detect_version())

        for endpoint in self.endpoints:
            try:
                full_url = urljoin(base_url, endpoint['path'].lstrip('/'))

                self.zap.core.access_url(full_url)

            except Exception as e:
                print(f"[OpenAPI] Failed to access {full_url}: {e}")

        return True

    def generate_sample_requests(self) -> List[Dict]:
        """Generate sample HTTP requests from spec"""
        if not self.endpoints:
            self.parse_endpoints()

        requests_list = []

        for endpoint in self.endpoints:
            sample_request = {
                'method': endpoint['method'],
                'url': endpoint['full_url'],
                'headers': {},
                'params': {},
                'body': None
            }

            for param in endpoint['parameters']:
                sample_value = self._generate_sample_value(param)

                if param['in'] == 'query':
                    sample_request['params'][param['name']] = sample_value
                elif param['in'] == 'header':
                    sample_request['headers'][param['name']] = sample_value
                elif param['in'] == 'path':
                    sample_request['url'] = sample_request['url'].replace(
                        f"{{{param['name']}}}", str(sample_value)
                    )

            if endpoint['request_body']:
                sample_request['headers']['Content-Type'] = endpoint['request_body']['content_type']
                sample_request['body'] = self._generate_sample_body(
                    endpoint['request_body']['schema']
                )

            requests_list.append(sample_request)

        return requests_list

    def _generate_sample_value(self, param: Dict) -> str:
        """Generate sample value for parameter"""
        param_type = param.get('type', 'string')

        type_samples = {
            'string': 'test',
            'integer': 1,
            'number': 1.0,
            'boolean': True,
            'array': ['item1', 'item2']
        }

        return type_samples.get(param_type, 'test')

    def _generate_sample_body(self, schema: Dict) -> Dict:
        """Generate sample request body from schema"""
        if not schema:
            return {}

        schema_type = schema.get('type', 'object')

        if schema_type == 'object':
            sample = {}
            properties = schema.get('properties', {})

            for prop_name, prop_schema in properties.items():
                sample[prop_name] = self._generate_sample_value({
                    'type': prop_schema.get('type', 'string')
                })

            return sample

        elif schema_type == 'array':
            return [self._generate_sample_body(schema.get('items', {}))]

        else:
            return self._generate_sample_value({'type': schema_type})

    def get_authenticated_endpoints(self) -> List[Dict]:
        """Filter endpoints that require authentication"""
        if not self.endpoints:
            self.parse_endpoints()

        return [
            ep for ep in self.endpoints
            if ep['security'] or any('auth' in tag.lower() for tag in ep['tags'])
        ]

    def get_summary(self) -> Dict:
        """Get summary of parsed API"""
        if not self.endpoints:
            return {}

        methods_count = {}
        for ep in self.endpoints:
            method = ep['method']
            methods_count[method] = methods_count.get(method, 0) + 1

        return {
            'total_endpoints': len(self.endpoints),
            'methods': methods_count,
            'base_url': self._extract_base_url(self._detect_version()),
            'authenticated_endpoints': len(self.get_authenticated_endpoints()),
            'version': self._detect_version()
        }
