"""
GraphQL Scanner - Introspection, mutation fuzzing, batching attacks.
"""
import json
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from .utils import get_logger, create_http_session, RateLimiter

logger = get_logger("graphql.scanner")

INTROSPECTION_QUERY = '''
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      kind name description
      fields(includeDeprecated: true) {
        name description
        args { name description type { kind name ofType { kind name } } }
        type { kind name ofType { kind name ofType { kind name } } }
      }
    }
  }
}
'''

GRAPHQL_PATTERNS = [
    r'/graphql',
    r'/api/graphql',
    r'/v\d+/graphql',
    r'/query',
    r'/gql',
]


@dataclass
class GraphQLEndpoint:
    url: str
    method: str = 'POST'
    has_introspection: bool = False
    schema: Optional[Dict] = None
    queries: List[str] = field(default_factory=list)
    mutations: List[str] = field(default_factory=list)


@dataclass
class GraphQLVulnerability:
    type: str
    endpoint: str
    severity: str
    description: str
    # `evidence` accepte str ou dict : certains findings (ex. introspection
    # activée) ont besoin de transporter une liste de types exposés, pas
    # juste une chaîne d'évidence. La sérialisation (CSV, rapport HTML,
    # bundle zip) gère les deux formes.
    evidence: Any = None
    remediation: Optional[str] = None


class GraphQLScanner:
    """Scanner for GraphQL endpoint security testing."""

    def __init__(self, har_data: Dict, config: Optional[Dict] = None, zap_client=None):
        self.har_data = har_data
        self.config = config or {}
        self.session = create_http_session()
        self.zap_client = zap_client
        self.endpoints: List[GraphQLEndpoint] = []
        self.vulnerabilities: List[GraphQLVulnerability] = []

        self.rate_limiter = RateLimiter(
            requests_per_second=self.config.get('rate_limit', 10.0),
            burst=self.config.get('rate_burst', 20)
        )

        self.introspection_timeout = self.config.get('introspection_timeout', 30)
        self.max_depth = self.config.get('max_depth', 10)
        self.batch_limit = self.config.get('batch_limit', 100)

    def _request(self, method: str, url: str, **kwargs) -> Any:
        """Route request through ZAP if available"""
        if self.zap_client:
            return self.zap_client.request(method, url, **kwargs)
        return getattr(self.session, method.lower())(url, **kwargs)

    def detect_endpoints(self) -> List[GraphQLEndpoint]:
        """Detect GraphQL endpoints from HAR data."""
        logger.info("detecting_graphql_endpoints")
        detected = set()

        for entry in self.har_data.get('entries', []):
            request = entry.get('request', {})
            url = request.get('url', '')
            method = request.get('method', 'GET')

            # Check URL pattern
            for pattern in GRAPHQL_PATTERNS:
                if re.search(pattern, url, re.IGNORECASE):
                    detected.add((url.split('?')[0], method))
                    break

            # Check for GraphQL in request body
            post_data = request.get('postData', {})
            text = post_data.get('text', '')
            if text and any(kw in text for kw in ['query', 'mutation', '__schema']):
                detected.add((url.split('?')[0], method))

            # Check content-type
            headers = {h['name'].lower(): h['value'] for h in request.get('headers', [])}
            if 'application/graphql' in headers.get('content-type', ''):
                detected.add((url.split('?')[0], method))

        self.endpoints = [GraphQLEndpoint(url=url, method=method) for url, method in detected]
        logger.info("graphql_endpoints_detected", count=len(self.endpoints))
        return self.endpoints

    def run_introspection(self, endpoint: GraphQLEndpoint) -> Optional[Dict]:
        """Run introspection query against endpoint."""
        logger.debug("running_introspection", url=endpoint.url[:50])

        self.rate_limiter.acquire()

        try:
            response = self._request(
                'POST',
                endpoint.url,
                json={'query': INTROSPECTION_QUERY},
                timeout=self.introspection_timeout,
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code == 200:
                data = response.json()
                if 'data' in data and '__schema' in data.get('data', {}):
                    endpoint.has_introspection = True
                    endpoint.schema = data['data']['__schema']
                    self._extract_operations(endpoint)

                    # On récupère les types exposés par l'introspection et on
                    # flag les noms sensibles (User, Admin*, Internal*, Payment,
                    # Session, Token, Credential...). Un pentesteur qui voit
                    # « introspection=true » a besoin de savoir *quels* types
                    # sont exposés pour prioriser — c'est ça qui rend la
                    # finding actionnable, pas juste le booléen.
                    types = data['data']['__schema'].get('types', []) or []
                    all_type_names = sorted({
                        t.get('name') for t in types
                        if t.get('name') and not t.get('name', '').startswith('__')
                    })
                    sensitive_pat = (
                        'user', 'admin', 'internal', 'payment', 'session',
                        'token', 'credential', 'secret', 'password', 'billing',
                    )
                    sensitive_types = [
                        n for n in all_type_names
                        if any(p in n.lower() for p in sensitive_pat)
                    ]

                    self.vulnerabilities.append(GraphQLVulnerability(
                        type='INTROSPECTION_ENABLED',
                        endpoint=endpoint.url,
                        severity='High' if sensitive_types else 'Medium',
                        description=(
                            f"GraphQL introspection is enabled — "
                            f"{len(all_type_names)} types exposed, "
                            f"{len(sensitive_types)} sensitive "
                            f"(e.g. {', '.join(sensitive_types[:5])})"
                            if sensitive_types
                            else f"GraphQL introspection is enabled — {len(all_type_names)} types exposed"
                        ),
                        remediation='Disable introspection in production',
                        evidence={
                            'exposed_types': all_type_names[:100],
                            'sensitive_types': sensitive_types,
                            'total_types': len(all_type_names),
                        },
                    ))

                    logger.info("introspection_success", url=endpoint.url[:50],
                                 total_types=len(all_type_names),
                                 sensitive=len(sensitive_types))
                    return endpoint.schema

        except Exception as e:
            logger.debug("introspection_failed", url=endpoint.url[:50], error=str(e))

        return None

    def _extract_operations(self, endpoint: GraphQLEndpoint):
        """Extract queries and mutations from schema."""
        if not endpoint.schema:
            return

        types = endpoint.schema.get('types', [])
        query_type = endpoint.schema.get('queryType', {}).get('name')
        mutation_type = endpoint.schema.get('mutationType', {}).get('name')

        for t in types:
            if t.get('name') == query_type:
                endpoint.queries = [f['name'] for f in t.get('fields', []) if f.get('name')]
            elif t.get('name') == mutation_type:
                endpoint.mutations = [f['name'] for f in t.get('fields', []) if f.get('name')]

    def test_batch_attacks(self, endpoint: GraphQLEndpoint) -> List[Dict]:
        """Test for batching/aliasing DoS vulnerabilities."""
        logger.info("testing_batch_attacks", url=endpoint.url[:50])
        results = []

        # Alias-based batching
        alias_query = self._generate_alias_query(self.batch_limit)
        self.rate_limiter.acquire()

        try:
            response = self._request(
                'POST',
                endpoint.url,
                json={'query': alias_query},
                timeout=60,
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code == 200:
                results.append({
                    'type': 'ALIAS_BATCHING',
                    'limit_tested': self.batch_limit,
                    'status': response.status_code,
                    'response_size': len(response.content)
                })

                if len(response.content) > 10000:
                    self.vulnerabilities.append(GraphQLVulnerability(
                        type='BATCH_ATTACK_POSSIBLE',
                        endpoint=endpoint.url,
                        severity='Medium',
                        description=f'Endpoint accepts {self.batch_limit} aliased queries',
                        remediation='Implement query complexity limits'
                    ))

        except Exception as e:
            logger.debug("batch_test_failed", error=str(e))

        # Array-based batching
        array_query = [{'query': '{ __typename }'} for _ in range(self.batch_limit)]
        self.rate_limiter.acquire()

        try:
            response = self._request(
                'POST',
                endpoint.url,
                json=array_query,
                timeout=60,
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code == 200:
                results.append({
                    'type': 'ARRAY_BATCHING',
                    'limit_tested': self.batch_limit,
                    'status': response.status_code,
                    'response_size': len(response.content)
                })

        except Exception:
            pass

        return results

    def test_depth_limit(self, endpoint: GraphQLEndpoint) -> Optional[Dict]:
        """Test for query depth limit."""
        logger.debug("testing_depth_limit", url=endpoint.url[:50])

        deep_query = self._generate_deep_query(self.max_depth)
        self.rate_limiter.acquire()

        try:
            response = self._request(
                'POST',
                endpoint.url,
                json={'query': deep_query},
                timeout=30,
                headers={'Content-Type': 'application/json'}
            )

            result = {
                'depth_tested': self.max_depth,
                'status': response.status_code,
                'blocked': response.status_code != 200
            }

            if response.status_code == 200:
                self.vulnerabilities.append(GraphQLVulnerability(
                    type='NO_DEPTH_LIMIT',
                    endpoint=endpoint.url,
                    severity='Medium',
                    description=f'No query depth limit (tested {self.max_depth} levels)',
                    remediation='Implement query depth limiting'
                ))

            return result

        except Exception:
            return None

    def fuzz_arguments(self, endpoint: GraphQLEndpoint, payloads: List[str]) -> List[Dict]:
        """Fuzz GraphQL arguments with injection payloads."""
        results = []

        if not endpoint.schema:
            return results

        # Get fields with arguments
        types = endpoint.schema.get('types', [])
        fields_with_args = []

        for t in types:
            for field in t.get('fields', []):
                if field.get('args'):
                    fields_with_args.append({
                        'type': t['name'],
                        'field': field['name'],
                        'args': field['args']
                    })

        logger.info("fuzzing_arguments", fields=len(fields_with_args), payloads=len(payloads))

        for field_info in fields_with_args[:10]:  # Limit
            for arg in field_info['args']:
                for payload in payloads[:20]:  # Limit payloads
                    result = self._test_argument_injection(
                        endpoint, field_info, arg, payload
                    )
                    if result:
                        results.append(result)

        return results

    def _test_argument_injection(
        self,
        endpoint: GraphQLEndpoint,
        field_info: Dict,
        arg: Dict,
        payload: str
    ) -> Optional[Dict]:
        """Test single argument with payload."""
        query = f'{{ {field_info["field"]}({arg["name"]}: "{payload}") {{ __typename }} }}'

        self.rate_limiter.acquire()

        try:
            response = self._request(
                'POST',
                endpoint.url,
                json={'query': query},
                timeout=10,
                headers={'Content-Type': 'application/json'}
            )

            # Check for error disclosure
            if response.status_code == 200:
                data = response.json()
                errors = data.get('errors', [])

                for error in errors:
                    msg = str(error.get('message', '')).lower()
                    if any(x in msg for x in ['sql', 'syntax', 'mysql', 'postgres', 'oracle']):
                        return {
                            'field': field_info['field'],
                            'arg': arg['name'],
                            'payload': payload,
                            'error': error.get('message'),
                            'type': 'SQL_ERROR_DISCLOSURE'
                        }

        except Exception:
            pass

        return None

    def _generate_alias_query(self, count: int) -> str:
        """Generate aliased query for batching test."""
        aliases = [f'a{i}: __typename' for i in range(count)]
        return '{ ' + ' '.join(aliases) + ' }'

    def _generate_deep_query(self, depth: int) -> str:
        """Generate deeply nested query."""
        query = '{ __schema { types { '
        for _ in range(depth):
            query += 'ofType { kind name '
        query += ' }' * depth
        query += ' } } }'
        return query

    def scan_all(self) -> Dict[str, Any]:
        """Run full GraphQL security scan."""
        logger.info("graphql_scan_start")

        if not self.endpoints:
            self.detect_endpoints()

        results = {
            'endpoints': [],
            'vulnerabilities': [],
            'summary': {}
        }

        for endpoint in self.endpoints:
            endpoint_result = {
                'url': endpoint.url,
                'introspection': None,
                'batch_tests': [],
                'depth_test': None
            }

            # Introspection
            schema = self.run_introspection(endpoint)
            if schema:
                endpoint_result['introspection'] = {
                    'enabled': True,
                    'queries': len(endpoint.queries),
                    'mutations': len(endpoint.mutations)
                }

            # Batch attacks
            endpoint_result['batch_tests'] = self.test_batch_attacks(endpoint)

            # Depth limit
            endpoint_result['depth_test'] = self.test_depth_limit(endpoint)

            results['endpoints'].append(endpoint_result)

        results['vulnerabilities'] = [
            {
                'type': v.type,
                'endpoint': v.endpoint,
                'severity': v.severity,
                'description': v.description,
                'remediation': v.remediation
            }
            for v in self.vulnerabilities
        ]

        results['summary'] = {
            'total_endpoints': len(self.endpoints),
            'introspection_enabled': sum(1 for e in self.endpoints if e.has_introspection),
            'vulnerabilities_found': len(self.vulnerabilities)
        }

        logger.info("graphql_scan_complete", **results['summary'])
        return results
