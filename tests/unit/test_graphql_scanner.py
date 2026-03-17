"""Tests for GraphQL Scanner module"""
import pytest
from unittest.mock import Mock, patch


@pytest.fixture
def sample_har():
    return {
        'entries': [
            {
                'request': {
                    'url': 'https://api.example.com/graphql',
                    'method': 'POST',
                    'headers': [{'name': 'Content-Type', 'value': 'application/json'}],
                    'postData': {'text': '{"query": "{ users { id name } }"}'}
                }
            },
            {
                'request': {
                    'url': 'https://api.example.com/api/v1/graphql',
                    'method': 'POST',
                    'headers': [{'name': 'Content-Type', 'value': 'application/graphql'}]
                }
            },
            {
                'request': {
                    'url': 'https://api.example.com/rest/users',
                    'method': 'GET',
                    'headers': []
                }
            }
        ]
    }


@pytest.fixture
def config():
    return {
        'rate_limit': 10.0,
        'introspection_timeout': 10,
        'max_depth': 5,
        'batch_limit': 50
    }


class TestGraphQLEndpoint:
    def test_create_endpoint(self):
        from modules.graphql_scanner import GraphQLEndpoint

        endpoint = GraphQLEndpoint(url='https://api.com/graphql', method='POST')

        assert endpoint.url == 'https://api.com/graphql'
        assert endpoint.method == 'POST'
        assert endpoint.has_introspection is False
        assert endpoint.queries == []
        assert endpoint.mutations == []


class TestGraphQLVulnerability:
    def test_create_vulnerability(self):
        from modules.graphql_scanner import GraphQLVulnerability

        vuln = GraphQLVulnerability(
            type='INTROSPECTION_ENABLED',
            endpoint='https://api.com/graphql',
            severity='Medium',
            description='Introspection enabled',
            remediation='Disable in production'
        )

        assert vuln.type == 'INTROSPECTION_ENABLED'
        assert vuln.severity == 'Medium'


class TestGraphQLScanner:
    def test_init(self, sample_har, config):
        from modules.graphql_scanner import GraphQLScanner

        scanner = GraphQLScanner(sample_har, config)

        assert scanner.har_data == sample_har
        assert scanner.max_depth == 5
        assert scanner.batch_limit == 50

    def test_init_with_zap(self, sample_har, config):
        from modules.graphql_scanner import GraphQLScanner

        mock_zap = Mock()
        scanner = GraphQLScanner(sample_har, config, zap_client=mock_zap)

        assert scanner.zap_client == mock_zap

    def test_detect_endpoints_url_pattern(self, sample_har, config):
        from modules.graphql_scanner import GraphQLScanner

        scanner = GraphQLScanner(sample_har, config)
        endpoints = scanner.detect_endpoints()

        urls = [e.url for e in endpoints]
        assert any('graphql' in url for url in urls)
        assert len(endpoints) >= 1

    def test_detect_endpoints_content_type(self, config):
        from modules.graphql_scanner import GraphQLScanner

        har = {
            'entries': [{
                'request': {
                    'url': 'https://api.com/query',
                    'method': 'POST',
                    'headers': [{'name': 'Content-Type', 'value': 'application/graphql'}]
                }
            }]
        }

        scanner = GraphQLScanner(har, config)
        endpoints = scanner.detect_endpoints()

        assert len(endpoints) == 1

    def test_detect_endpoints_body_content(self, config):
        from modules.graphql_scanner import GraphQLScanner

        har = {
            'entries': [{
                'request': {
                    'url': 'https://api.com/api',
                    'method': 'POST',
                    'headers': [],
                    'postData': {'text': '{"query": "{ __schema { types { name } } }"}'}
                }
            }]
        }

        scanner = GraphQLScanner(har, config)
        endpoints = scanner.detect_endpoints()

        assert len(endpoints) == 1

    @patch('modules.graphql_scanner.create_http_session')
    def test_run_introspection_success(self, mock_session, sample_har, config):
        from modules.graphql_scanner import GraphQLScanner, GraphQLEndpoint

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'data': {
                '__schema': {
                    'queryType': {'name': 'Query'},
                    'mutationType': {'name': 'Mutation'},
                    'types': [
                        {'name': 'Query', 'fields': [{'name': 'users', 'args': []}]},
                        {'name': 'Mutation', 'fields': [{'name': 'createUser', 'args': []}]}
                    ]
                }
            }
        }
        mock_session.return_value.post.return_value = mock_response

        scanner = GraphQLScanner(sample_har, config)
        endpoint = GraphQLEndpoint(url='https://api.com/graphql')
        schema = scanner.run_introspection(endpoint)

        assert schema is not None
        assert endpoint.has_introspection is True
        assert 'users' in endpoint.queries
        assert 'createUser' in endpoint.mutations

    @patch('modules.graphql_scanner.create_http_session')
    def test_run_introspection_disabled(self, mock_session, sample_har, config):
        from modules.graphql_scanner import GraphQLScanner, GraphQLEndpoint

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'errors': [{'message': 'Introspection disabled'}]}
        mock_session.return_value.post.return_value = mock_response

        scanner = GraphQLScanner(sample_har, config)
        endpoint = GraphQLEndpoint(url='https://api.com/graphql')
        schema = scanner.run_introspection(endpoint)

        assert schema is None
        assert endpoint.has_introspection is False

    @patch('modules.graphql_scanner.create_http_session')
    def test_test_batch_attacks(self, mock_session, sample_har, config):
        from modules.graphql_scanner import GraphQLScanner, GraphQLEndpoint

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'x' * 15000
        mock_session.return_value.post.return_value = mock_response

        scanner = GraphQLScanner(sample_har, config)
        endpoint = GraphQLEndpoint(url='https://api.com/graphql')
        results = scanner.test_batch_attacks(endpoint)

        assert len(results) >= 1
        assert any(r['type'] == 'ALIAS_BATCHING' for r in results)

    @patch('modules.graphql_scanner.create_http_session')
    def test_test_depth_limit_vulnerable(self, mock_session, sample_har, config):
        from modules.graphql_scanner import GraphQLScanner, GraphQLEndpoint

        mock_response = Mock()
        mock_response.status_code = 200
        mock_session.return_value.post.return_value = mock_response

        scanner = GraphQLScanner(sample_har, config)
        endpoint = GraphQLEndpoint(url='https://api.com/graphql')
        result = scanner.test_depth_limit(endpoint)

        assert result is not None
        assert result['blocked'] is False

    @patch('modules.graphql_scanner.create_http_session')
    def test_test_depth_limit_blocked(self, mock_session, sample_har, config):
        from modules.graphql_scanner import GraphQLScanner, GraphQLEndpoint

        mock_response = Mock()
        mock_response.status_code = 400
        mock_session.return_value.post.return_value = mock_response

        scanner = GraphQLScanner(sample_har, config)
        endpoint = GraphQLEndpoint(url='https://api.com/graphql')
        result = scanner.test_depth_limit(endpoint)

        assert result is not None
        assert result['blocked'] is True

    def test_generate_alias_query(self, sample_har, config):
        from modules.graphql_scanner import GraphQLScanner

        scanner = GraphQLScanner(sample_har, config)
        query = scanner._generate_alias_query(5)

        assert 'a0: __typename' in query
        assert 'a4: __typename' in query

    def test_generate_deep_query(self, sample_har, config):
        from modules.graphql_scanner import GraphQLScanner

        scanner = GraphQLScanner(sample_har, config)
        query = scanner._generate_deep_query(3)

        assert '__schema' in query
        assert 'ofType' in query

    @patch('modules.graphql_scanner.create_http_session')
    def test_fuzz_arguments_no_schema(self, mock_session, sample_har, config):
        from modules.graphql_scanner import GraphQLScanner, GraphQLEndpoint

        scanner = GraphQLScanner(sample_har, config)
        endpoint = GraphQLEndpoint(url='https://api.com/graphql')
        results = scanner.fuzz_arguments(endpoint, ["' OR 1=1--", "<script>"])

        assert results == []

    @patch('modules.graphql_scanner.create_http_session')
    def test_fuzz_arguments_with_schema(self, mock_session, sample_har, config):
        from modules.graphql_scanner import GraphQLScanner, GraphQLEndpoint

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'data': None, 'errors': [{'message': 'syntax error'}]}
        mock_session.return_value.post.return_value = mock_response

        scanner = GraphQLScanner(sample_har, config)
        endpoint = GraphQLEndpoint(url='https://api.com/graphql')
        endpoint.schema = {
            'types': [{
                'name': 'Query',
                'fields': [{
                    'name': 'user',
                    'args': [{'name': 'id', 'type': {'kind': 'SCALAR', 'name': 'ID'}}]
                }]
            }]
        }

        results = scanner.fuzz_arguments(endpoint, ["' OR 1=1--"])

        # No SQL error disclosure, so empty results
        assert isinstance(results, list)

    @patch('modules.graphql_scanner.create_http_session')
    def test_scan_all(self, mock_session, sample_har, config):
        from modules.graphql_scanner import GraphQLScanner

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b'response'
        mock_response.json.return_value = {
            'data': {
                '__schema': {
                    'queryType': {'name': 'Query'},
                    'mutationType': None,
                    'types': []
                }
            }
        }
        mock_session.return_value.post.return_value = mock_response

        scanner = GraphQLScanner(sample_har, config)
        results = scanner.scan_all()

        assert 'endpoints' in results
        assert 'vulnerabilities' in results
        assert 'summary' in results

    def test_request_with_zap(self, sample_har, config):
        from modules.graphql_scanner import GraphQLScanner

        mock_zap = Mock()
        mock_response = Mock()
        mock_zap.request.return_value = mock_response

        scanner = GraphQLScanner(sample_har, config, zap_client=mock_zap)
        result = scanner._request('POST', 'https://api.com/graphql', json={})

        mock_zap.request.assert_called_once()

    @patch('modules.graphql_scanner.create_http_session')
    def test_request_without_zap(self, mock_session, sample_har, config):
        from modules.graphql_scanner import GraphQLScanner

        mock_response = Mock()
        mock_session.return_value.post.return_value = mock_response

        scanner = GraphQLScanner(sample_har, config)
        result = scanner._request('POST', 'https://api.com/graphql', json={})

        mock_session.return_value.post.assert_called()
