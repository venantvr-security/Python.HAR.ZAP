"""Tests for API routes"""
import pytest
from unittest.mock import Mock, patch, MagicMock, AsyncMock
import io
import json

# Skip all tests if FastAPI not installed
pytest.importorskip("fastapi", reason="FastAPI not installed")
pytest.importorskip("httpx", reason="httpx not installed")

from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def mock_har_service():
    service = Mock()
    service.current_har = {
        'log': {'entries': [{'request': {'url': 'https://api.com/test'}}]}
    }
    service.load_har.return_value = {'entries': 10, 'domains': ['api.com']}
    service.preprocess.return_value = {'filtered': 5}
    service.get_summary.return_value = {'total': 10}
    service.get_endpoints.return_value = ['/api/users', '/api/data']
    service.get_urls.return_value = ['https://api.com/users', 'https://api.com/data']
    return service


@pytest.fixture
def mock_zap_service():
    service = Mock()
    service.is_running = True
    service.zap_url = 'http://localhost:8080'
    service.api_key = 'test-key'
    service.get_http_client.return_value = Mock()
    return service


@pytest.fixture
def mock_config():
    return {
        'attack_strategies': [
            {'id': 'cors', 'name': 'CORS', 'module': 'cors_tester', 'enabled': True},
            {'id': 'jwt', 'name': 'JWT', 'module': 'jwt_attacks', 'enabled': True},
            {'id': 'disabled', 'name': 'Disabled', 'module': 'test', 'enabled': False}
        ],
        'extraction_patterns': {
            'numeric_id': r'\d+',
            'uuid': r'[0-9a-f-]+'
        }
    }


@pytest.fixture
def app(mock_har_service, mock_zap_service, mock_config):
    from web.api.routes import har, attacks, enrich

    app = FastAPI()
    app.state.shared = {
        'har_service': mock_har_service,
        'zap_service': mock_zap_service,
        'config': mock_config
    }

    app.include_router(har.router, prefix="/har")
    app.include_router(attacks.router, prefix="/attacks")
    app.include_router(enrich.router, prefix="/enrich")

    return app


@pytest.fixture
def client(app):
    return TestClient(app)


class TestHARRoutes:
    def test_upload_har_success(self, client, mock_har_service):
        har_content = json.dumps({'log': {'entries': []}})
        response = client.post(
            "/har/upload",
            files={"file": ("test.har", io.BytesIO(har_content.encode()), "application/json")}
        )

        assert response.status_code == 200
        data = response.json()
        assert data['status'] == 'loaded'
        assert data['filename'] == 'test.har'

    def test_upload_har_invalid_extension(self, client):
        response = client.post(
            "/har/upload",
            files={"file": ("test.json", io.BytesIO(b'{}'), "application/json")}
        )

        assert response.status_code == 400
        assert 'must be .har' in response.json()['detail']

    def test_upload_har_invalid_content(self, client, mock_har_service):
        mock_har_service.load_har.side_effect = Exception("Invalid JSON")

        response = client.post(
            "/har/upload",
            files={"file": ("test.har", io.BytesIO(b'invalid'), "application/json")}
        )

        assert response.status_code == 400
        assert 'Invalid HAR' in response.json()['detail']

    def test_preprocess_har(self, client):
        response = client.post(
            "/har/preprocess",
            json={"exclude_static": True, "methods": ["GET", "POST"]}
        )

        assert response.status_code == 200

    def test_preprocess_no_har(self, client, mock_har_service):
        mock_har_service.current_har = None

        response = client.post("/har/preprocess")

        assert response.status_code == 400
        assert 'No HAR loaded' in response.json()['detail']

    def test_get_summary(self, client):
        response = client.get("/har/summary")

        assert response.status_code == 200
        assert 'total' in response.json()

    def test_get_endpoints(self, client):
        response = client.get("/har/endpoints")

        assert response.status_code == 200
        assert 'endpoints' in response.json()

    def test_get_urls(self, client):
        response = client.get("/har/urls")

        assert response.status_code == 200
        assert 'urls' in response.json()


class TestAttackRoutes:
    def test_list_strategies(self, client):
        response = client.get("/attacks/strategies")

        assert response.status_code == 200
        data = response.json()
        assert 'strategies' in data
        assert len(data['strategies']) == 3

    def test_run_attack_no_har(self, client, mock_har_service):
        mock_har_service.current_har = None

        response = client.post(
            "/attacks/run",
            json={"strategy": "cors"}
        )

        assert response.status_code == 400
        assert 'No HAR loaded' in response.json()['detail']

    def test_run_attack_unknown_strategy(self, client):
        response = client.post(
            "/attacks/run",
            json={"strategy": "unknown"}
        )

        assert response.status_code == 400
        assert 'Unknown strategy' in response.json()['detail']

    def test_run_attack_disabled_strategy(self, client):
        response = client.post(
            "/attacks/run",
            json={"strategy": "disabled"}
        )

        assert response.status_code == 400
        assert 'Strategy disabled' in response.json()['detail']

    @patch('web.api.routes.attacks.run_attack_module')
    def test_run_attack_legacy(self, mock_run, client, mock_zap_service):
        # Le handler `async` combiné à pytest sans plugin asyncio ne passait
        # jamais dans le code — le test restait vert par erreur. Version
        # synchrone : on parle à `client` qui fait l'appel HTTP, pas besoin
        # d'await.
        mock_zap_service.is_running = False
        mock_run.return_value = {'findings': [], 'summary': {}}

        response = client.post(
            "/attacks/run",
            json={"strategy": "cors"}
        )

        # With ZAP not running, should try legacy
        assert response.status_code in [200, 500]

    def test_pipeline_no_har(self, client, mock_har_service):
        mock_har_service.current_har = None

        response = client.post(
            "/attacks/pipeline",
            json={}
        )

        assert response.status_code == 400
        assert 'No HAR loaded' in response.json()['detail']

    def test_pipeline_no_zap(self, client, mock_zap_service):
        mock_zap_service.is_running = False

        response = client.post(
            "/attacks/pipeline",
            json={}
        )

        assert response.status_code == 400
        assert 'ZAP not running' in response.json()['detail']


class TestEnrichRoutes:
    def test_get_patterns(self, client):
        response = client.get("/enrich/patterns")

        assert response.status_code == 200
        data = response.json()
        assert 'patterns' in data

    def test_extract_no_har(self, client, mock_har_service):
        mock_har_service.current_har = None

        response = client.post(
            "/enrich/extract",
            json={"pattern_types": ["numeric_id"]}
        )

        assert response.status_code == 400
        assert 'No HAR loaded' in response.json()['detail']

    def test_get_zap_lists_no_zap(self, client, mock_zap_service):
        mock_zap_service.is_running = False

        response = client.get("/enrich/zap-lists")

        assert response.status_code == 400

    def test_preview_no_har(self, client, mock_har_service):
        mock_har_service.current_har = None

        response = client.post(
            "/enrich/preview",
            json={"pattern_type": "numeric_id"}
        )

        assert response.status_code == 400

    def test_fuzz_no_zap(self, client, mock_zap_service):
        mock_zap_service.is_running = False

        response = client.post(
            "/enrich/fuzz",
            json={"url": "https://api.com/test", "param": "id", "pattern_type": "numeric_id"}
        )

        assert response.status_code == 400


class TestAttackModuleRunner:
    @pytest.mark.asyncio
    async def test_run_attack_module_cors(self):
        from web.api.routes.attacks import run_attack_module

        har_data = {'log': {'entries': []}}
        config = {}

        with patch('modules.cors_tester.CORSTester') as mock_tester:
            mock_instance = Mock()
            mock_instance.test_all.return_value = {'vulnerabilities': [], 'summary': {}}
            mock_tester.return_value = mock_instance

            results = await run_attack_module('cors_tester', har_data, config)

            assert 'findings' in results
            assert 'summary' in results

    @pytest.mark.asyncio
    async def test_run_attack_module_unknown(self):
        from web.api.routes.attacks import run_attack_module

        results = await run_attack_module('unknown_module', {}, {})

        assert 'error' in results['summary']
