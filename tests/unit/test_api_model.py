"""Tests du modèle sémantique APIModel (déterministe) + enrichissement IA simulé."""
import json

from modules.semantic.api_model import APIModel, route_is_sensitive


def _entry(method, url, req_headers=None, status=200, resp_text="{}", post_text=None):
    e = {"request": {"method": method, "url": url,
                     "headers": [{"name": k, "value": v} for k, v in (req_headers or {}).items()]},
         "response": {"status": status, "content": {"text": resp_text}}}
    if post_text is not None:
        e["request"]["postData"] = {"text": post_text}
    return e


def _har(entries):
    return {"log": {"entries": entries}}


AUTH = {"Authorization": "Bearer x"}

HAR = _har([
    # liste publique (aucune auth) -> seen_without_auth
    _entry("GET", "https://api.x/users/v1", status=200,
           resp_text=json.dumps({"users": [{"username": "a", "email": "a@x"}]})),
    # création (surface d'affectation de masse)
    _entry("POST", "https://api.x/users/v1/register", AUTH, 200,
           post_text=json.dumps({"username": "n", "password": "p", "email": "e@x"})),
    # endpoint sensible (debug) authentifié
    _entry("GET", "https://api.x/users/v1/_debug", AUTH, 200,
           resp_text=json.dumps({"users": [{"username": "a", "password": "p"}]})),
    # item authentifié
    _entry("GET", "https://api.x/books/v1/42", AUTH, 200,
           resp_text=json.dumps({"book_title": "t", "owner": "a"})),
])


class TestDeterministicModel:
    def test_route_is_sensitive_keywords(self):
        assert route_is_sensitive("/users/v1/_debug")
        assert route_is_sensitive("/admin/config")
        assert not route_is_sensitive("/users/v1")

    def test_resource_and_crud(self):
        m = APIModel.from_har(HAR)
        by = {t: r for t, r in m.routes.items()}
        assert by["GET /users/v1"].resource == "users"
        assert by["GET /users/v1"].crud == "list"
        assert by["POST /users/v1/register"].crud == "create"
        assert by["GET /books/v1/{id}"].crud == "read"
        assert by["GET /books/v1/{id}"].is_item

    def test_seen_without_auth_marks_public(self):
        m = APIModel.from_har(HAR)
        assert m.is_public("GET /users/v1")            # vue sans auth
        assert not m.is_public("GET /users/v1/_debug")  # toujours avec auth

    def test_sensitivity_by_path_and_response(self):
        m = APIModel.from_har(HAR)
        assert m.is_sensitive("GET /users/v1/_debug")   # mot-clé + password en réponse
        assert not m.is_sensitive("GET /users/v1")

    def test_readback_orders_sensitive_first(self):
        m = APIModel.from_har(HAR)
        write = m.routes["POST /users/v1/register"]
        reads = m.readback_for(write)
        # les GET de la ressource 'users', le sensible (_debug) en tête
        assert reads and reads[0].template == "GET /users/v1/_debug"
        assert any(r.template == "GET /users/v1" for r in reads)

    def test_identity_field_inferred(self):
        m = APIModel.from_har(HAR)
        assert m.identity_field_for("users") == "username"

    def test_oracle_candidate_urls(self):
        m = APIModel.from_har(HAR)
        urls = m.oracle_candidate_urls("users")
        assert any("_debug" in u for u in urls)


class FakeClient:
    class _R:
        def __init__(self, c): self.content = c

    def complete(self, prompt, system=None):
        return self._R(json.dumps({
            "GET /users/v1": {"entity": "Utilisateur", "sensitive": False},
            "GET /users/v1/_debug": {"entity": "Utilisateur", "sensitive": True}}))


class TestLLMEnrichment:
    def test_entity_naming_and_sensitivity(self):
        m = APIModel.from_har(HAR, client=FakeClient())
        assert m.routes["GET /users/v1"].entity == "Utilisateur"
        assert m.routes["GET /users/v1/_debug"].sensitive is True

    def test_enrichment_failure_is_safe(self):
        class Broken:
            def complete(self, prompt, system=None):
                raise RuntimeError("down")
        m = APIModel.from_har(HAR, client=Broken())  # ne doit pas lever
        assert m.routes["GET /users/v1"].resource == "users"  # déterministe intact
