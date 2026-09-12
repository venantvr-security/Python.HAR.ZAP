"""Tests de l'extrapolation de routes (déterministe + LLM simulé + sondage)."""
import json

from modules.semantic.api_model import APIModel
from modules.llm.route_extrapolator import (
    extrapolate_routes, probe_candidates, CandidateRoute)


def _e(method, url, status=200, resp="{}"):
    return {"request": {"method": method, "url": url, "headers": []},
            "response": {"status": status, "content": {"text": resp}}}


HAR = {"log": {"entries": [
    _e("GET", "https://api.x/users/v1"),
    _e("GET", "https://api.x/users/v1/42"),
    _e("GET", "https://api.x/books/v1"),
]}}


class TestOffline:
    def test_proposes_missing_verbs_and_sensitive(self):
        model = APIModel.from_har(HAR)
        cands = extrapolate_routes(model)
        pairs = {(c.method, c.path) for c in cands}
        # verbe destructeur manquant sur l'item observé
        assert ("DELETE", "/users/v1/{id}") in pairs
        # suffixe sensible probable sur une collection
        assert any(p.endswith("/_debug") for (_m, p) in pairs)

    def test_does_not_repeat_observed(self):
        model = APIModel.from_har(HAR)
        cands = extrapolate_routes(model)
        pairs = {(c.method, c.path) for c in cands}
        assert ("GET", "/users/v1") not in pairs      # déjà observé
        assert ("GET", "/users/v1/{id}") not in pairs


class TestLLM:
    def test_llm_candidates_used(self):
        class Client:
            class _R:
                def __init__(self, c): self.content = c

            def complete(self, prompt, system=None):
                return self._R(json.dumps([
                    {"method": "GET", "path": "/admin/v1/users", "why": "admin area",
                     "risk": "high"}]))
        model = APIModel.from_har(HAR)
        cands = extrapolate_routes(model, client=Client())
        assert any(c.path == "/admin/v1/users" and c.source == "llm" for c in cands)

    def test_llm_failure_falls_back_offline(self):
        class Broken:
            def complete(self, prompt, system=None):
                raise RuntimeError("down")
        model = APIModel.from_har(HAR)
        cands = extrapolate_routes(model, client=Broken())
        assert cands and all(c.source == "offline" for c in cands)


class TestProbe:
    def test_confirms_existing_skips_missing_and_unsafe(self):
        # Serveur : /users/v1/_debug existe (200), le reste 404.
        def send(method, url, headers=None):
            return {"status": 200} if url.endswith("/_debug") else {"status": 404}
        cands = [
            CandidateRoute("GET", "/users/v1/_debug"),
            CandidateRoute("GET", "/users/v1/ghost"),
            CandidateRoute("DELETE", "/users/v1/{id}"),   # non sûr -> jamais sondé
        ]
        confirmed = probe_candidates(send, "https://api.x", cands)
        paths = {c.path for c in confirmed}
        assert paths == {"/users/v1/_debug"}
        # la route destructive n'a pas été sondée
        assert next(c for c in cands if c.method == "DELETE").exists is None

    def test_catch_all_id_route_not_a_false_positive(self):
        # Piège : /books/v1/<n'importe quoi> frappe la route /{id} et renvoie
        # toujours 401. Les suffixes devinés ne doivent PAS être confirmés (ils
        # se comportent comme le catch-all), mais un vrai endpoint 200 l'est.
        def send(method, url, headers=None):
            if url.endswith("/realsecret"):
                return {"status": 200}
            return {"status": 401}   # catch-all /{id} pour tout le reste
        cands = [
            CandidateRoute("GET", "/books/v1/_debug"),    # = catch-all 401 -> écarté
            CandidateRoute("GET", "/books/v1/admin"),     # = catch-all 401 -> écarté
            CandidateRoute("GET", "/books/v1/realsecret"),  # 200 distinct -> retenu
        ]
        confirmed = probe_candidates(send, "https://api.x", cands)
        assert {c.path for c in confirmed} == {"/books/v1/realsecret"}
