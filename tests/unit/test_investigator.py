"""Tests de l'Investigator mass-assignment (offline + plan LLM simulé).

Serveur simulé : l'inscription renvoie toujours 200 mais ne STOCKE réellement
que certains champs (les autres sont ignorés silencieusement — le piège à faux
positifs). Un endpoint `_debug` expose l'état stocké et sert d'oracle.
"""
import json

from modules.llm.investigator import MassAssignmentInvestigator
from modules.llm.adaptive_mass_assignment import AdaptiveMassAssignmentLoop

TARGET = {"url": "https://api.demo/users/register", "method": "POST"}
BASE_BODY = {"username": "seed", "password": "x", "email": "seed@e.com"}
ORACLES = ["https://api.demo/users", "https://api.demo/users/_debug"]


class FakeServer:
    """`stored_from` : mapping champ_injecté -> attribut réellement stocké.
    Un champ absent de ce mapping est ignoré (accepté en apparence, sans effet)."""

    def __init__(self, stored_from):
        self.stored_from = stored_from
        self.users = []

    def send(self, method, url, headers=None, json_body=None):
        if method == "POST":
            rec = {"username": json_body.get("username")}
            for injected, attr in self.stored_from.items():
                if injected in json_body:
                    rec[attr] = json_body[injected]
            self.users.append(rec)
            return {"status": 200, "body": json.dumps({"message": "registered"})}
        if method == "GET" and url.endswith("/_debug"):
            return {"status": 200, "body": json.dumps({"users": self.users})}
        return {"status": 200, "body": json.dumps({"users": []})}


class FakeClient:
    def __init__(self, plan):
        self._plan = plan

    class _R:
        def __init__(self, c): self.content = c

    def complete(self, prompt, system=None):
        return self._R(json.dumps(self._plan))


class TestOfflinePlan:
    def test_picks_debug_oracle_and_discovers_record_path(self):
        srv = FakeServer({"admin": "admin"})
        inv = MassAssignmentInvestigator(srv.send, oracle_candidates=ORACLES)
        plan = inv.plan(TARGET, BASE_BODY)
        assert plan.oracle_url.endswith("/_debug")   # oracle « debug » préféré
        assert plan.identity_field == "username"
        assert plan.record_path == "users"           # découvert en sondant l'oracle
        assert plan.source == "offline"

    def test_confirms_only_stored_field(self):
        # Le serveur ne stocke que 'admin' ; les autres champs sont ignorés.
        srv = FakeServer({"admin": "admin"})
        inv = MassAssignmentInvestigator(srv.send, oracle_candidates=ORACLES)
        ex, vf, _ = inv.instrument(TARGET, BASE_BODY)
        f = AdaptiveMassAssignmentLoop(ex, verify_fn=vf).run(TARGET)
        assert [e["field"] for e in f.accepted_fields] == ["admin"]
        assert "admin" not in [e["field"] for e in f.suspected_fields]
        assert len(f.suspected_fields) >= 1           # les ignorés sont isolés

    def test_no_oracle_confirms_nothing(self):
        srv = FakeServer({"admin": "admin"})
        inv = MassAssignmentInvestigator(srv.send, oracle_candidates=[])
        ex, vf, _ = inv.instrument(TARGET, BASE_BODY)
        f = AdaptiveMassAssignmentLoop(ex, verify_fn=vf).run(TARGET)
        assert f.accepted_fields == []                # rien de confirmable sans oracle


class TestLLMPlan:
    def test_semantic_mapping_injected_to_stored(self):
        # Le serveur stocke l'injection 'is_admin' sous l'attribut 'admin'.
        # L'heuristique offline (effect_field=None) vérifierait record['is_admin']
        # -> absent -> non confirmé. L'IA mappe is_admin -> admin -> confirmé.
        srv = FakeServer({"is_admin": "admin"})
        plan = {"oracle_url": "https://api.demo/users/_debug", "identity_field": "username",
                "record_path": "users", "effect_field": "admin"}
        inv = MassAssignmentInvestigator(srv.send, client=FakeClient(plan),
                                         oracle_candidates=ORACLES)
        p = inv.plan(TARGET, BASE_BODY)
        assert p.source == "llm" and p.effect_field == "admin"
        ex, vf, _ = inv.instrument(TARGET, BASE_BODY, plan=p)
        f = AdaptiveMassAssignmentLoop(ex, verify_fn=vf).run(TARGET)
        assert "is_admin" in [e["field"] for e in f.accepted_fields]

    def test_offline_misses_semantic_mapping(self):
        # Preuve du contraste : sans l'IA, le mapping is_admin->admin est manqué.
        srv = FakeServer({"is_admin": "admin"})
        inv = MassAssignmentInvestigator(srv.send, oracle_candidates=ORACLES)
        ex, vf, _ = inv.instrument(TARGET, BASE_BODY)
        f = AdaptiveMassAssignmentLoop(ex, verify_fn=vf).run(TARGET)
        assert "is_admin" not in [e["field"] for e in f.accepted_fields]
