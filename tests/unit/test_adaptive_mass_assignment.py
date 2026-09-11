"""Tests de la boucle Mass Assignment adaptative (offline + LLM simulé)."""
import pytest
from modules.llm.adaptive_mass_assignment import AdaptiveMassAssignmentLoop


def make_server(accept):
    def server(payload):
        f = list(payload)[0]
        if f in accept:
            return {'status': 200, 'body': f'{f} updated ok'}
        return {'status': 400, 'body': 'invalid field'}
    return server


TARGET = {'url': 'https://api.demo.com/v1/users/42', 'method': 'PATCH'}


class _Resp:
    def __init__(self, c): self.content = c


class TestOffline:
    def test_accepts_seed_field(self):
        f = AdaptiveMassAssignmentLoop(make_server({'role'})).run(TARGET)
        assert f.vulnerable and 'role' in [e['field'] for e in f.accepted_fields]

    def test_none_accepted(self):
        f = AdaptiveMassAssignmentLoop(make_server(set())).run(TARGET)
        assert not f.vulnerable

    def test_refine_adjacency_discovers_more(self):
        # role accepté => refine tente is_superuser (adjacence offline), aussi accepté.
        f = AdaptiveMassAssignmentLoop(make_server({'role', 'is_superuser'})).run(TARGET)
        fields = [e['field'] for e in f.accepted_fields]
        assert 'role' in fields and 'is_superuser' in fields

    def test_error_in_2xx_body_is_rejected(self):
        def server(payload):
            return {'status': 200, 'body': 'validation error: field not allowed'}
        f = AdaptiveMassAssignmentLoop(server).run(TARGET)
        assert not f.vulnerable


class TestLLM:
    def test_llm_interpret_and_refine(self):
        def server(payload):
            f = list(payload)[0]
            return {'status': 200, 'body': 'ok'} if f in ('role', 'god_mode') else {'status': 400, 'body': 'no'}

        class Client:
            def complete(self, prompt, system=None):
                if 'ACCEPTED it' in prompt:
                    accepted = 'status=200' in prompt
                    return _Resp('{"accepted": %s, "confidence": 0.9, "reason": "llm"}'
                                 % ('true' if accepted else 'false'))
                return _Resp('[{"field": "god_mode", "value": true}]')
        f = AdaptiveMassAssignmentLoop(server, client=Client(), max_rounds=2).run(TARGET)
        fields = [e['field'] for e in f.accepted_fields]
        assert 'role' in fields and 'god_mode' in fields
        assert any(e['reason'] == 'llm' for e in f.accepted_fields)

    def test_llm_failure_falls_back_offline(self):
        class Client:
            def complete(self, prompt, system=None):
                raise RuntimeError("down")
        f = AdaptiveMassAssignmentLoop(make_server({'role'}), client=Client()).run(TARGET)
        assert f.vulnerable  # repli offline a fonctionné
