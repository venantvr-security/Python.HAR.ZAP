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


class TestSecondOrderVerification:
    """Un serveur qui répond 2xx en IGNORANT les champs inconnus (cas très
    courant) piège l'heuristique. verify_fn tranche par l'effet réel."""

    def _ignoring_server(self, payload):
        # Accepte tout en apparence (200, pas d'erreur), quel que soit le champ.
        return {'status': 200, 'body': 'registered'}

    def test_without_verify_flags_everything(self):
        # Sans vérification : chaque champ testé est jugé accepté (faux positifs).
        f = AdaptiveMassAssignmentLoop(self._ignoring_server).run(TARGET)
        assert f.vulnerable
        assert len(f.accepted_fields) > 1  # bruit : plusieurs champs "acceptés"
        assert f.suspected_fields == []

    def test_with_verify_confirms_only_real(self):
        # verify_fn ne confirme que 'admin' : lui seul est retenu, le reste suspecté.
        f = AdaptiveMassAssignmentLoop(
            self._ignoring_server,
            verify_fn=lambda field, value: field == 'admin').run(TARGET)
        accepted = [e['field'] for e in f.accepted_fields]
        suspected = [e['field'] for e in f.suspected_fields]
        assert accepted == ['admin']
        assert 'admin' not in suspected and len(suspected) >= 1


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
