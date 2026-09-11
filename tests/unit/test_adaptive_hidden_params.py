"""Tests de la boucle Hidden Params adaptative."""
import pytest
from modules.llm.adaptive_hidden_params import AdaptiveHiddenParamsLoop, HPObservation

TARGET = {'url': 'https://api.demo.com/v1/dashboard', 'method': 'GET'}


def base_and(active_params, marker=False, size=300):
    """Serveur : réponse de base 300o ; si un param actif est présent, change."""
    def server(url, method='GET'):
        for p in active_params:
            if f'{p}=' in url:
                if marker:
                    return {'status': 200, 'content_length': 2000,
                            'body': 'Traceback (most recent call last): boom'}
                return {'status': 200, 'content_length': 1000, 'body': 'x' * 1000}
        return {'status': 200, 'content_length': size, 'body': 'y' * size}
    return server


class _Resp:
    def __init__(self, c): self.content = c


class TestOffline:
    def test_debug_marker_detected(self):
        f = AdaptiveHiddenParamsLoop(base_and({'debug'}, marker=True)).run(TARGET)
        assert f.vulnerable and 'debug' in [p['name'] for p in f.active_params]

    def test_size_delta_detected(self):
        f = AdaptiveHiddenParamsLoop(base_and({'admin'})).run(TARGET)
        assert 'admin' in [p['name'] for p in f.active_params]

    def test_no_change_not_flagged(self):
        f = AdaptiveHiddenParamsLoop(base_and(set())).run(TARGET)
        assert not f.vulnerable

    def test_refine_adjacency(self):
        # debug actif => refine tente verbose/debug_level/trace (adjacence offline)
        f = AdaptiveHiddenParamsLoop(base_and({'debug', 'verbose'})).run(TARGET)
        names = [p['name'] for p in f.active_params]
        assert 'debug' in names and 'verbose' in names


class TestLLM:
    def test_llm_interpret(self):
        server = base_and({'debug'})
        class Client:
            def complete(self, prompt, system=None):
                if 'hidden parameter' in prompt:
                    active = 'len=1000' in prompt.split('WITH')[1] if 'WITH' in prompt else False
                    return _Resp('{"active": %s, "confidence": 0.9, "reason": "llm"}'
                                 % ('true' if active else 'false'))
                return _Resp('[]')
        f = AdaptiveHiddenParamsLoop(server, client=Client()).run(TARGET)
        assert any(p['reason'] == 'llm' for p in f.active_params)

    def test_llm_failure_falls_back(self):
        class Client:
            def complete(self, prompt, system=None):
                raise RuntimeError("down")
        f = AdaptiveHiddenParamsLoop(base_and({'debug'}, marker=True), client=Client()).run(TARGET)
        assert f.vulnerable
