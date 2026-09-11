"""Tests de la boucle IDOR adaptative (offline déterministe + LLM simulé)."""
import re
import pytest

from modules.llm.adaptive_idor import (
    AdaptiveIDORLoop, IDORObservation, IDORVerdict, _extract_json,
)


def _id_from(url):
    m = re.search(r'/users/(-?[^/?&]+)', url)
    return m.group(1) if m else ''


def make_server(leak_ids, own='42'):
    def server(url, method='GET'):
        cid = _id_from(url)
        if cid == own:
            return {'status': 200, 'content_length': 500, 'body': 'OWN 42 profile'}
        if cid in leak_ids:
            return {'status': 200, 'content_length': 480, 'body': f'user {cid} private'}
        return {'status': 403, 'content_length': 20, 'body': 'forbidden'}
    return server


TARGET = {'url': 'https://api.demo.com/v1/users/42', 'method': 'GET', 'original_value': '42'}


class _Resp:
    def __init__(self, content): self.content = content


class TestOfflineLoop:
    def test_finds_neighbor_leak(self):
        loop = AdaptiveIDORLoop(make_server({'43'}))
        f = loop.run(TARGET)
        assert f.vulnerable and f.observation.candidate_id == '43'
        assert f.verdict.source == 'offline' and f.verdict.confidence >= 0.85

    def test_all_protected_not_vulnerable(self):
        f = AdaptiveIDORLoop(make_server(set())).run(TARGET)
        assert not f.vulnerable

    def test_uuid_is_skipped(self):
        uid = 'a3f1c2d4-1111-4222-8333-444455556666'
        t = {'url': f'https://api.demo.com/v1/users/{uid}', 'method': 'GET', 'original_value': uid}
        f = AdaptiveIDORLoop(make_server({uid})).run(t)
        assert not f.vulnerable and 'UUID' in f.verdict.reason

    def test_small_200_is_not_a_leak(self):
        def server(url, method='GET'):
            cid = _id_from(url)
            if cid == '42':
                return {'status': 200, 'content_length': 500, 'body': 'OWN'}
            return {'status': 200, 'content_length': 5, 'body': 'x'}  # sous le plancher
        f = AdaptiveIDORLoop(server).run(TARGET)
        assert not f.vulnerable

    def test_refine_densifies_beyond_initial(self):
        # confidence_stop inatteignable => jamais d'arrêt anticipé => refine tourne.
        # 43 est un candidat initial "chaud" (200) ; refine densifie autour (45, 46...).
        loop = AdaptiveIDORLoop(make_server({'43'}), max_rounds=3, per_round=6, confidence_stop=1.1)
        f = loop.run(TARGET)
        assert '48' in f.tried  # 48 = 43+5, produit par la densification refine
        assert f.rounds >= 2


class TestUrlBuilding:
    def test_path_segment_replacement(self):
        url = AdaptiveIDORLoop._build_url(TARGET, '99')
        assert url.endswith('/users/99')

    def test_query_param_replacement(self):
        t = {'url': 'https://x.io/api?user_id=42&x=1', 'method': 'GET',
             'param': 'user_id', 'original_value': '42'}
        url = AdaptiveIDORLoop._build_url(t, '77')
        assert 'user_id=77' in url and 'x=1' in url


class TestLLMPaths:
    def test_llm_interpret(self):
        class Client:
            def complete(self, prompt, system=None):
                if 'adjudicating' in prompt:
                    leak = 'status=200' in prompt.split('TEST')[1]
                    return _Resp('{"is_leak": %s, "confidence": 0.95, "reason": "llm"}'
                                 % ('true' if leak else 'false'))
                return _Resp('[]')
        f = AdaptiveIDORLoop(make_server({'43'}), client=Client()).run(TARGET)
        assert f.vulnerable and f.verdict.source == 'llm' and f.verdict.confidence == 0.95

    def test_llm_refine_proposes_ids(self):
        calls = {'refine': 0}
        class Client:
            def complete(self, prompt, system=None):
                if 'adjudicating' in prompt:
                    leak = 'status=200' in prompt.split('TEST')[1]
                    # basse confiance => pas d'arrêt anticipé => refine sera consulté
                    return _Resp('{"is_leak": %s, "confidence": 0.6, "reason": "llm"}'
                                 % ('true' if leak else 'false'))
                calls['refine'] += 1
                return _Resp('["500","501"]')
        loop = AdaptiveIDORLoop(make_server({'500'}), client=Client(),
                                max_rounds=2, per_round=4, confidence_stop=0.99)
        f = loop.run(TARGET)
        assert calls['refine'] >= 1
        assert '500' in f.tried or '501' in f.tried

    def test_llm_failure_falls_back_offline(self):
        class Client:
            def complete(self, prompt, system=None):
                raise RuntimeError("network down")
        f = AdaptiveIDORLoop(make_server({'43'}), client=Client()).run(TARGET)
        assert f.vulnerable and f.verdict.source == 'offline'


class TestExtractJson:
    def test_array(self):
        assert _extract_json('["1","2"]') == ['1', '2']

    def test_fenced_object(self):
        assert _extract_json('```json\n{"is_leak": true}\n```') == {'is_leak': True}

    def test_none(self):
        assert _extract_json('nope') is None
