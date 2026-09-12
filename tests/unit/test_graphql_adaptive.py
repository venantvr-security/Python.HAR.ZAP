"""Tests de la couche GraphQL adaptative."""
from modules.graphql_adaptive import detect_introspection, generate_attack_queries


class _Resp:
    def __init__(self, c): self.content = c


def test_introspection_enabled():
    def srv(url, method, body):
        return {'status': 200, 'body': '{"data":{"__schema":{"queryType":{"name":"Query"}}}}'}
    f = detect_introspection(srv, 'https://x/graphql')
    assert f and 'introspection' in f.title.lower()

def test_introspection_disabled():
    assert detect_introspection(lambda u, m, b: {'status': 400, 'body': 'nope'}, 'https://x/graphql') is None

def test_offline_templates():
    qs = generate_attack_queries('', client=None)
    assert qs and any('__schema' in q or '__typename' in q for q in qs)

def test_llm_queries():
    client = type('C', (), {'complete': lambda self, p, system=None: _Resp('["query{secret}"]')})()
    qs = generate_attack_queries('{types}', client=client)
    assert qs == ['query{secret}']
