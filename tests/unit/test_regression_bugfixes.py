"""
Tests de régression pour l'audit de bugs du 2026-07-21.

Principe directeur : chaque test prouve qu'une DÉTECTION fonctionne réellement
(un cas vulnérable → un finding), et non pas seulement que le retour a le bon
type. C'est précisément le trou de couverture qui avait laissé passer plusieurs
détections mortes (accès dict lu comme objet, mauvais chemin HAR, return dans une
boucle). Voir la note d'audit : les tests d'origine n'assèraient que
`isinstance(results, list)`, ce qui passe même sur une liste vide.
"""
from unittest.mock import Mock, patch

import pytest


# ---------------------------------------------------------------------------
# HAUTE — cors_tester : la réflexion d'origine doit être détectée
# ---------------------------------------------------------------------------
def test_cors_origin_reflection_is_detected():
    """Un serveur qui reflète l'origine + credentials=true DOIT ressortir en
    Critical. Avant le fix, `_get_cors_response` lisait le dict-réponse comme un
    objet → AttributeError avalée → None → aucun finding."""
    from modules.cors_tester import CORSTester

    def reflecting_get(url, headers=None):
        origin = (headers or {}).get('Origin', '')
        return {
            'status_code': 200,
            'headers': {
                'access-control-allow-origin': origin,   # origine reflétée
                'access-control-allow-credentials': 'true',
            },
            'text': ''
        }

    tester = CORSTester({'log': {'entries': []}}, {})
    with patch.object(tester, '_get', side_effect=reflecting_get):
        results = tester.test_origin_reflection('https://api.example.com/data')

    assert any(r.vulnerable and r.severity == 'Critical' for r in results), \
        "la réflexion d'origine avec credentials doit être détectée en Critical"


# ---------------------------------------------------------------------------
# HAUTE — graphql / websocket : détection sur un HAR réel (log.entries)
# ---------------------------------------------------------------------------
def test_graphql_detects_endpoint_from_real_har():
    """Un vrai HAR expose log.entries. Avant le fix, la lecture de
    har_data['entries'] renvoyait toujours [] → 0 endpoint."""
    from modules.graphql_scanner import GraphQLScanner

    har = {'log': {'entries': [
        {'request': {'url': 'https://api.example.com/graphql', 'method': 'POST',
                     'postData': {'text': '{"query":"{ me { id } }"}'}, 'headers': []}}
    ]}}
    endpoints = GraphQLScanner(har, {}).detect_endpoints()
    assert len(endpoints) >= 1


def test_graphql_tolerates_unwrapped_entries():
    """Rétro-compat : un dict déjà déballé {'entries': [...]} reste accepté."""
    from modules.graphql_scanner import GraphQLScanner

    har = {'entries': [
        {'request': {'url': 'https://api.example.com/graphql', 'method': 'POST',
                     'postData': {'text': 'query { me }'}, 'headers': []}}
    ]}
    assert len(GraphQLScanner(har, {}).detect_endpoints()) >= 1


def test_websocket_detects_endpoint_from_real_har():
    from modules.websocket_scanner import WebSocketScanner

    har = {'log': {'entries': [
        {'request': {'url': 'https://api.example.com/ws', 'method': 'GET',
                     'headers': [{'name': 'Upgrade', 'value': 'websocket'}]},
         'response': {'status': 101}}
    ]}}
    assert len(WebSocketScanner(har, {}).detect_endpoints()) >= 1


# ---------------------------------------------------------------------------
# HAUTE — jwt : l'attaque KID injection doit pouvoir conclure
# ---------------------------------------------------------------------------
def test_jwt_kid_injection_can_flag_vulnerable():
    """Avant le fix, `response.status_code` sur un dict levait une AttributeError
    avalée → l'attaque KID renvoyait toujours None."""
    from modules.jwt_attacks import JWTAttackTester

    tester = JWTAttackTester({'log': {'entries': []}}, {'jwt_timeout': 5})
    jwt_data = {'token': 'a.b.c', 'url': 'https://api.example.com/user',
                'header_name': 'Authorization'}

    ok_response = {'status_code': 200, 'content': b'x' * 250, 'text': 'x' * 250}
    with patch.object(tester, 'decode_jwt',
                      return_value=({'alg': 'HS256', 'kid': 'orig'}, {'sub': '1'}, 'sig')), \
         patch.object(tester, '_make_request_with_token', return_value=ok_response):
        result = tester.test_kid_injection(jwt_data)

    assert result is not None and result.vulnerable


# ---------------------------------------------------------------------------
# HAUTE — zap_fuzzer : TOUS les paramètres d'ID doivent être fuzzés
# ---------------------------------------------------------------------------
@patch('modules.zap_fuzzer.time.sleep')
def test_fuzzer_tests_every_id_param(_sleep):
    """Avant le fix, le `return` était dans la boucle → seul le 1er paramètre
    était testé. Un endpoint à 2 params d'ID doit produire 2 résultats."""
    from modules.zap_fuzzer import ZAPFuzzer

    zap = Mock()
    zap.fuzzer.add_fuzzer.return_value = 'fuzzer-1'
    zap.fuzzer.status.return_value = {'state': 'FINISHED', 'progress': 100}
    zap.fuzzer.messages.return_value = []

    fuzzer = ZAPFuzzer(zap, {'ids': ['1', '2', '99']},
                       {'max_workers': 2, 'max_payloads': 10,
                        'fuzzer_timeout': 5, 'rate_limit': 1000.0})
    results = fuzzer.fuzz_idor_endpoints([
        {'url': 'https://api.com/order', 'params': ['user_id', 'doc_id']}
    ])

    assert {r['param'] for r in results} == {'user_id', 'doc_id'}


# ---------------------------------------------------------------------------
# HAUTE — har_preprocessor : process() idempotent (pas d'accumulation)
# ---------------------------------------------------------------------------
def test_har_preprocessor_process_is_idempotent():
    """Avant le fix, chaque appel à process() ré-appendait → données doublées."""
    from modules.har_preprocessor import HARPreprocessor

    har = {'log': {'entries': [
        {'request': {'method': 'POST', 'url': 'https://api.example.com/users/1',
                     'headers': [{'name': 'Content-Type', 'value': 'application/json'}],
                     'queryString': [], 'cookies': [],
                     'postData': {'mimeType': 'application/json', 'text': '{"a": 1}'}},
         'response': {'status': 200, 'content': {'mimeType': 'application/json',
                                                 'text': '{"id": 1}', 'size': 9}}}
    ]}}
    p = HARPreprocessor(har_data=har)
    n1 = len(p.process().endpoints)
    n2 = len(p.process().endpoints)
    assert n1 == n2, "process() ne doit pas accumuler les endpoints entre deux appels"


# ---------------------------------------------------------------------------
# MOYENNE — acceptance_engine : la garde de risque couvre bien la clause XSS
# ---------------------------------------------------------------------------
def test_no_xss_ignores_low_risk():
    from modules.acceptance_engine import AcceptanceEngine

    low = AcceptanceEngine._check_no_xss(
        {}, {'zap_alerts': [{'alert': 'Reflected XSS', 'risk': 'Low'}]})
    assert low['passed'] is True, "une XSS en risque Low ne doit pas faire échouer no_xss"

    high = AcceptanceEngine._check_no_xss(
        {}, {'zap_alerts': [{'alert': 'Reflected XSS', 'risk': 'High'}]})
    assert high['passed'] is False


# ---------------------------------------------------------------------------
# MOYENNE — owasp_mapper : cweid en chaîne (format ZAP réel) doit mapper
# ---------------------------------------------------------------------------
def test_owasp_maps_string_cweid():
    from modules.owasp_mapper import OWASPMapper

    mapper = OWASPMapper()
    # pluginId inconnu + nom sans mot-clé → seul le CWE peut mapper.
    cat = mapper._map_single_alert({'pluginId': '0', 'alert': 'qqqq', 'cweid': '89'})
    assert cat is not None, "un cweid en chaîne (ex. '89') doit être mappé comme l'entier"


# ---------------------------------------------------------------------------
# MOYENNE — token_extractor : match d'ID précis (plus de sous-chaîne 'id')
# ---------------------------------------------------------------------------
def test_token_extractor_id_param_is_precise():
    from modules.token_extractor import TokenExtractor

    te = TokenExtractor({'log': {'entries': []}})
    te._categorize_value('width', 'zzzq')      # 'width' contient 'id' mais n'est pas un ID
    te._categorize_value('user_id', 'zzzr')    # vrai paramètre d'ID
    assert 'zzzq' not in te.tokens['ids']
    assert 'zzzr' in te.tokens['ids']


# ---------------------------------------------------------------------------
# MOYENNE — payload_analyzer : bool étiqueté _BOOL (pas _INT)
# ---------------------------------------------------------------------------
def test_payload_template_bool_before_int():
    from modules.payload_analyzer import PayloadAnalyzer

    pa = PayloadAnalyzer({'log': {'entries': []}})
    tpl = pa._create_template({'active': True, 'count': 5})
    assert tpl['active'] == '{{ACTIVE_BOOL}}'
    assert tpl['count'] == '{{COUNT_INT}}'
