"""Attestation d'autorisation opérateur : conditionne l'IA + préambule système."""
import os

import pytest

from modules.llm.client import ai_authorized, LLMClient, LLMConfig, LLMResponse
from modules.llm.adaptive_idor import client_from_config
from modules.llm.prompts.system import AUTHORIZATION_PREAMBLE

CFG = {'llm': {'api_key': 'sk-test', 'provider': 'anthropic'}}


@pytest.fixture(autouse=True)
def _clean_env():
    for k in ('HARZAP_AI_AUTHORIZED', 'HARZAP_LLM_REPLAY_MODE', 'HARZAP_LLM_REPLAY_FILE'):
        os.environ.pop(k, None)
    yield
    for k in ('HARZAP_AI_AUTHORIZED', 'HARZAP_LLM_REPLAY_MODE', 'HARZAP_LLM_REPLAY_FILE'):
        os.environ.pop(k, None)


class TestAttestation:
    def test_env_and_config(self):
        assert not ai_authorized({})
        assert ai_authorized({'llm': {'authorized': True}})
        os.environ['HARZAP_AI_AUTHORIZED'] = '1'
        assert ai_authorized({})

    def test_no_key_returns_none(self):
        assert client_from_config({'llm': {}}) is None

    def test_key_but_no_attestation_disables_ai(self, capsys):
        assert client_from_config(CFG) is None
        assert 'Authorization not attested' in capsys.readouterr().out

    def test_attestation_enables_client(self):
        os.environ['HARZAP_AI_AUTHORIZED'] = '1'
        c = client_from_config(CFG)
        assert c is not None and c.config.authorized

    def test_replay_allowed_without_attestation(self, tmp_path):
        os.environ['HARZAP_LLM_REPLAY_MODE'] = 'replay'
        os.environ['HARZAP_LLM_REPLAY_FILE'] = str(tmp_path / 't.json')
        assert client_from_config({}) is not None   # sert un transcript, pas de réseau


class TestPreamble:
    def _client(self, authorized):
        c = LLMClient(LLMConfig(api_key='k', authorized=authorized))
        captured = {}

        def fake(prompt, system=None):
            captured['system'] = system
            return LLMResponse(content='{}', model='x', usage={}, latency_ms=0)
        c._complete_anthropic = fake
        return c, captured

    def test_preamble_prepended_when_authorized(self):
        c, cap = self._client(True)
        c.complete('u', system='Persona.')
        assert cap['system'].startswith(AUTHORIZATION_PREAMBLE) and 'Persona.' in cap['system']

    def test_no_preamble_when_not_authorized(self):
        c, cap = self._client(False)
        c.complete('u', system='Persona.')
        assert cap['system'] == 'Persona.'
