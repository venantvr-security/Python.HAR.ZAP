"""Tests du record/replay des interactions LLM."""
import json
import pytest
from modules.llm.replay import (
    ReplayCache, ReplayableClient, ReplayResponse, interaction_key, wrap_for_replay)


class _Inner:
    """Faux LLMClient : renvoie une réponse déterministe et compte les appels."""
    class _C: model = 'test-model'
    config = _C()
    available = True
    def __init__(self): self.calls = 0
    def complete(self, prompt, system=''):
        self.calls += 1
        return ReplayResponse(f"ANSWER::{prompt}")


class TestKey:
    def test_stable_and_model_independent(self):
        assert interaction_key('s', 'p') == interaction_key('s', 'p')
        assert interaction_key('s', 'p') != interaction_key('s', 'q')


class TestCache:
    def test_put_get_persist(self, tmp_path):
        p = tmp_path / 't.json'
        c = ReplayCache(str(p))
        c.put('k', 'v')
        assert c.get('k') == 'v'
        assert ReplayCache(str(p)).get('k') == 'v'   # rechargé depuis le disque
        assert 'interactions' in json.loads(p.read_text())


class TestRecord:
    def test_records_and_calls_inner(self, tmp_path):
        inner = _Inner()
        rc = ReplayableClient(inner, ReplayCache(str(tmp_path / 't.json')), 'record')
        assert rc.available is True
        resp = rc.complete('hello', system='sys')
        assert resp.content == 'ANSWER::hello' and inner.calls == 1
        assert rc.cache.get(interaction_key('sys', 'hello')) == 'ANSWER::hello'


class TestReplay:
    def test_serves_without_inner(self, tmp_path):
        cache = ReplayCache(str(tmp_path / 't.json'))
        cache.put(interaction_key('sys', 'hello'), 'SAVED')
        rc = ReplayableClient(None, cache, 'replay')
        assert rc.available is True                     # pas de clé requise
        assert rc.complete('hello', system='sys').content == 'SAVED'

    def test_miss_returns_none(self, tmp_path):
        rc = ReplayableClient(None, ReplayCache(str(tmp_path / 't.json')), 'replay')
        assert rc.complete('unknown') is None           # -> repli offline


class TestRoundTrip:
    def test_record_then_replay(self, tmp_path, monkeypatch):
        path = str(tmp_path / 'transcript.json')
        # 1) record
        monkeypatch.setenv('HARZAP_LLM_REPLAY_MODE', 'record')
        monkeypatch.setenv('HARZAP_LLM_REPLAY_FILE', path)
        inner = _Inner()
        rec = wrap_for_replay(inner, {})
        rec.complete('p1', system='s')
        # 2) replay depuis le même transcript, SANS client réel
        monkeypatch.setenv('HARZAP_LLM_REPLAY_MODE', 'replay')
        rep = wrap_for_replay(None, {})
        assert rep.available is True
        assert rep.complete('p1', system='s').content == 'ANSWER::p1'
        assert inner.calls == 1                          # aucun nouvel appel réel


class TestClientFromConfig:
    def test_replay_mode_no_key_available(self, tmp_path, monkeypatch):
        path = str(tmp_path / 't.json')
        ReplayCache(path).put(interaction_key('sys', 'hello'), 'SAVED')
        monkeypatch.delenv('HARZAP_LLM_API_KEY', raising=False)
        monkeypatch.delenv('HARZAP_GEMINI_API_KEY', raising=False)
        monkeypatch.setenv('HARZAP_LLM_REPLAY_MODE', 'replay')
        monkeypatch.setenv('HARZAP_LLM_REPLAY_FILE', path)
        from modules.llm.adaptive_idor import client_from_config
        client = client_from_config({})
        assert client is not None and client.available is True
        assert client.complete('hello', system='sys').content == 'SAVED'

    def test_no_replay_no_key_returns_none(self, monkeypatch):
        monkeypatch.delenv('HARZAP_LLM_API_KEY', raising=False)
        monkeypatch.delenv('HARZAP_GEMINI_API_KEY', raising=False)
        monkeypatch.delenv('HARZAP_LLM_REPLAY_MODE', raising=False)
        from modules.llm.adaptive_idor import client_from_config
        assert client_from_config({}) is None
