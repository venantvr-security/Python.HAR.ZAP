"""Tests du pont d'enrichissement des patterns payloads vers le PatternStore/ZAP."""
import os
import pytest
from modules.llm.pattern_enricher import PatternEnricher


class _IDOR:
    def __init__(self, url, leaks):
        self.target_url = url
        self.leaks = leaks
        self.vulnerable = bool(leaks)


class _MA:
    def __init__(self, url, fields):
        self.target_url = url
        self.accepted_fields = [{'field': f, 'value': v, 'reason': 'x'} for f, v in fields]


class TestPatternEnricher:
    def test_records_and_exports_to_zap(self, tmp_path):
        enr = PatternEnricher.for_run(domain='demo.com', base_path=str(tmp_path))
        assert enr.active
        assert enr.record_idor([_IDOR('https://x/users/42', ['43', '44'])]) == 1
        assert enr.record_mass_assignment([_MA('https://x/users/42', [('role', 'admin'), ('is_admin', True)])]) == 2
        exported = enr.flush()
        assert 'idor' in exported and 'mass_assignment' in exported

        idor_txt = tmp_path / 'zap_export' / 'fuzzers' / 'llm_idor.txt'
        ma_txt = tmp_path / 'zap_export' / 'fuzzers' / 'llm_mass_assignment.txt'
        assert idor_txt.exists() and ma_txt.exists()
        assert '43' in idor_txt.read_text() and '44' in idor_txt.read_text()
        ma_content = ma_txt.read_text()
        assert 'role=admin' in ma_content and 'is_admin=True' in ma_content

    def test_records_proven_payloads_to_zap(self, tmp_path):
        """Les charges prouvées (SSRF/traversal/SSTI/XSS/redirect) -> wordlists."""
        enr = PatternEnricher.for_run(domain='demo.com', base_path=str(tmp_path))
        assert enr.record_payloads('ssrf', ['http://169.254.169.254/', 'file:///etc/passwd']) == 2
        assert enr.record_payloads('xss', ['<svg/onload=alert(1)>']) == 1
        # dédoublonnage
        assert enr.record_payloads('path_traversal', ['../etc/passwd', '../etc/passwd']) == 1
        exported = enr.flush()
        assert {'ssrf', 'xss', 'path_traversal'} <= set(exported)
        ssrf_txt = tmp_path / 'zap_export' / 'fuzzers' / 'llm_ssrf.txt'
        assert 'file:///etc/passwd' in ssrf_txt.read_text()

    def test_record_payloads_inactive_noop(self):
        enr = PatternEnricher(store=None, session_id=None)
        assert enr.record_payloads('ssrf', ['http://x/']) == 0

    def test_no_leaks_records_nothing(self, tmp_path):
        enr = PatternEnricher.for_run(domain='demo.com', base_path=str(tmp_path))
        assert enr.record_idor([_IDOR('https://x/users/42', [])]) == 0

    def test_inactive_enricher_is_noop(self):
        enr = PatternEnricher(store=None, session_id=None)
        assert not enr.active
        assert enr.record_idor([_IDOR('u', ['1'])]) == 0
        assert enr.record_mass_assignment([_MA('u', [('role', 'admin')])]) == 0
        assert enr.flush() == {}
