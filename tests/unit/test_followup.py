"""Phase 4 — follow-up dirigé : récolte de secrets sur les shadow confirmés +
recommandations d'actions déduites des findings."""
from modules.llm.followup import harvest_secrets, directed_followups, run_followups


class TestHarvestSecrets:
    def test_shadow_confirmed_yields_secret(self):
        findings = [{'name': 'Shadow/undocumented route reachable: GET /debug/config',
                     'url': 'http://x/debug/config', 'status': 'confirmed',
                     'owasp': 'API9:2023'}]

        def ex(url, method='GET', body=None):
            return {'status': 200,
                    'body': '{"secret_key":"cms_dev_secret_2024","env":"prod"}'}
        out = harvest_secrets(findings, ex)
        assert out and out[0]['risk'] == 'Critical'
        assert 'secret_key' in out[0]['name'] and out[0]['status'] == 'confirmed'

    def test_no_secret_no_finding(self):
        findings = [{'name': 'Shadow route: GET /health', 'url': 'http://x/health',
                     'status': 'confirmed', 'owasp': 'API9:2023'}]
        assert harvest_secrets(findings, lambda u, m='GET', b=None: {'status': 200, 'body': 'ok'}) == []

    def test_suspected_shadow_ignored(self):
        findings = [{'name': 'Shadow debug', 'url': 'http://x/debug', 'status': 'suspected'}]
        called = []
        harvest_secrets(findings, lambda u, m='GET', b=None: called.append(u) or {'body': ''})
        assert called == []                       # on ne relit QUE les confirmés

    def test_non_shadow_ignored(self):
        findings = [{'name': 'Reflected XSS', 'url': 'http://x/s', 'status': 'confirmed'}]
        called = []
        harvest_secrets(findings, lambda u, m='GET', b=None: called.append(u) or {'body': 'secret_key: x'})
        assert called == []


class TestDirectedFollowups:
    def test_ssrf_and_jwt_and_bola_recommendations(self):
        findings = [
            {'name': 'SSRF via body url', 'source': 'probe_api7'},
            {'name': 'JWT bypass via alg=none accepted', 'source': 'auth_confirmer'},
            {'name': 'BOLA — object accessible', 'source': 'bola_investigator'},
            {'name': 'SQL injection (error-based) via q', 'source': 'inj_sqli'},
        ]
        recs = directed_followups(findings)
        actions = ' '.join(r['action'] for r in recs).lower()
        assert 'interne' in actions and 'bfla' in actions and 'rejouer' in actions and 'union' in actions

    def test_dedup(self):
        f = [{'name': 'SSRF a', 'source': 'probe_api7'}, {'name': 'SSRF b', 'source': 'probe_api7'}]
        # deux triggers différents -> deux recos ; même action mais triggers distincts
        assert len(directed_followups(f)) == 2


class TestRunFollowups:
    def test_end_to_end(self):
        findings = [{'name': 'Shadow: GET /debug/config', 'url': 'http://x/debug/config',
                     'status': 'confirmed', 'owasp': 'API9:2023'},
                    {'name': 'SSRF via url', 'source': 'probe_api7'}]

        def ex(url, method='GET', body=None):
            return {'status': 200, 'body': '{"service_token":"svc-internal-9d41"}'}
        harvested, recs = run_followups(findings, ex)
        assert any('service_token' in h['name'] for h in harvested)
        assert any('interne' in r['action'].lower() for r in recs)
