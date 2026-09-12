"""Tests de la matrice d'accès multi-rôles."""
import pytest
from modules.access_matrix import (
    Role, Endpoint, build_endpoints, run_matrix, render_matrix_cli)


def _har(entries):
    return {"log": {"entries": [{"request": {"method": m, "url": u}} for m, u in entries]}}


ROLE_HARS = [
    ('anon', _har([])),
    ('user', _har([("GET", "https://api.x/v1/users/42")])),
    ('admin', _har([("GET", "https://api.x/v1/users/42"), ("GET", "https://api.x/v1/admin/config")])),
]
ROLES = [Role('anon', {}, 0), Role('user', {'Authorization': 'U'}, 1),
         Role('admin', {'Authorization': 'A'}, 2)]


class TestBuildEndpoints:
    def test_min_priv_is_lowest_legitimate_user(self):
        eps = {e.template: e for e in build_endpoints(ROLE_HARS)}
        assert eps['GET /v1/users/{id}'].min_priv == 1      # user
        assert eps['GET /v1/admin/config'].min_priv == 2    # admin only
        assert eps['GET /v1/users/{id}'].url.endswith('/users/42')

    def test_templates_collapse_ids(self):
        eps = build_endpoints([('user', _har([
            ("GET", "https://api.x/v1/users/1"), ("GET", "https://api.x/v1/users/2")]))])
        assert len(eps) == 1  # même gabarit


class TestRunMatrix:
    def _server_bfla(self):
        # BFLA : 'user' (U) atteint /admin/config, réservé à admin.
        def server(url, method, headers):
            tok = headers.get('Authorization', '')
            if '/admin/config' in url:
                return {'status': 200} if tok else {'status': 403}  # bug: user OK aussi
            if '/users/42' in url:
                return {'status': 200} if tok else {'status': 401}
            return {'status': 404}
        return server

    def test_flags_only_real_bfla(self):
        m = run_matrix(ROLES, build_endpoints(ROLE_HARS), self._server_bfla())
        assert len(m.violations) == 1
        v = m.violations[0]
        assert v.role == 'user' and v.requires_role == 'admin' and '/admin/config' in v.endpoint

    def test_legit_use_not_flagged(self):
        # user accédant à son propre /users/{id} ne doit PAS être une violation
        m = run_matrix(ROLES, build_endpoints(ROLE_HARS), self._server_bfla())
        assert not any(v.role == 'user' and 'users/{id}' in v.endpoint for v in m.violations)

    def test_proper_enforcement_no_violation(self):
        def strict(url, method, headers):
            tok = headers.get('Authorization', '')
            if '/admin/config' in url:
                return {'status': 200} if tok == 'A' else {'status': 403}
            if '/users/42' in url:
                return {'status': 200} if tok else {'status': 401}
            return {'status': 404}
        m = run_matrix(ROLES, build_endpoints(ROLE_HARS), strict)
        assert len(m.violations) == 0

    def test_anon_access_is_critical(self):
        # anon atteint un endpoint réservé -> violation Critical
        def leaky(url, method, headers):
            return {'status': 200}  # tout ouvert
        m = run_matrix(ROLES, build_endpoints(ROLE_HARS), leaky)
        anon_v = [v for v in m.violations if v.role == 'anon']
        assert anon_v and all(v.severity == 'Critical' for v in anon_v)

    def test_grid_and_findings(self):
        m = run_matrix(ROLES, build_endpoints(ROLE_HARS), self._server_bfla())
        assert 'GET /v1/admin/config' in m.grid
        vf = m.violation_findings()
        assert vf and vf[0]['source'] == 'access_matrix' and vf[0]['risk'] == 'High'  # user->admin

    def test_render_cli(self):
        out = render_matrix_cli(run_matrix(ROLES, build_endpoints(ROLE_HARS), self._server_bfla()))
        assert 'ACCESS MATRIX' in out and 'Violations: 1' in out


class TestParallelism:
    def test_parallel_equals_sequential(self):
        # Serveur BFLA connu ; résultat identique en parallèle et séquentiel.
        def srv(url, method, headers):
            tok = headers.get('Authorization', '')
            if '/admin/config' in url:
                return {'status': 200} if tok else {'status': 403}   # bug: user aussi
            if '/users/42' in url:
                return {'status': 200} if tok else {'status': 401}
            return {'status': 404}
        eps = build_endpoints(ROLE_HARS)
        seq = run_matrix(ROLES, eps, srv, max_workers=1)
        par = run_matrix(ROLES, eps, srv, max_workers=8)
        assert par.grid == seq.grid
        assert [v.detail for v in par.violations] == [v.detail for v in seq.violations]

    def test_all_requests_executed_in_parallel(self):
        import threading
        seen = set()
        lock = threading.Lock()
        def srv(url, method, headers):
            with lock:
                seen.add((url, headers.get('Authorization', '')))
            return {'status': 403}
        eps = build_endpoints(ROLE_HARS)
        run_matrix(ROLES, eps, srv, max_workers=8)
        assert len(seen) == len(eps) * len(ROLES)   # chaque cellule rôle×endpoint tirée
