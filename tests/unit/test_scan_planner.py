"""Tests for modules/scan_planner.py — the dry-run layer."""
from pathlib import Path

import pytest

from modules.scan_planner import (
    REQUESTS_PER_TARGET_DEFAULT,
    REQUESTS_PER_TARGET_FULL_ASSAULT,
    ScanPlan,
    _format_duration,
    _policy_for,
    format_plan,
    plan_scan,
)


def _har(fuzzable=None, apis=None):
    return {
        'fuzzable_urls': fuzzable or [],
        'api_endpoints': apis or [],
    }


class TestPolicy:
    def test_sql_when_id_param(self):
        assert _policy_for({'params': ['id']}) == 'SQL-Injection'

    def test_sql_when_sql_in_param(self):
        assert _policy_for({'params': ['sql_query']}) == 'SQL-Injection'

    def test_path_traversal_when_file_param(self):
        assert _policy_for({'params': ['file_path']}) == 'Path-Traversal'

    def test_default_when_nothing_matches(self):
        assert _policy_for({'params': ['email', 'name']}) == 'Default Policy'


class TestPlanScan:
    def test_empty_har_returns_empty_plan(self):
        plan = plan_scan(_har())
        assert plan.targets == []
        assert plan.estimated_requests == 0
        assert any("no-op" in w.lower() for w in plan.warnings)

    def test_fuzzable_targets_collected(self):
        har = _har(fuzzable=[
            {'url': 'https://x/a', 'method': 'POST', 'params': ['id']},
            {'url': 'https://x/b', 'method': 'GET', 'params': ['file']},
        ])
        plan = plan_scan(har)
        assert len(plan.targets) == 2
        assert plan.targets[0]['policy'] == 'SQL-Injection'
        assert plan.targets[1]['policy'] == 'Path-Traversal'

    def test_api_targets_use_api_minimal_policy(self):
        har = _har(apis=[{'url': 'https://x/api/users', 'method': 'GET', 'params': []}])
        plan = plan_scan(har)
        assert plan.targets[0]['policy'] == 'API-Minimal'
        assert plan.targets[0]['type'] == 'api'

    def test_respects_max_fuzzable(self):
        har = _har(fuzzable=[{'url': f'https://x/{i}', 'params': []} for i in range(50)])
        plan = plan_scan(har, config={'max_fuzzable_urls': 5})
        assert len(plan.targets) == 5

    def test_estimated_requests_default(self):
        har = _har(fuzzable=[{'url': 'https://x/a', 'params': []}] * 3)
        plan = plan_scan(har)
        assert plan.estimated_requests == REQUESTS_PER_TARGET_DEFAULT * 3

    def test_full_assault_triples_requests(self):
        har = _har(fuzzable=[{'url': 'https://x/a', 'params': []}])
        plan_default = plan_scan(har)
        plan_full = plan_scan(har, config={'full_assault': True})
        assert plan_full.estimated_requests > plan_default.estimated_requests
        assert plan_full.estimated_requests == REQUESTS_PER_TARGET_FULL_ASSAULT
        assert any("FULL" in w for w in plan_full.warnings)

    def test_rate_limit_drives_duration(self):
        har = _har(fuzzable=[{'url': 'https://x/a', 'params': []}] * 2)
        fast = plan_scan(har, config={'rate_limit': 100.0})
        slow = plan_scan(har, config={'rate_limit': 1.0})
        assert slow.estimated_duration_s > fast.estimated_duration_s
        assert any("slow" in w.lower() or "Rate limit very low" in w for w in slow.warnings)

    def test_missing_scope_domains_warning(self):
        plan = plan_scan(_har(fuzzable=[{'url': 'https://x/a', 'params': []}]))
        assert any("scope_domains" in w.lower() for w in plan.warnings)

    def test_scope_domains_no_warning(self):
        plan = plan_scan(
            _har(fuzzable=[{'url': 'https://x/a', 'params': []}]),
            config={'scope_domains': ['x.com']},
        )
        assert not any("scope_domains" in w.lower() for w in plan.warnings)

    def test_scripts_to_load_from_real_dir(self, tmp_path):
        (tmp_path / 'active').mkdir()
        (tmp_path / 'passive').mkdir()
        (tmp_path / 'active' / 'one.js').write_text('// x')
        (tmp_path / 'passive' / 'two.js').write_text('// x')
        plan = plan_scan(_har(fuzzable=[{'url': 'https://x/a', 'params': []}]),
                         scripts_dir=tmp_path)
        assert 'active/one.js' in plan.scripts_to_load
        assert 'passive/two.js' in plan.scripts_to_load

    def test_scripts_empty_when_dir_missing(self, tmp_path):
        plan = plan_scan(_har(fuzzable=[{'url': 'https://x/a', 'params': []}]),
                         scripts_dir=tmp_path / 'missing')
        assert plan.scripts_to_load == []

    def test_python_attacks_respect_config(self):
        config = {'attack_strategies': [
            {'id': 'mass_assignment', 'enabled': True},
            {'id': 'idor', 'enabled': False},
            {'id': 'race_condition', 'enabled': True},
        ]}
        plan = plan_scan(_har(), config=config)
        assert 'mass_assignment' in plan.python_attacks
        assert 'race_condition' in plan.python_attacks
        assert 'idor' not in plan.python_attacks

    def test_to_dict_has_summary(self):
        plan = plan_scan(_har(fuzzable=[{'url': 'https://x/a', 'params': []}]))
        d = plan.to_dict()
        assert d['summary']['target_count'] == 1
        assert 'estimated_duration_pretty' in d['summary']


class TestFormatPlan:
    def test_format_includes_key_sections(self):
        plan = plan_scan(
            _har(fuzzable=[{'url': 'https://x/a', 'params': ['id']}]),
            config={'scope_domains': ['x.com'], 'rate_limit': 10.0},
        )
        text = format_plan(plan)
        assert 'DRY-RUN' in text
        assert 'Targets:' in text
        assert 'Estimated' in text

    def test_format_shows_warnings(self):
        plan = plan_scan(_har())
        text = format_plan(plan)
        assert 'Warnings' in text
        assert 'no-op' in text.lower()

    def test_duration_formats(self):
        assert _format_duration(10) == "10s"
        assert _format_duration(90).startswith("1m")
        assert _format_duration(3700).startswith("1h")


class TestScanPlanDataclass:
    def test_defaults(self):
        plan = ScanPlan()
        assert plan.targets == []
        assert plan.estimated_requests == 0
        assert plan.rate_limit == 10.0
