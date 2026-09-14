"""Les prompts d'investigation sont externalisés et enregistrés au catalogue."""
from modules.llm.prompts import get_prompt, PROMPTS
from modules.llm.prompts.investigations import INVESTIGATION_PROMPTS


class TestCatalog:
    def test_all_registered(self):
        for name in INVESTIGATION_PROMPTS:
            assert get_prompt(name) is not None
            assert name in PROMPTS

    def test_render_fills_placeholders(self):
        s, u = get_prompt('mix_adjudicate').render(
            kind='BOLA', url='/x', reason='why', evidence='ev')
        assert 'BOLA' in u and '/x' in u and '$' not in u  # tous les $var résolus
        assert s.startswith('You are')

    def test_extrapolate_preserves_json_braces(self):
        _, u = get_prompt('route_extrapolate').render(resources=['users'], observed='  GET /x')
        assert '{id}' in u and '"method"' in u   # les accolades JSON survivent

    def test_investigator_plan_shape(self):
        s, u = get_prompt('investigator_plan').render(
            method='POST', url='/r', body_keys=['a'], oracles='  - /o')
        assert 'oracle_url' in u and '/r' in u and '$' not in u
