"""Prompts des moteurs historiques externalisés + garde-fou anti-inline."""
import pathlib
import re

from modules.llm.prompts import get_prompt, PROMPTS
from modules.llm.prompts.historical import HISTORICAL_PROMPTS


class TestHistoricalCatalog:
    def test_all_registered(self):
        for name in HISTORICAL_PROMPTS:
            assert get_prompt(name) is not None and name in PROMPTS

    def test_idor_interpret_renders(self):
        s, u = get_prompt('idor_interpret').render(
            baseline_id='1', baseline_status=200, baseline_len=10, baseline_body="'a'",
            test_id='2', test_status=200, test_len=10, test_body="'b'")
        assert 'is_leak' in u and '$' not in u and s.startswith('You are')

    def test_owasp_classify_preserves_json(self):
        _, u = get_prompt('owasp_classify').render(categories='{}', finding='{}')
        assert '"category"' in u and '$' not in u

    def test_exploit_chain_offensive_persona(self):
        s, _ = get_prompt('exploit_chain').render(findings='[]')
        assert 'offensive' in s.lower()


class TestNoInlinePrompts:
    """Garde-fou : plus aucun gros littéral de prompt hors du package prompts/."""

    def test_engines_have_no_inline_prompts(self):
        root = pathlib.Path(__file__).resolve().parents[2] / 'modules'
        needles = [
            'Return JSON {', 'Return JSON as an array', 'Return a JSON',
            'You are adjudicating', 'You are confirming', 'You are mapping',
            'A hidden parameter was added', 'A mass-assignment field',
            'Map this security finding', 'Given these confirmed API',
        ]
        offenders = []
        for py in root.rglob('*.py'):
            if 'prompts' in py.parts:          # le catalogue a le droit
                continue
            text = py.read_text(encoding='utf-8', errors='ignore')
            for n in needles:
                if n in text:
                    offenders.append(f"{py.relative_to(root)} :: {n}")
        assert not offenders, "prompts inline restants:\n" + "\n".join(offenders)
