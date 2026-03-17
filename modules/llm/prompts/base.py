"""
Base prompt template class.
"""
from dataclasses import dataclass
from string import Template
from typing import Tuple


@dataclass
class PromptTemplate:
    """Reusable prompt template."""
    name: str
    system: str
    user: str
    description: str = ""

    def render(self, **kwargs) -> Tuple[str, str]:
        """
        Render template with variables.

        Returns:
            Tuple of (system_prompt, user_prompt)
        """
        return (
            Template(self.system).safe_substitute(**kwargs),
            Template(self.user).safe_substitute(**kwargs)
        )

    def render_user(self, **kwargs) -> str:
        """Render only user prompt."""
        return Template(self.user).safe_substitute(**kwargs)

    def render_system(self, **kwargs) -> str:
        """Render only system prompt."""
        return Template(self.system).safe_substitute(**kwargs)
