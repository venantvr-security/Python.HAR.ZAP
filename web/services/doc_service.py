"""
Documentation Service

Parses and serves markdown documentation for the onboarding wizard.
"""
import os
import re
from pathlib import Path
from typing import Dict, List, Optional


class DocService:
    """Parse and serve documentation for onboarding wizard"""

    WIZARD_STEPS = [
        {
            'id': 'welcome',
            'title': 'Bienvenue',
            'file': 'GETTING_STARTED.md',
            'section': None,
            'description': 'Introduction au DAST Security Platform'
        },
        {
            'id': 'install',
            'title': 'Installation',
            'file': 'guides/INSTALLATION.md',
            'section': None,
            'description': 'Installation des dépendances et configuration initiale'
        },
        {
            'id': 'config',
            'title': 'Configuration',
            'file': 'guides/CONFIGURATION.md',
            'section': None,
            'description': 'Configuration du scan et des politiques'
        },
        {
            'id': 'docker',
            'title': 'Docker ZAP',
            'file': 'guides/INSTALLATION.md',
            'section': 'Docker',
            'description': 'Lancement de ZAP via Docker',
            'has_action': True,
            'action': 'docker_setup'
        },
        {
            'id': 'tor',
            'title': 'Configuration TOR',
            'file': 'guides/TOR_SETUP.md',
            'section': None,
            'description': 'Routage anonyme via TOR (optionnel)',
            'has_action': True,
            'action': 'tor_setup',
            'optional': True
        },
        {
            'id': 'har',
            'title': 'Capture HAR',
            'file': 'GETTING_STARTED.md',
            'section': 'Capturing',
            'description': 'Comment capturer le trafic HTTP'
        },
        {
            'id': 'scan',
            'title': 'Premier Scan',
            'file': 'api/CLI.md',
            'section': 'scan',
            'description': 'Lancer votre premier scan de sécurité'
        },
        {
            'id': 'cicd',
            'title': 'Intégration CI/CD',
            'file': 'examples/CICD.md',
            'section': None,
            'description': 'Intégration dans votre pipeline',
            'optional': True
        }
    ]

    def __init__(self, docs_path: str = None):
        if docs_path:
            self.docs_path = Path(docs_path)
        else:
            # Default to project docs directory
            self.docs_path = Path(__file__).parent.parent.parent / 'docs'

    def get_doc(self, path: str) -> Optional[str]:
        """Load markdown file content"""
        full_path = self.docs_path / path
        if not full_path.exists():
            return None
        try:
            return full_path.read_text(encoding='utf-8')
        except Exception:
            return None

    def get_section(self, content: str, section: str) -> Optional[str]:
        """Extract a specific section from markdown content"""
        if not content or not section:
            return content

        # Find section header (## or ###)
        pattern = rf'^(#{2,3})\s+.*{re.escape(section)}.*$'
        lines = content.split('\n')

        start_idx = None
        header_level = None

        for i, line in enumerate(lines):
            match = re.match(pattern, line, re.IGNORECASE)
            if match:
                start_idx = i
                header_level = len(match.group(1))
                break

        if start_idx is None:
            return None

        # Find end of section (next header of same or higher level)
        end_idx = len(lines)
        for i in range(start_idx + 1, len(lines)):
            line = lines[i]
            header_match = re.match(r'^(#{1,' + str(header_level) + r'})\s+', line)
            if header_match:
                end_idx = i
                break

        return '\n'.join(lines[start_idx:end_idx])

    def list_docs(self) -> List[Dict]:
        """List all available documentation files"""
        docs = []

        for path in self.docs_path.rglob('*.md'):
            rel_path = path.relative_to(self.docs_path)
            content = path.read_text(encoding='utf-8')

            # Extract title from first H1
            title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
            title = title_match.group(1) if title_match else rel_path.stem

            # Get category from directory
            category = rel_path.parent.name if rel_path.parent.name != '.' else 'root'

            docs.append({
                'path': str(rel_path),
                'title': title,
                'category': category,
                'size': len(content)
            })

        return sorted(docs, key=lambda x: (x['category'], x['title']))

    def get_wizard_steps(self) -> List[Dict]:
        """Get wizard steps with parsed content"""
        steps = []

        for step in self.WIZARD_STEPS:
            content = self.get_doc(step['file'])

            if content and step.get('section'):
                content = self.get_section(content, step['section'])

            steps.append({
                **step,
                'content': content or f"Documentation non trouvée: {step['file']}",
                'available': content is not None
            })

        return steps

    def get_wizard_step(self, step_id: str) -> Optional[Dict]:
        """Get a specific wizard step by ID"""
        for step in self.get_wizard_steps():
            if step['id'] == step_id:
                return step
        return None

    def search_docs(self, query: str) -> List[Dict]:
        """Search documentation content"""
        results = []
        query_lower = query.lower()

        for doc in self.list_docs():
            content = self.get_doc(doc['path'])
            if content and query_lower in content.lower():
                # Find matching lines for context
                lines = content.split('\n')
                matches = []
                for i, line in enumerate(lines):
                    if query_lower in line.lower():
                        # Get surrounding context
                        start = max(0, i - 1)
                        end = min(len(lines), i + 2)
                        context = '\n'.join(lines[start:end])
                        matches.append({
                            'line': i + 1,
                            'context': context[:200]
                        })

                results.append({
                    **doc,
                    'matches': matches[:5]  # Limit matches
                })

        return results

    def get_toc(self, path: str) -> List[Dict]:
        """Extract table of contents from a markdown file"""
        content = self.get_doc(path)
        if not content:
            return []

        toc = []
        for match in re.finditer(r'^(#{1,4})\s+(.+)$', content, re.MULTILINE):
            level = len(match.group(1))
            title = match.group(2)
            # Create anchor from title
            anchor = re.sub(r'[^\w\s-]', '', title.lower())
            anchor = re.sub(r'\s+', '-', anchor)

            toc.append({
                'level': level,
                'title': title,
                'anchor': anchor
            })

        return toc
