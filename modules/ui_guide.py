"""
Onglet Guide — intègre la documentation du repo dans Streamlit.

Pourquoi ce module existe :
- Un nouveau pentesteur ouvre Streamlit et voit 10 onglets techniques sans
  savoir par où commencer. Plutôt que de dupliquer le contenu, on expose
  directement les fichiers .md du repo (QUICKSTART, HOWTO, PENTEST, etc.)
  rendus comme de la documentation in-app.
- Les MD sont la source de vérité (CLAUDE.md interdit de les traduire ou de
  les dupliquer). On les lit en direct depuis le disque ; si un fichier est
  modifié, le prochain refresh Streamlit en profite.

Les pages listées ici sont sélectionnées volontairement : les docs techniques
complètes restent dans `docs/` pour une lecture dédiée hors app.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import streamlit as st


@dataclass
class GuidePage:
    label: str
    path: Path
    description: str


_ROOT = Path(__file__).parent.parent


def _page(rel: str, label: str, description: str) -> GuidePage:
    return GuidePage(label=label, path=_ROOT / rel, description=description)


GUIDE_PAGES: List[GuidePage] = [
    _page("QUICKSTART.md", "🚀 Quickstart", "5-min first scan"),
    _page("PENTEST.md", "🎯 Pentest walkthrough", "End-to-end scenario"),
    _page("docs/HOWTO.md", "📖 HOWTO", "Step-by-step recipes"),
    _page("docs/INNOVATION.md", "💡 Innovation", "What makes HAR-ZAP different"),
    _page("docs/HUNTING_GUIDE.md", "🔍 Hunting guide", "Vulnerability hunting playbook"),
    _page("docs/ARCHITECTURE.md", "🏗️ Architecture", "System architecture"),
    _page("docs/guides/ADVANCED_ATTACKS.md", "🧪 Advanced attacks", "JWT/CORS/smuggling/cache guide"),
    _page("docs/redteam/MASS_ASSIGNMENT.md", "🔴 Mass Assignment", "Red-team attack deep dive"),
    _page("docs/redteam/UNAUTHENTICATED_REPLAY.md", "🔴 Unauth replay", "Red-team attack deep dive"),
    _page("docs/redteam/RACE_CONDITIONS.md", "🔴 Race conditions", "Red-team attack deep dive"),
    _page("docs/redteam/HIDDEN_PARAMETERS.md", "🔴 Hidden parameters", "Red-team attack deep dive"),
    _page("docs/ROADMAP_LLM_SECURITY.md", "🗺️ LLM roadmap", "LLM integration design notes"),
    _page("CLAUDE.md", "📜 Project charter", "Didactic mission + writing rules"),
]


def _read_md(path: Path) -> Optional[str]:
    if not path.exists() or not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return None


def render_guide_tab() -> None:
    """Affiche un sélecteur + le contenu markdown rendu, live depuis le disque."""
    st.header("📚 Guide")
    st.caption(
        "Documentation in-app. Les fichiers sont lus en direct depuis le "
        "repo — toute modification est reflétée au prochain rechargement."
    )

    available = [p for p in GUIDE_PAGES if p.path.exists()]
    if not available:
        st.warning("Aucun guide trouvé — vérifier que le repo est complet.")
        return

    choice = st.selectbox(
        "Choisir une page",
        options=range(len(available)),
        format_func=lambda i: f"{available[i].label} — {available[i].description}",
        key="guide_page_picker",
    )

    page = available[choice]
    st.caption(f"📄 `{page.path.relative_to(_ROOT)}`")

    content = _read_md(page.path)
    if content is None:
        st.error("Impossible de lire le fichier.")
        return

    # Les liens relatifs (ex. `docs/INNOVATION.md`) ne marcheront pas en
    # Streamlit car le navigateur cherche sur le même host. On laisse le
    # markdown tel quel — l'utilisateur peut ouvrir le fichier dans son
    # éditeur via le chemin affiché ci-dessus.
    st.markdown(content, unsafe_allow_html=False)
