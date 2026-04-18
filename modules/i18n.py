"""
Internationalisation helper for the Streamlit app.

English is the default language. French is optional and toggled via the
language selector in the sidebar. Markdown documentation is intentionally
NOT translated — this module covers the app UI only.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

DEFAULT_LANG = "en"
SUPPORTED_LANGS = ("en", "fr")

_LOCALE_DIR = Path(__file__).parent.parent / "locales"
_cache: dict[str, dict] = {}


def load_locale(lang: str) -> dict:
    """Load locale JSON for a given language (cached)."""
    if lang not in SUPPORTED_LANGS:
        lang = DEFAULT_LANG
    if lang not in _cache:
        path = _LOCALE_DIR / f"{lang}.json"
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                _cache[lang] = json.load(f)
        else:
            _cache[lang] = {}
    return _cache[lang]


def get_lang() -> str:
    """Return the currently selected language from Streamlit session_state."""
    try:
        import streamlit as st  # imported lazily so this module stays CLI-friendly
        return st.session_state.get("lang", DEFAULT_LANG)
    except Exception:
        return DEFAULT_LANG


def set_lang(lang: str) -> None:
    """Set the current language in session_state. Falls back to default if unknown."""
    if lang not in SUPPORTED_LANGS:
        lang = DEFAULT_LANG
    try:
        import streamlit as st
        st.session_state["lang"] = lang
    except Exception:
        pass


def t(key: str, lang: Optional[str] = None, **fmt: Any) -> str:
    """
    Translate a dotted key. Example: t("sidebar.reset_btn").

    Falls back to English, then to the key itself if the translation is missing.
    """
    lang = lang or get_lang()
    for candidate in (lang, DEFAULT_LANG):
        data = load_locale(candidate)
        value = _lookup(data, key)
        if value is not None:
            return value.format(**fmt) if fmt else value
    return key


def _lookup(data: dict, dotted_key: str) -> Optional[str]:
    node: Any = data
    for part in dotted_key.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node if isinstance(node, str) else None


def pick_localized(value: Any, lang: Optional[str] = None) -> str:
    """
    Resolve a value that may be a plain string or a {en, fr} dict.

    Used by ui_components for ui_texts.json entries that can be either form.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        lang = lang or get_lang()
        return value.get(lang) or value.get(DEFAULT_LANG) or next(iter(value.values()), "")
    return ""


def reload() -> None:
    """Drop the cache (useful for tests and hot-reload)."""
    _cache.clear()
