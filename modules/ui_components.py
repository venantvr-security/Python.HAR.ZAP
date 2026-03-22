"""Decoupled UI components with externalized texts and tooltips."""
import json
from pathlib import Path
from typing import Any, List, Optional

import streamlit as st

_UI_TEXTS = None
_JS_INJECTED = False


def _load_texts() -> dict:
    """Load UI texts from JSON file (cached)."""
    global _UI_TEXTS
    if _UI_TEXTS is None:
        ui_file = Path(__file__).parent.parent / "ui_texts.json"
        if ui_file.exists():
            with open(ui_file, "r", encoding="utf-8") as f:
                _UI_TEXTS = json.load(f)
        else:
            _UI_TEXTS = {}
    return _UI_TEXTS


def get_text(tab: str, ctrl: str, field: str = "label") -> str:
    """Get text from UI texts JSON."""
    texts = _load_texts()
    return texts.get(tab, {}).get(ctrl, {}).get(field, "")


def file_uploader(tab: str, ctrl: str, *, types: List[str], key: str, **kwargs) -> Any:
    """File uploader with externalized label and help."""
    label = get_text(tab, ctrl) or kwargs.pop("label", "Upload file")
    help_text = get_text(tab, ctrl, "help")
    return st.file_uploader(label, type=types, key=key, help=help_text or None, **kwargs)


def text_area(tab: str, ctrl: str, *, key: str, **kwargs) -> str:
    """Text area with externalized label and help."""
    label = get_text(tab, ctrl) or kwargs.pop("label", "")
    help_text = get_text(tab, ctrl, "help")
    return st.text_area(label, key=key, help=help_text or None, **kwargs)


def text_input(tab: str, ctrl: str, *, key: str, **kwargs) -> str:
    """Text input with externalized label and help."""
    label = get_text(tab, ctrl) or kwargs.pop("label", "")
    help_text = get_text(tab, ctrl, "help")
    return st.text_input(label, key=key, help=help_text or None, **kwargs)


def multiselect(tab: str, ctrl: str, options: List[str], *, key: str, **kwargs) -> List[str]:
    """Multiselect with externalized label and help."""
    label = get_text(tab, ctrl) or kwargs.pop("label", "")
    help_text = get_text(tab, ctrl, "help")
    return st.multiselect(label, options, key=key, help=help_text or None, **kwargs)


def selectbox(tab: str, ctrl: str, options: List[str], *, key: str, **kwargs) -> str:
    """Selectbox with externalized label and help."""
    label = get_text(tab, ctrl) or kwargs.pop("label", "")
    help_text = get_text(tab, ctrl, "help")
    return st.selectbox(label, options, key=key, help=help_text or None, **kwargs)


def checkbox(tab: str, ctrl: str, *, key: str, **kwargs) -> bool:
    """Checkbox with externalized label and help."""
    label = get_text(tab, ctrl) or kwargs.pop("label", "")
    help_text = get_text(tab, ctrl, "help")
    return st.checkbox(label, key=key, help=help_text or None, **kwargs)


def slider(tab: str, ctrl: str, min_val: int, max_val: int, default: int, *, key: str, **kwargs) -> int:
    """Slider with externalized label and help."""
    label = get_text(tab, ctrl) or kwargs.pop("label", "")
    help_text = get_text(tab, ctrl, "help")
    return st.slider(label, min_val, max_val, default, key=key, help=help_text or None, **kwargs)


def number_input(tab: str, ctrl: str, *, key: str, **kwargs) -> int:
    """Number input with externalized label and help."""
    label = get_text(tab, ctrl) or kwargs.pop("label", "")
    help_text = get_text(tab, ctrl, "help")
    return st.number_input(label, key=key, help=help_text or None, **kwargs)


def button(tab: str, ctrl: str, *, key: str, icon: str = "", **kwargs) -> bool:
    """Button with externalized label and help."""
    label = get_text(tab, ctrl) or kwargs.pop("label", "")
    if icon:
        label = f"{icon} {label}"
    help_text = get_text(tab, ctrl, "help")
    return st.button(label, key=key, help=help_text or None, **kwargs)


def reload_texts():
    """Force reload of UI texts (useful for hot-reload)."""
    global _UI_TEXTS
    _UI_TEXTS = None
    _load_texts()


def inject_tooltips_js():
    """Inject JavaScript for dynamic tooltips based on control IDs."""
    global _JS_INJECTED
    if _JS_INJECTED:
        return

    texts = _load_texts()
    texts_json = json.dumps(texts)

    js_code = f"""
    <script>
    const UITexts = {texts_json};

    function applyTooltips() {{
        for (const [tabName, controls] of Object.entries(UITexts)) {{
            if (tabName.startsWith('_')) continue;
            for (const [ctrlName, config] of Object.entries(controls)) {{
                if (!config.id || !config.help) continue;

                // Find by various Streamlit selectors
                const selectors = [
                    `[data-testid="${{config.id}}"]`,
                    `[key="${{config.id}}"]`,
                    `label:has(+ [data-testid="${{config.id}}"])`,
                    `.stButton button[kind="primary"]`
                ];

                for (const sel of selectors) {{
                    try {{
                        const el = document.querySelector(sel);
                        if (el && !el.dataset.tooltipApplied) {{
                            el.title = config.help;
                            el.dataset.tooltipApplied = 'true';
                        }}
                    }} catch (e) {{}}
                }}
            }}
        }}
    }}

    // Apply on load and on mutations
    const observer = new MutationObserver(() => setTimeout(applyTooltips, 50));
    observer.observe(document.body, {{ childList: true, subtree: true }});
    setTimeout(applyTooltips, 500);
    </script>
    """

    st.markdown(js_code, unsafe_allow_html=True)
    _JS_INJECTED = True


def get_all_texts() -> dict:
    """Return all UI texts (for API exposure)."""
    return _load_texts()
