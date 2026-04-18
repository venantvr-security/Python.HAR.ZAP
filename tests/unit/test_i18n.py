"""Tests for i18n module."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest


class TestI18n:
    @pytest.fixture(autouse=True)
    def reset_cache(self):
        from modules import i18n
        i18n.reload()
        yield
        i18n.reload()

    def test_load_locale_en(self):
        from modules.i18n import load_locale
        en = load_locale("en")
        assert isinstance(en, dict)
        assert en["_meta"]["lang"] == "en"
        assert "sidebar" in en

    def test_load_locale_fr(self):
        from modules.i18n import load_locale
        fr = load_locale("fr")
        assert isinstance(fr, dict)
        assert fr["_meta"]["lang"] == "fr"

    def test_load_locale_unknown_fallback(self):
        from modules.i18n import load_locale, DEFAULT_LANG
        unknown = load_locale("zz")
        default = load_locale(DEFAULT_LANG)
        assert unknown is default

    def test_t_default_english(self):
        from modules.i18n import t
        assert t("sidebar.reset_btn") == "Reset session"

    def test_t_french(self):
        from modules.i18n import t
        assert t("sidebar.reset_btn", lang="fr") == "Réinitialiser la session"

    def test_t_fallback_to_english_when_key_missing_in_french(self, tmp_path, monkeypatch):
        from modules import i18n
        monkeypatch.setattr(i18n, "_LOCALE_DIR", tmp_path)
        (tmp_path / "en.json").write_text(json.dumps({"a": {"b": "English-only"}}))
        (tmp_path / "fr.json").write_text(json.dumps({"a": {}}))
        i18n.reload()
        assert i18n.t("a.b", lang="fr") == "English-only"

    def test_t_returns_key_when_missing_everywhere(self):
        from modules.i18n import t
        assert t("nonexistent.key.path") == "nonexistent.key.path"

    def test_t_with_format(self):
        from modules.i18n import t
        result = t("sidebar.restored_toast", n=42, lang="fr")
        assert "42" in result
        assert "Restauré" in result

    def test_pick_localized_plain_string(self):
        from modules.i18n import pick_localized
        assert pick_localized("hello") == "hello"

    def test_pick_localized_dict(self):
        from modules.i18n import pick_localized
        assert pick_localized({"en": "A", "fr": "B"}, lang="en") == "A"
        assert pick_localized({"en": "A", "fr": "B"}, lang="fr") == "B"

    def test_pick_localized_dict_fallback(self):
        from modules.i18n import pick_localized
        assert pick_localized({"en": "A"}, lang="fr") == "A"

    def test_pick_localized_empty(self):
        from modules.i18n import pick_localized
        assert pick_localized(None) == ""
        assert pick_localized({}) == ""

    def test_supported_langs(self):
        from modules.i18n import SUPPORTED_LANGS, DEFAULT_LANG
        assert "en" in SUPPORTED_LANGS
        assert "fr" in SUPPORTED_LANGS
        assert DEFAULT_LANG == "en"

    def test_all_en_keys_have_fr_counterpart(self):
        from modules.i18n import load_locale
        en = load_locale("en")
        fr = load_locale("fr")

        def keys(d, prefix=""):
            out = []
            for k, v in d.items():
                if k.startswith("_"):
                    continue
                path = f"{prefix}.{k}" if prefix else k
                if isinstance(v, dict):
                    out.extend(keys(v, path))
                else:
                    out.append(path)
            return out

        en_keys = set(keys(en))
        fr_keys = set(keys(fr))
        missing = en_keys - fr_keys
        assert not missing, f"French translations missing for: {missing}"

    def test_ui_texts_multilang_structure(self):
        path = Path(__file__).parent.parent.parent / "ui_texts.json"
        data = json.loads(path.read_text())
        assert data["_meta"]["langs"] == ["en", "fr"]
        for tab, controls in data.items():
            if tab.startswith("_"):
                continue
            for ctrl, cfg in controls.items():
                label = cfg.get("label")
                assert isinstance(label, dict), f"{tab}/{ctrl} label must be multilang"
                assert "en" in label and "fr" in label


class TestUIComponentsI18n:
    @pytest.fixture(autouse=True)
    def reset_cache(self):
        import modules.ui_components as uic
        from modules import i18n
        uic._UI_TEXTS = None
        uic._JS_INJECTED = False
        i18n.reload()
        yield
        uic._UI_TEXTS = None
        uic._JS_INJECTED = False
        i18n.reload()

    def test_get_text_returns_english_by_default(self):
        from modules.ui_components import get_text
        assert get_text("upload_tab", "har_uploader", "label") == "Upload HAR file"

    def test_get_text_returns_french_when_requested(self):
        from modules.ui_components import get_text
        result = get_text("upload_tab", "har_uploader", "label", lang="fr")
        assert result == "Importer un fichier HAR"

    def test_get_text_help_in_french(self):
        from modules.ui_components import get_text
        result = get_text("upload_tab", "har_uploader", "help", lang="fr")
        assert "HAR" in result
        assert "DevTools" in result or "navigateur" in result
