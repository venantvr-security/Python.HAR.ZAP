"""Tests for ui_components module."""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


class TestUIComponents:
    @pytest.fixture(autouse=True)
    def reset_cache(self):
        """Reset the module-level cache before each test."""
        import modules.ui_components as uic
        uic._UI_TEXTS = None
        uic._JS_INJECTED = False
        yield
        uic._UI_TEXTS = None
        uic._JS_INJECTED = False

    def test_load_texts(self):
        from modules.ui_components import _load_texts
        texts = _load_texts()
        assert isinstance(texts, dict)
        assert "_meta" in texts
        assert "upload_tab" in texts

    def test_get_text_existing(self):
        from modules.ui_components import get_text
        label = get_text("upload_tab", "har_uploader", "label")
        assert label == "Upload HAR file"

        help_text = get_text("upload_tab", "har_uploader", "help")
        assert "HAR" in help_text

    def test_get_text_missing_tab(self):
        from modules.ui_components import get_text
        result = get_text("nonexistent_tab", "ctrl", "label")
        assert result == ""

    def test_get_text_missing_ctrl(self):
        from modules.ui_components import get_text
        result = get_text("upload_tab", "nonexistent_ctrl", "label")
        assert result == ""

    def test_get_text_missing_field(self):
        from modules.ui_components import get_text
        result = get_text("upload_tab", "har_uploader", "nonexistent")
        assert result == ""

    def test_get_all_texts(self):
        from modules.ui_components import get_all_texts
        texts = get_all_texts()
        assert isinstance(texts, dict)
        assert len(texts) >= 9  # At least 9 tabs

    def test_reload_texts(self):
        from modules.ui_components import _load_texts, reload_texts
        import modules.ui_components as uic

        _load_texts()
        assert uic._UI_TEXTS is not None

        reload_texts()
        assert uic._UI_TEXTS is not None

    @patch("modules.ui_components.st")
    def test_file_uploader(self, mock_st):
        from modules.ui_components import file_uploader
        mock_st.file_uploader.return_value = None

        result = file_uploader("upload_tab", "har_uploader", types=["har"], key="test")

        mock_st.file_uploader.assert_called_once()
        call_args = mock_st.file_uploader.call_args
        assert call_args[0][0] == "Upload HAR file"
        assert call_args[1]["type"] == ["har"]
        assert call_args[1]["key"] == "test"
        assert "help" in call_args[1]

    @patch("modules.ui_components.st")
    def test_text_area(self, mock_st):
        from modules.ui_components import text_area
        mock_st.text_area.return_value = "test"

        result = text_area("upload_tab", "scope_domains", key="scope_key")

        mock_st.text_area.assert_called_once()
        call_args = mock_st.text_area.call_args
        assert call_args[0][0] == "Scope domains (one per line)"
        assert call_args[1]["key"] == "scope_key"

    @patch("modules.ui_components.st")
    def test_text_input(self, mock_st):
        from modules.ui_components import text_input
        mock_st.text_input.return_value = "val"

        result = text_input("fuzzer_tab", "custom_url", key="url_key")

        mock_st.text_input.assert_called_once()
        assert mock_st.text_input.call_args[0][0] == "Target URL"

    @patch("modules.ui_components.st")
    def test_multiselect(self, mock_st):
        from modules.ui_components import multiselect
        mock_st.multiselect.return_value = ["opt1"]

        result = multiselect("upload_tab", "scan_types", ["opt1", "opt2"], key="scan_key")

        mock_st.multiselect.assert_called_once()
        call_args = mock_st.multiselect.call_args
        assert call_args[1]["key"] == "scan_key"

    @patch("modules.ui_components.st")
    def test_selectbox(self, mock_st):
        from modules.ui_components import selectbox
        mock_st.selectbox.return_value = "opt1"

        result = selectbox("fuzzer_tab", "wordlist_choice", ["opt1", "opt2"], key="wl_key")

        mock_st.selectbox.assert_called_once()
        assert mock_st.selectbox.call_args[0][0] == "Wordlist"

    @patch("modules.ui_components.st")
    def test_checkbox(self, mock_st):
        from modules.ui_components import checkbox
        mock_st.checkbox.return_value = True

        result = checkbox("upload_tab", "full_assault", key="assault_key")

        mock_st.checkbox.assert_called_once()

    @patch("modules.ui_components.st")
    def test_slider(self, mock_st):
        from modules.ui_components import slider
        mock_st.slider.return_value = 5

        result = slider("idor_tab", "parallel_workers", 1, 10, 5, key="workers_key")

        mock_st.slider.assert_called_once()
        call_args = mock_st.slider.call_args
        assert call_args[0][1] == 1  # min
        assert call_args[0][2] == 10  # max
        assert call_args[0][3] == 5  # default

    @patch("modules.ui_components.st")
    def test_number_input(self, mock_st):
        from modules.ui_components import number_input
        mock_st.number_input.return_value = 10

        result = number_input("acceptance_tab", "max_high_threshold", key="high_key")

        mock_st.number_input.assert_called_once()

    @patch("modules.ui_components.st")
    def test_button(self, mock_st):
        from modules.ui_components import button
        mock_st.button.return_value = True

        result = button("upload_tab", "analyze_btn", key="analyze_key")

        mock_st.button.assert_called_once()
        assert mock_st.button.call_args[0][0] == "Analyze HAR"

    @patch("modules.ui_components.st")
    def test_button_with_icon(self, mock_st):
        from modules.ui_components import button
        mock_st.button.return_value = True

        result = button("upload_tab", "analyze_btn", key="analyze_key", icon="🔍")

        mock_st.button.assert_called_once()
        assert "🔍" in mock_st.button.call_args[0][0]

    @patch("modules.ui_components.st")
    def test_inject_tooltips_js(self, mock_st):
        from modules.ui_components import inject_tooltips_js
        import modules.ui_components as uic

        inject_tooltips_js()

        mock_st.markdown.assert_called_once()
        call_args = mock_st.markdown.call_args
        assert "unsafe_allow_html" in call_args[1]
        assert call_args[1]["unsafe_allow_html"] is True
        assert "UITexts" in call_args[0][0]
        assert uic._JS_INJECTED

    @patch("modules.ui_components.st")
    def test_inject_tooltips_js_only_once(self, mock_st):
        from modules.ui_components import inject_tooltips_js
        import modules.ui_components as uic

        inject_tooltips_js()
        inject_tooltips_js()  # Second call should be no-op

        assert mock_st.markdown.call_count == 1


class TestUITextsJSON:
    def test_json_structure(self):
        ui_file = Path(__file__).parent.parent.parent / "ui_texts.json"
        with open(ui_file, "r", encoding="utf-8") as f:
            texts = json.load(f)

        assert "_meta" in texts
        assert texts["_meta"]["version"] == "2.0"

    def test_all_controls_have_required_fields(self):
        ui_file = Path(__file__).parent.parent.parent / "ui_texts.json"
        with open(ui_file, "r", encoding="utf-8") as f:
            texts = json.load(f)

        for tab_name, controls in texts.items():
            if tab_name.startswith("_"):
                continue
            for ctrl_name, config in controls.items():
                assert "id" in config, f"{tab_name}/{ctrl_name} missing id"
                assert "label" in config, f"{tab_name}/{ctrl_name} missing label"
                assert "help" in config, f"{tab_name}/{ctrl_name} missing help"

    def test_all_ids_unique(self):
        ui_file = Path(__file__).parent.parent.parent / "ui_texts.json"
        with open(ui_file, "r", encoding="utf-8") as f:
            texts = json.load(f)

        all_ids = []
        for tab_name, controls in texts.items():
            if tab_name.startswith("_"):
                continue
            for ctrl_name, config in controls.items():
                all_ids.append(config.get("id"))

        assert len(all_ids) == len(set(all_ids)), "Duplicate IDs found"
