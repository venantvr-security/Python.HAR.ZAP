"""Tests for workflow_state module."""
import json
import os
import tempfile
from unittest.mock import MagicMock

import pytest

from modules.workflow_state import (
    WorkflowState,
    WorkflowStep,
    compute_har_hash,
    restore_to_session_state,
    save_from_session_state,
    WORKFLOW_STEPS,
)


class TestWorkflowStep:
    def test_create_step(self):
        step = WorkflowStep(name="upload", data_keys=["har_data"])
        assert step.name == "upload"
        assert step.status == "pending"
        assert step.started_at is None
        assert step.completed_at is None
        assert step.data_keys == ["har_data"]

    def test_to_dict(self):
        step = WorkflowStep(name="upload", status="done", data_keys=["har_data"])
        d = step.to_dict()
        assert d["name"] == "upload"
        assert d["status"] == "done"
        assert d["data_keys"] == ["har_data"]

    def test_from_dict(self):
        data = {
            "name": "tokens",
            "status": "in_progress",
            "started_at": "2026-03-21T10:00:00",
            "completed_at": None,
            "data_keys": ["extracted_tokens"],
        }
        step = WorkflowStep.from_dict(data)
        assert step.name == "tokens"
        assert step.status == "in_progress"
        assert step.started_at == "2026-03-21T10:00:00"


class TestWorkflowState:
    def test_create_new(self):
        state = WorkflowState.create_new()
        assert state.session_id is not None
        assert len(state.steps) == len(WORKFLOW_STEPS)
        assert state.current_step == 0
        assert state.data == {}

    def test_mark_step_started(self):
        state = WorkflowState.create_new()
        state.mark_step_started("upload")

        step = state.get_step("upload")
        assert step.status == "in_progress"
        assert step.started_at is not None
        assert state.current_step == 0

    def test_mark_step_done(self):
        state = WorkflowState.create_new()
        data = {"har_data": {"log": {"entries": []}}}
        state.mark_step_done("upload", data)

        step = state.get_step("upload")
        assert step.status == "done"
        assert step.completed_at is not None
        assert state.current_step == 1
        assert state.data.get("har_data") == data["har_data"]

    def test_mark_step_skipped(self):
        state = WorkflowState.create_new()
        state.mark_step_skipped("idor")

        step = state.get_step("idor")
        assert step.status == "skipped"

    def test_is_step_done(self):
        state = WorkflowState.create_new()
        assert not state.is_step_done("upload")

        state.mark_step_done("upload", {})
        assert state.is_step_done("upload")

    def test_get_resume_point(self):
        state = WorkflowState.create_new()
        assert state.get_resume_point() == 0

        state.mark_step_done("upload", {})
        state.mark_step_done("tokens", {})
        assert state.get_resume_point() == 2

    def test_get_progress(self):
        state = WorkflowState.create_new()
        done, total = state.get_progress()
        assert done == 0
        assert total == len(WORKFLOW_STEPS)

        state.mark_step_done("upload", {})
        state.mark_step_done("tokens", {})
        done, total = state.get_progress()
        assert done == 2

    def test_to_dict_and_from_dict(self):
        state = WorkflowState.create_new()
        state.mark_step_done("upload", {"har_data": {"test": True}})

        d = state.to_dict()
        restored = WorkflowState.from_dict(d)

        assert restored.session_id == state.session_id
        assert restored.current_step == state.current_step
        assert len(restored.steps) == len(state.steps)
        assert restored.data == state.data

    def test_save_and_load(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            state = WorkflowState.create_new()
            state.mark_step_done("upload", {"har_data": {"test": True}})
            state.save(path)

            loaded = WorkflowState.load(path)
            assert loaded is not None
            assert loaded.session_id == state.session_id
            assert loaded.is_step_done("upload")
            assert loaded.data.get("har_data") == {"test": True}
        finally:
            os.unlink(path)

    def test_load_nonexistent(self):
        result = WorkflowState.load("/nonexistent/path.json")
        assert result is None

    def test_exists(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            assert WorkflowState.exists(path)
            os.unlink(path)
            assert not WorkflowState.exists(path)
        except FileNotFoundError:
            pass

    def test_delete(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        assert os.path.exists(path)
        WorkflowState.delete(path)
        assert not os.path.exists(path)

    def test_delete_nonexistent(self):
        # Should not raise
        WorkflowState.delete("/nonexistent/path.json")


class TestHelperFunctions:
    def test_compute_har_hash(self):
        har1 = {"log": {"entries": [{"request": {"url": "http://test.com"}}]}}
        har2 = {"log": {"entries": [{"request": {"url": "http://test.com"}}]}}
        har3 = {"log": {"entries": [{"request": {"url": "http://other.com"}}]}}

        hash1 = compute_har_hash(har1)
        hash2 = compute_har_hash(har2)
        hash3 = compute_har_hash(har3)

        assert hash1 == hash2  # Same content
        assert hash1 != hash3  # Different content
        assert len(hash1) == 16

    def test_restore_to_session_state(self):
        state = WorkflowState.create_new()
        state.data = {
            "har_data": {"test": True},
            "extracted_tokens": {"ids": [1, 2, 3]},
        }

        session_state = MagicMock()
        session_state.__setitem__ = MagicMock()
        session_state.__contains__ = lambda self, key: False

        # Use a simple dict for testing
        mock_state = {}
        restored = restore_to_session_state(state, mock_state)

        assert "har_data" in restored
        assert "extracted_tokens" in restored
        assert mock_state["har_data"] == {"test": True}

    def test_save_from_session_state(self):
        state = WorkflowState.create_new()

        mock_session = {
            "har_data": {"log": {"entries": []}},
            "other_key": "ignored",
        }

        save_from_session_state(state, mock_session, "upload")

        assert state.is_step_done("upload")
        assert state.data.get("har_data") == {"log": {"entries": []}}
        assert "other_key" not in state.data


class TestWorkflowStepsDefinition:
    def test_workflow_steps_defined(self):
        assert len(WORKFLOW_STEPS) == 8
        step_names = [name for name, _ in WORKFLOW_STEPS]
        assert "upload" in step_names
        assert "tokens" in step_names
        assert "preprocess" in step_names
        assert "zap_scan" in step_names
        assert "idor" in step_names
        assert "redteam" in step_names
        assert "passive" in step_names

    def test_each_step_has_data_keys(self):
        for name, keys in WORKFLOW_STEPS:
            assert isinstance(keys, list)
            assert len(keys) > 0 or name == "config"
