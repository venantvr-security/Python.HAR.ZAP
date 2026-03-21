"""Workflow state persistence for HAR.ZAP session resume."""
import json
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_SESSION_FILE = ".harzap_session.json"

WORKFLOW_STEPS = [
    ("upload", ["har_data"]),
    ("tokens", ["extracted_tokens", "fuzzing_recommendations"]),
    ("preprocess", ["preprocessed_data"]),
    ("config", ["config", "scan_types"]),
    ("zap_scan", ["scan_results"]),
    ("idor", ["idor_results"]),
    ("redteam", ["redteam_results"]),
    ("passive", ["passive_results"]),
]


@dataclass
class WorkflowStep:
    name: str
    status: str = "pending"  # pending | in_progress | done | skipped
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    data_keys: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> "WorkflowStep":
        return cls(**data)


@dataclass
class WorkflowState:
    session_id: str
    created_at: str
    last_updated: str
    current_step: int
    steps: List[WorkflowStep]
    data: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create_new(cls) -> "WorkflowState":
        now = datetime.now().isoformat()
        session_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        steps = [
            WorkflowStep(name=name, data_keys=keys)
            for name, keys in WORKFLOW_STEPS
        ]
        return cls(
            session_id=session_id,
            created_at=now,
            last_updated=now,
            current_step=0,
            steps=steps,
            data={},
        )

    def mark_step_started(self, step_name: str):
        for i, step in enumerate(self.steps):
            if step.name == step_name:
                step.status = "in_progress"
                step.started_at = datetime.now().isoformat()
                self.current_step = i
                self.last_updated = datetime.now().isoformat()
                break

    def mark_step_done(self, step_name: str, data: Optional[Dict] = None):
        for i, step in enumerate(self.steps):
            if step.name == step_name:
                step.status = "done"
                step.completed_at = datetime.now().isoformat()
                self.current_step = i + 1
                self.last_updated = datetime.now().isoformat()
                if data:
                    for key in step.data_keys:
                        if key in data:
                            self.data[key] = data[key]
                break

    def mark_step_skipped(self, step_name: str):
        for step in self.steps:
            if step.name == step_name:
                step.status = "skipped"
                self.last_updated = datetime.now().isoformat()
                break

    def get_step(self, step_name: str) -> Optional[WorkflowStep]:
        for step in self.steps:
            if step.name == step_name:
                return step
        return None

    def is_step_done(self, step_name: str) -> bool:
        step = self.get_step(step_name)
        return step is not None and step.status == "done"

    def get_resume_point(self) -> int:
        for i, step in enumerate(self.steps):
            if step.status in ("pending", "in_progress"):
                return i
        return len(self.steps)

    def get_progress(self) -> tuple:
        done = sum(1 for s in self.steps if s.status == "done")
        return done, len(self.steps)

    def to_dict(self) -> Dict:
        return {
            "session_id": self.session_id,
            "created_at": self.created_at,
            "last_updated": self.last_updated,
            "current_step": self.current_step,
            "steps": [s.to_dict() for s in self.steps],
            "data": self.data,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "WorkflowState":
        steps = [WorkflowStep.from_dict(s) for s in data.get("steps", [])]
        return cls(
            session_id=data["session_id"],
            created_at=data["created_at"],
            last_updated=data["last_updated"],
            current_step=data.get("current_step", 0),
            steps=steps,
            data=data.get("data", {}),
        )

    def save(self, path: str = DEFAULT_SESSION_FILE):
        self.last_updated = datetime.now().isoformat()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)

    @classmethod
    def load(cls, path: str = DEFAULT_SESSION_FILE) -> Optional["WorkflowState"]:
        p = Path(path)
        if not p.exists():
            return None
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            return cls.from_dict(data)
        except (json.JSONDecodeError, KeyError):
            return None

    @classmethod
    def exists(cls, path: str = DEFAULT_SESSION_FILE) -> bool:
        return Path(path).exists()

    @classmethod
    def delete(cls, path: str = DEFAULT_SESSION_FILE):
        p = Path(path)
        if p.exists():
            p.unlink()


def compute_har_hash(har_data: Dict) -> str:
    """Compute hash of HAR data for identity."""
    content = json.dumps(har_data, sort_keys=True)
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def restore_to_session_state(workflow: WorkflowState, session_state) -> List[str]:
    """Restore workflow data to Streamlit session_state. Returns list of restored keys."""
    restored = []
    for key, value in workflow.data.items():
        if value is not None:
            session_state[key] = value
            restored.append(key)
    return restored


def save_from_session_state(workflow: WorkflowState, session_state, step_name: str):
    """Save relevant session_state data for a step."""
    step = workflow.get_step(step_name)
    if step:
        data = {}
        for key in step.data_keys:
            if key in session_state and session_state[key] is not None:
                data[key] = session_state[key]
        workflow.mark_step_done(step_name, data)
        workflow.save()
