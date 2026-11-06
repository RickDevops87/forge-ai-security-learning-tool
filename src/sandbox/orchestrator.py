"""Sandbox orchestrator — controls what the model can see and do."""
from __future__ import annotations

import os
import tempfile
import shutil
from pathlib import Path
from typing import Any, Dict, List

from .filesystem import SandboxedFilesystem
from .tools import MockToolRegistry
from .canaries import CanaryDetector
from .fixtures import FixtureLoader
from src.engine.action_gate import ActionConfirmationGate


class SandboxOrchestrator:
    """Controls the sandbox environment for exercise execution."""

    def __init__(self) -> None:
        self.temp_dir: str = ""
        self.filesystem: SandboxedFilesystem | None = None
        self.tool_registry: MockToolRegistry | None = None
        self.canary_detector: CanaryDetector | None = None
        self.fixture_loader: FixtureLoader | None = None
        self.action_gate: ActionConfirmationGate | None = None
        self._active: bool = False

    def start(self) -> None:
        """Initialize the sandbox."""
        self.temp_dir = tempfile.mkdtemp(prefix="ai-sec-lab-")
        self.filesystem = SandboxedFilesystem(self.temp_dir)
        self.tool_registry = MockToolRegistry(self.temp_dir)
        self.canary_detector = CanaryDetector()
        self.fixture_loader = FixtureLoader(self.temp_dir)
        self.action_gate = ActionConfirmationGate()
        self._active = True

    def stop(self) -> None:
        """Clean up the sandbox."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        self.temp_dir = ""
        self._active = False

    def load_fixtures(self, fixture_names: List[str]) -> None:
        """Load synthetic fixtures into the sandbox."""
        if self.fixture_loader:
            self.fixture_loader.load(fixture_names)

    def reset(self) -> None:
        """Reset sandbox state for a new exercise."""
        self.stop()
        self.start()

    @property
    def is_active(self) -> bool:
        return self._active

    def get_temp_dir(self) -> str:
        return self.temp_dir
