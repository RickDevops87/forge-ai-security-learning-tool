import pytest
import asyncio
from src.providers.factory import create_provider, register_provider
from src.providers.base import IModelProvider, ModelResponse
from src.sandbox.orchestrator import SandboxOrchestrator
from src.scenarios.registry import ScenarioRegistry
from src.engine.executor import ExerciseExecutor
from src.engine.safety import SafetyGuard


@pytest.fixture
def temp_sandbox():
    sandbox = SandboxOrchestrator()
    sandbox.start()
    yield sandbox
    sandbox.stop()


@pytest.fixture
def demo_provider():
    return create_provider("demo")


@pytest.fixture
def registry():
    return ScenarioRegistry()


@pytest.fixture
def safety_guard():
    return SafetyGuard()
