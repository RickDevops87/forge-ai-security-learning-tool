"""Provider factory — creates adapters by name."""
from __future__ import annotations

from typing import Dict, Optional
from .base import IModelProvider
from .demo import DemoProvider
from .local.ollama import OllamaProvider
from .hosted.openai import OpenAIProvider
from .hosted.base_http import BaseHTTPProvider


_PROVIDERS: Dict[str, type[IModelProvider]] = {
    "demo": DemoProvider,
    "ollama": OllamaProvider,
    "openai": OpenAIProvider,
    "custom": OpenAIProvider,  # OpenAI-compatible endpoint
}


def create_provider(name: str, **kwargs) -> IModelProvider:
    """Create a provider by name."""
    provider_class = _PROVIDERS.get(name)
    if provider_class is None:
        available = ", ".join(_PROVIDERS.keys())
        raise ValueError(f"Unknown provider '{name}'. Available: {available}")
    return provider_class(**kwargs)


def list_providers() -> list[str]:
    """List available provider names."""
    return list(_PROVIDERS.keys())


def register_provider(name: str, provider_class: type[IModelProvider]) -> None:
    """Register a custom provider (for extending the product)."""
    _PROVIDERS[name] = provider_class
