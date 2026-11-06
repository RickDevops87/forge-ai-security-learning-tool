"""Custom OpenAI-compatible endpoint adapter."""
from __future__ import annotations

import httpx
from typing import Any, Dict, Iterator, List
from .base_http import BaseHTTPProvider
from ..base import ModelResponse, Tool


class CustomEndpointProvider(BaseHTTPProvider):
    """Adapter for any OpenAI-compatible endpoint."""

    def __init__(self, api_key: str, base_url: str, model: str = "custom", **kwargs: Any) -> None:
        super().__init__(api_key=api_key, base_url=base_url, model=model)

    def name(self) -> str:
        return f"Custom Endpoint ({self.model})"
