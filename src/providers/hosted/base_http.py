"""Shared HTTP client logic for hosted providers."""
from __future__ import annotations

import httpx
from typing import Any, Dict, Iterator, List
from ..base import IModelProvider, ModelResponse, Tool


class BaseHTTPProvider(IModelProvider):
    """Base class for HTTP-based model providers."""

    def __init__(self, api_key: str, base_url: str, model: str, **kwargs: Any) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._client = httpx.AsyncClient(timeout=300.0)

    def name(self) -> str:
        return f"{self.__class__.__name__} ({self.model})"

    def supports_tools(self) -> bool:
        return False  # Implement per-provider

    async def chat(
        self,
        messages: List[Dict[str, str]],
        tools: List[Tool] | None = None,
        **kwargs: Any,
    ) -> ModelResponse:
        raise NotImplementedError

    async def stream(
        self,
        messages: List[Dict[str, str]],
        tools: List[Tool] | None = None,
        **kwargs: Any,
    ) -> Iterator[ModelResponse]:
        raise NotImplementedError

    async def close(self) -> None:
        await self._client.aclose()
