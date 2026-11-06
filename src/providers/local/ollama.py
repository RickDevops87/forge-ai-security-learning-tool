"""Ollama provider adapter."""
from __future__ import annotations

import httpx
import asyncio
from typing import Any, Dict, Iterator, List
from ..base import IModelProvider, ModelResponse, Tool


class OllamaProvider(IModelProvider):
    """Adapter for Ollama local model server."""

    def __init__(self, base_url: str = "http://127.0.0.1:11434", model: str = "llama3", **kwargs: Any) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self._client = httpx.AsyncClient(timeout=300.0)

    def name(self) -> str:
        return f"Ollama ({self.model})"

    def supports_tools(self) -> bool:
        return False  # Ollama tool support varies by model

    async def chat(
        self,
        messages: List[Dict[str, str]],
        tools: List[Tool] | None = None,
        **kwargs: Any,
    ) -> ModelResponse:
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": 0.7},
        }

        try:
            resp = await self._client.post(f"{self.base_url}/api/chat", json=payload)
            resp.raise_for_status()
            data = resp.json()
            content = data.get("message", {}).get("content", "")
            return ModelResponse(content=content)
        except httpx.ConnectError as e:
            return ModelResponse(content="", error=f"Cannot connect to Ollama at {self.base_url}: {e}")
        except Exception as e:
            return ModelResponse(content="", error=str(e))

    async def stream(
        self,
        messages: List[Dict[str, str]],
        tools: List[Tool] | None = None,
        **kwargs: Any,
    ) -> Iterator[ModelResponse]:
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": True,
            "options": {"temperature": 0.7},
        }

        try:
            async with self._client.stream("POST", f"{self.base_url}/api/chat", json=payload) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if line.strip():
                        try:
                            data = httpx._models.Response.json(httpx.Response(200, text=line))
                            content = data.get("message", {}).get("content", "")
                            if content:
                                yield ModelResponse(content=content)
                        except Exception:
                            continue
        except Exception as e:
            yield ModelResponse(content="", error=str(e))

    async def close(self) -> None:
        await self._client.aclose()
