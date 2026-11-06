"""OpenAI provider adapter."""
from __future__ import annotations

import httpx
from typing import Any, Dict, Iterator, List
from .base_http import BaseHTTPProvider
from ..base import ModelResponse, Tool


class OpenAIProvider(BaseHTTPProvider):
    """Adapter for OpenAI API."""

    def __init__(self, api_key: str, model: str = "gpt-4o", base_url: str = "https://api.openai.com/v1", **kwargs: Any) -> None:
        super().__init__(api_key=api_key, base_url=base_url, model=model)
        self._client = httpx.AsyncClient(
            timeout=300.0,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )

    def supports_tools(self) -> bool:
        return True

    async def chat(
        self,
        messages: List[Dict[str, str]],
        tools: List[Tool] | None = None,
        **kwargs: Any,
    ) -> ModelResponse:
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.7,
        }
        if tools:
            payload["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    },
                }
                for t in tools
            ]

        try:
            resp = await self._client.post(f"{self.base_url}/chat/completions", json=payload)
            resp.raise_for_status()
            data = resp.json()
            choice = data.get("choices", [{}])[0]
            message = choice.get("message", {})
            content = message.get("content", "")
            tool_calls = message.get("tool_calls", [])
            refusal = message.get("refusal")

            return ModelResponse(content=content, tool_calls=tool_calls, refusal=refusal)
        except httpx.HTTPStatusError as e:
            return ModelResponse(content="", error=f"OpenAI API error: {e.response.status_code} {e.response.text[:200]}")
        except Exception as e:
            return ModelResponse(content="", error=str(e))

    async def stream(
        self,
        messages: List[Dict[str, str]],
        tools: List[Tool] | None = None,
        **kwargs: Any,
    ) -> Iterator[ModelResponse]:
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.7,
            "stream": True,
        }
        if tools:
            payload["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    },
                }
                for t in tools
            ]

        try:
            async with self._client.stream("POST", f"{self.base_url}/chat/completions", json=payload) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if line.startswith("data: "):
                        data_str = line[6:]
                        if data_str == "[DONE]":
                            break
                        try:
                            data = httpx._models.Response.json(httpx.Response(200, text=data_str))
                            choices = data.get("choices", [])
                            if choices:
                                delta = choices[0].get("delta", {})
                                content = delta.get("content", "")
                                if content:
                                    yield ModelResponse(content=content)
                        except Exception:
                            continue
        except Exception as e:
            yield ModelResponse(content="", error=str(e))