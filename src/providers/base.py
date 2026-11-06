"""Base provider interface — UI-independent."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Iterator, List


class Tool:
    def __init__(
        self,
        name: str,
        description: str,
        parameters: Dict[str, Any],
    ) -> None:
        self.name = name
        self.description = description
        self.parameters = parameters


class ModelResponse:
    def __init__(
        self,
        content: str,
        tool_calls: List[Dict[str, Any]] | None = None,
        refusal: str | None = None,
        error: str | None = None,
    ) -> None:
        self.content = content
        self.tool_calls = tool_calls or []
        self.refusal = refusal
        self.error = error


class IModelProvider(ABC):
    @abstractmethod
    async def chat(
        self,
        messages: List[Dict[str, str]],
        tools: List[Tool] | None = None,
        **kwargs: Any,
    ) -> ModelResponse:
        ...

    @abstractmethod
    async def stream(
        self,
        messages: List[Dict[str, str]],
        tools: List[Tool] | None = None,
        **kwargs: Any,
    ) -> Iterator[ModelResponse]:
        ...

    @abstractmethod
    def supports_tools(self) -> bool:
        ...

    @abstractmethod
    def name(self) -> str:
        ...
