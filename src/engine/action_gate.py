"""Action-bound confirmation gate for synthetic consequential lab tools."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import secrets
import time
from typing import Any, Awaitable, Callable, Dict


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    executed: bool
    reason: str
    action_digest: str
    result: Dict[str, Any] | None = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ActionConfirmationGate:
    """Require a separate, one-time confirmation bound to an exact action.

    Model text and tool arguments cannot create confirmations. A trusted caller
    must explicitly issue the token after presenting the exact tool and
    arguments to the user. Tokens expire, are single-use, and cannot authorize
    changed arguments or a different tool.
    """

    def __init__(self, ttl_seconds: float = 120.0) -> None:
        self.ttl_seconds = ttl_seconds
        self._approvals: Dict[str, tuple[str, float]] = {}

    @staticmethod
    def action_digest(tool_name: str, arguments: Dict[str, Any]) -> str:
        payload = json.dumps(
            {"tool": tool_name, "arguments": arguments},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def issue_confirmation(self, tool_name: str, arguments: Dict[str, Any]) -> str:
        """Trusted UI/controller entry point; never expose this method to a model."""
        token = secrets.token_urlsafe(32)
        self._approvals[token] = (
            self.action_digest(tool_name, arguments),
            time.monotonic() + self.ttl_seconds,
        )
        return token

    async def dispatch(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        handler: Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]],
        confirmation_token: str | None = None,
    ) -> GateDecision:
        digest = self.action_digest(tool_name, arguments)
        if not confirmation_token:
            return GateDecision(False, False, "separate_confirmation_required", digest)

        approval = self._approvals.pop(confirmation_token, None)
        if approval is None:
            return GateDecision(False, False, "invalid_or_replayed_confirmation", digest)

        approved_digest, expires_at = approval
        if time.monotonic() > expires_at:
            return GateDecision(False, False, "confirmation_expired", digest)
        if not secrets.compare_digest(approved_digest, digest):
            return GateDecision(False, False, "confirmation_does_not_match_action", digest)

        result = await handler(arguments)
        return GateDecision(True, True, "confirmed_action_executed", digest, result)
