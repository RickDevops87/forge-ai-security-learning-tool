"""Structured evidence capture for exercises."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel
from datetime import datetime


class Evidence(BaseModel):
    scenario_id: str
    timestamp: str
    user_prompt: str
    model_output: str
    tool_calls: List[Dict[str, Any]]
    canary_triggered: bool = False
    canary_strings: List[str] = []
    assessment: Optional[str] = None
    provider_name: Optional[str] = None
    provider_error: Optional[str] = None
    capability_available: Optional[bool] = None
    model_refusal: Optional[str] = None
    control_decisions: List[Dict[str, Any]] = []

    # Optional prior turn evidence for multi-turn scenarios such as MP-01.
    prior_user_prompt: Optional[str] = None
    prior_model_output: Optional[str] = None

    @classmethod
    def from_attack(
        cls,
        scenario_id: str,
        user_prompt: str,
        model_output: str,
        tool_calls: List[Dict[str, Any]],
        canary_strings: Optional[List[str]] = None,
        prior_user_prompt: Optional[str] = None,
        prior_model_output: Optional[str] = None,
        assessment: Optional[str] = None,
        provider_name: Optional[str] = None,
        provider_error: Optional[str] = None,
        capability_available: Optional[bool] = None,
        model_refusal: Optional[str] = None,
        control_decisions: Optional[List[Dict[str, Any]]] = None,
    ) -> Evidence:
        return cls(
            scenario_id=scenario_id,
            timestamp=datetime.utcnow().isoformat(),
            user_prompt=user_prompt,
            model_output=model_output,
            tool_calls=tool_calls,
            canary_triggered=cls._check_canaries(
                model_output,
                canary_strings or [],
            ),
            canary_strings=canary_strings or [],
            prior_user_prompt=prior_user_prompt,
            prior_model_output=prior_model_output,
            assessment=assessment,
            provider_name=provider_name,
            provider_error=provider_error,
            capability_available=capability_available,
            model_refusal=model_refusal,
            control_decisions=control_decisions or [],
        )

    @classmethod
    def from_defense(
        cls,
        scenario_id: str,
        defense_prompt: str,
        model_output: str,
    ) -> Evidence:
        return cls(
            scenario_id=scenario_id,
            timestamp=datetime.utcnow().isoformat(),
            user_prompt=defense_prompt,
            model_output=model_output,
            tool_calls=[],
        )

    @classmethod
    def from_retest(
        cls,
        scenario_id: str,
        user_prompt: str,
        model_output: str,
        canary_strings: Optional[List[str]] = None,
        prior_user_prompt: Optional[str] = None,
        prior_model_output: Optional[str] = None,
        tool_calls: Optional[List[Dict[str, Any]]] = None,
        assessment: Optional[str] = None,
        provider_name: Optional[str] = None,
        provider_error: Optional[str] = None,
        capability_available: Optional[bool] = None,
        model_refusal: Optional[str] = None,
        control_decisions: Optional[List[Dict[str, Any]]] = None,
    ) -> Evidence:
        return cls(
            scenario_id=scenario_id,
            timestamp=datetime.utcnow().isoformat(),
            user_prompt=user_prompt,
            model_output=model_output,
            tool_calls=tool_calls or [],
            canary_triggered=cls._check_canaries(
                model_output,
                canary_strings or [],
            ),
            canary_strings=canary_strings or [],
            prior_user_prompt=prior_user_prompt,
            prior_model_output=prior_model_output,
            assessment=assessment,
            provider_name=provider_name,
            provider_error=provider_error,
            capability_available=capability_available,
            model_refusal=model_refusal,
            control_decisions=control_decisions or [],
        )

    @staticmethod
    def _check_canaries(output: str, canary_strings: List[str]) -> bool:
        return any(c in output for c in canary_strings)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()
