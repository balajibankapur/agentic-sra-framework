"""Guardrail #11 — schema validation (hard-fail).

Validates the agent's JSON output against a Pydantic model. If the output
misses required fields, has wrong types, or has out-of-range values, the
entry is marked parse_error=True.
"""

from __future__ import annotations

from typing import Any, Type

from pydantic import BaseModel, ValidationError

from framework.agents.guardrails import GuardrailContext, GuardrailResult


def make_schema_check(model: Type[BaseModel]) -> "SchemaCheck":
    """Bind a schema_check guardrail to a specific Pydantic model."""
    return SchemaCheck(model=model)


class SchemaCheck:
    def __init__(self, model: Type[BaseModel]) -> None:
        self.model = model

    def __call__(self, entry: dict[str, Any], ctx: GuardrailContext) -> GuardrailResult:
        try:
            self.model.model_validate(entry)
        except ValidationError as e:
            # Trim the error to something short and actionable
            errs = e.errors()
            msgs = [f"{'/'.join(str(x) for x in err['loc'])}: {err['msg']}" for err in errs[:8]]
            return GuardrailResult.hard_fail(*msgs)
        return GuardrailResult.ok()
