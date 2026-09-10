"""Guardrail Layer per SDD §4.

Every guardrail exposes:

    def check(entry: dict, ctx: GuardrailContext) -> GuardrailResult

Hard-fail guardrails set passed=False AND severity="hard" -> the entry
is marked `parse_error` and the raw LLM output preserved for manual review.

Soft-warn guardrails set passed=False AND severity="soft" -> the entry
flows through with a message appended to entry.warnings.

Passing guardrails set passed=True (severity ignored).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Literal


@dataclass
class GuardrailContext:
    """Anything a guardrail may need from the surrounding pipeline."""

    threat_id: str = ""
    retrieved_chunks: dict[str, str] = field(default_factory=dict)  # chunk_id -> text
    known_node_ids: set[str] = field(default_factory=set)           # from Kuzu
    device: str = ""
    agent_name: str = ""                                            # for schema_check binding


@dataclass
class GuardrailResult:
    passed: bool
    severity: Literal["hard", "soft"] = "soft"
    messages: list[str] = field(default_factory=list)

    @classmethod
    def ok(cls) -> "GuardrailResult":
        return cls(passed=True)

    @classmethod
    def hard_fail(cls, *messages: str) -> "GuardrailResult":
        return cls(passed=False, severity="hard", messages=list(messages))

    @classmethod
    def soft_warn(cls, *messages: str) -> "GuardrailResult":
        return cls(passed=False, severity="soft", messages=list(messages))


GuardrailFn = Callable[[dict[str, Any], GuardrailContext], GuardrailResult]


def run_guardrails(
    entry: dict[str, Any],
    ctx: GuardrailContext,
    guardrail_names: list[str],
) -> tuple[bool, list[str], list[str]]:
    """Run a list of guardrails by name.

    Returns (passed_all_hard, hard_failures, soft_warnings). If any hard
    guardrail fails, passed_all_hard is False and the caller should mark
    the entry parse_error=True.
    """
    from framework.agents.guardrails import registry

    hard_failures: list[str] = []
    soft_warnings: list[str] = []
    for name in guardrail_names:
        fn = registry.RESOLVERS.get(name)
        if fn is None:
            soft_warnings.append(f"[{name}] unknown guardrail — skipped")
            continue
        result = fn(entry, ctx)
        if result.passed:
            continue
        if result.severity == "hard":
            hard_failures.extend(f"[{name}] {m}" for m in result.messages)
        else:
            soft_warnings.extend(f"[{name}] {m}" for m in result.messages)
    return (len(hard_failures) == 0, hard_failures, soft_warnings)
