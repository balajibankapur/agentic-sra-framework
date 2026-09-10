"""Guardrail #4 — quote substring verification (hard-fail).

For every `quote` field in the entry, verify it's a substring of a
retrieved chunk in the guardrail context. Prevents the LLM from
fabricating clause language.

Comparison is whitespace-normalized so minor formatting differences
(newlines, extra spaces) don't cause false failures.
"""

from __future__ import annotations

import re
from typing import Any

from framework.agents.guardrails import GuardrailContext, GuardrailResult


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def check(entry: dict[str, Any], ctx: GuardrailContext) -> GuardrailResult:
    """Verify every quoted string in the entry appears in a retrieved chunk."""
    quotes = _collect_quotes(entry)
    if not quotes:
        return GuardrailResult.ok()

    haystacks = [_norm(text) for text in ctx.retrieved_chunks.values()]
    if not haystacks:
        return GuardrailResult.hard_fail(
            f"entry has {len(quotes)} quote fields but no retrieved chunks in context"
        )

    misses: list[str] = []
    for path, quote in quotes:
        needle = _norm(quote)
        if len(needle) < 10:
            # Very short quotes are useless anchors; skip.
            continue
        if not any(needle in hay for hay in haystacks):
            misses.append(f"{path}: {quote[:80]!r} not found in any retrieved chunk")

    if misses:
        return GuardrailResult.hard_fail(*misses[:6])
    return GuardrailResult.ok()


def _collect_quotes(obj: Any, path: str = "") -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            sub = f"{path}.{k}" if path else k
            if k == "quote" and isinstance(v, str):
                out.append((sub, v))
            else:
                out.extend(_collect_quotes(v, sub))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            out.extend(_collect_quotes(item, f"{path}[{i}]"))
    return out
