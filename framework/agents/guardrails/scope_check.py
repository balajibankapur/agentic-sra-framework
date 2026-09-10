"""Guardrail #14 — scope check (soft-warn).

Enforces the "propose only firmware / existing docs / config changes"
scope statement. Flags any proposal that names an OS distribution,
CPU/hardware SKU, organizational process, or a doc / code path outside
the accepted set.
"""

from __future__ import annotations

import re
from typing import Any

from framework.agents.guardrails import GuardrailContext, GuardrailResult


_ALLOWED_DOCS = {"SRS.md", "SDD.md", "SDS.md", "SAD.md"}

_OUT_OF_SCOPE_TOKENS = re.compile(
    r"\b(replace\s+the\s+(mcu|cpu|processor|soc|hardware)|"
    r"new\s+(mcu|cpu|processor|soc|board)|"
    r"switch\s+to\s+(linux|freertos|zephyr|windows|rtos)|"
    r"organi[sz]ational\s+process|"
    r"hire\s+a|training\s+program)\b",
    re.IGNORECASE,
)


def check(entry: dict[str, Any], ctx: GuardrailContext) -> GuardrailResult:
    warnings: list[str] = []

    for i, d in enumerate(entry.get("proposed_doc_changes", []) or []):
        if not isinstance(d, dict):
            continue
        doc = d.get("doc", "")
        if doc not in _ALLOWED_DOCS:
            warnings.append(
                f"proposed_doc_changes[{i}].doc={doc!r} not in {sorted(_ALLOWED_DOCS)}"
            )

    for i, c in enumerate(entry.get("proposed_code_changes", []) or []):
        if not isinstance(c, dict):
            continue
        path = c.get("path", "")
        if path and not path.startswith("firmware/"):
            warnings.append(
                f"proposed_code_changes[{i}].path={path!r} does not start with firmware/"
            )

    # Scan free-text fields for out-of-scope tokens
    for path, text in _walk_strings(entry):
        if not isinstance(text, str):
            continue
        m = _OUT_OF_SCOPE_TOKENS.search(text)
        if m:
            warnings.append(f"out-of-scope proposal at {path}: {m.group(0)!r} in {text[:120]!r}")

    if warnings:
        return GuardrailResult.soft_warn(*warnings[:6])
    return GuardrailResult.ok()


def _walk_strings(obj: Any, path: str = "") -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            sub = f"{path}.{k}" if path else k
            out.extend(_walk_strings(v, sub))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            out.extend(_walk_strings(item, f"{path}[{i}]"))
    elif isinstance(obj, str):
        # only scan fields that look like proposal or narrative content
        if any(k in path for k in ("proposed_", "residual_risk_reason", "narrative", "reason")):
            out.append((path, obj))
    return out
