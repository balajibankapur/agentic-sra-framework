"""Guardrail #9 — legacy-vs-modern taxonomy check (soft-warn).

Verifies that existing_controls carry kind="legacy" and proposed_controls
carry kind="proposed". Also flags obvious taxonomy inversions (e.g. an
existing_control whose description reads like a modern proposal).
"""

from __future__ import annotations

import re
from typing import Any

from framework.agents.guardrails import GuardrailContext, GuardrailResult


_MODERN_HINTS = re.compile(
    r"\b(ed25519|ecdsa|aes-?\d+|sha-?256|sha-?3|tls\s?1\.[23]|mutual\s+auth|le\s+secure)",
    re.IGNORECASE,
)


def check(entry: dict[str, Any], ctx: GuardrailContext) -> GuardrailResult:
    warnings: list[str] = []

    for i, c in enumerate(entry.get("existing_controls", []) or []):
        if not isinstance(c, dict):
            continue
        kind = c.get("kind", "")
        desc = c.get("description", "")
        if kind != "legacy":
            warnings.append(
                f"existing_controls[{i}].kind={kind!r} (expected 'legacy')"
            )
        if _MODERN_HINTS.search(desc):
            warnings.append(
                f"existing_controls[{i}] description reads modern "
                f"({desc[:80]!r}) but is tagged as existing — verify it isn't a proposal"
            )

    for i, c in enumerate(entry.get("proposed_controls", []) or []):
        if not isinstance(c, dict):
            continue
        kind = c.get("kind", "")
        if kind != "proposed":
            warnings.append(
                f"proposed_controls[{i}].kind={kind!r} (expected 'proposed')"
            )

    if warnings:
        return GuardrailResult.soft_warn(*warnings[:6])
    return GuardrailResult.ok()
