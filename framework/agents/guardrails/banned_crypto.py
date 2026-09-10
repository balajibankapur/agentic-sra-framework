"""Guardrail #13 — banned-crypto scan (soft-warn).

Scans every free-text field in the entry for deprecated cryptographic
constructs appearing as a RECOMMENDATION (not as description of the
legacy state). Adds a warning rather than hard-failing so the reviewer
can decide.

Heuristic: a banned token counts as a recommendation when it appears in
`proposed_*` fields or in a `reason` field with words like "shall",
"should", "use", "recommend", "propose" nearby.
"""

from __future__ import annotations

import re
from typing import Any

from framework.agents.guardrails import GuardrailContext, GuardrailResult


_BANNED_TOKENS = [
    r"\bMD5\b",
    r"\bSHA-?1\b",
    r"\bRC4\b",
    r"\bDES\b",           # single DES, not 3DES
    r"\bTLS\s?1\.0\b",
    r"\bTLS\s?1\.1\b",
    r"\bSSLv?3\b",
]
_BANNED_RE = re.compile("|".join(_BANNED_TOKENS), re.IGNORECASE)

_RECOMMENDATION_HINT = re.compile(
    r"\b(shall|should|use|recommend|propose|adopt|upgrade to|switch to)\b",
    re.IGNORECASE,
)

_RECOMMENDATION_PATH_HINTS = ("proposed_", "recommend", "resolution", "residual_risk_reason", "narrative")


def check(entry: dict[str, Any], ctx: GuardrailContext) -> GuardrailResult:
    warnings: list[str] = []
    for path, text in _walk_strings(entry):
        if not text:
            continue
        m = _BANNED_RE.search(text)
        if not m:
            continue
        token = m.group(0)
        looks_like_recommendation = (
            any(hint in path for hint in _RECOMMENDATION_PATH_HINTS)
            or _RECOMMENDATION_HINT.search(text) is not None
        )
        if looks_like_recommendation:
            warnings.append(f"banned crypto {token!r} appears in recommendation at {path}: "
                            f"{text[:120]!r}")
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
        out.append((path, obj))
    return out
