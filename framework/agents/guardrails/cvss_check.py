"""Guardrail #3 — CVSS v3.1 vector parsing + score recompute (hard-fail).

Verifies:
  1. `cvss_v31.vector` parses as a CVSS v3.1 base vector string.
  2. `cvss_v31.base_score` matches what the vector actually scores (± 0.1
     tolerance for float rounding).
  3. `cvss_v31.severity` matches the standard score bands.

Uses the reference CVSS v3.1 calculator formula (FIRST.org spec).
"""

from __future__ import annotations

import re
from typing import Any

from framework.agents.guardrails import GuardrailContext, GuardrailResult


_VECTOR_RE = re.compile(
    r"^CVSS:3\.1"
    r"/AV:[NALP]"
    r"/AC:[LH]"
    r"/PR:[NLH]"
    r"/UI:[NR]"
    r"/S:[UC]"
    r"/C:[NLH]"
    r"/I:[NLH]"
    r"/A:[NLH]"
)


def check(entry: dict[str, Any], ctx: GuardrailContext) -> GuardrailResult:
    cvss = entry.get("cvss_v31")
    if not isinstance(cvss, dict):
        return GuardrailResult.hard_fail("cvss_v31 missing or not an object")

    vector = cvss.get("vector", "")
    if not _VECTOR_RE.match(vector):
        return GuardrailResult.hard_fail(
            f"cvss_v31.vector does not match CVSS v3.1 base vector pattern: {vector[:80]}"
        )

    try:
        computed = _score(vector)
    except Exception as e:
        return GuardrailResult.hard_fail(f"cvss vector parse error: {e}")

    reported = float(cvss.get("base_score", -1))
    if abs(reported - computed) > 0.1:
        return GuardrailResult.hard_fail(
            f"cvss_v31.base_score={reported} does not match vector-computed score={computed:.1f}"
        )

    reported_sev = cvss.get("severity", "")
    expected_sev = _severity_band(computed)
    if reported_sev != expected_sev:
        return GuardrailResult.hard_fail(
            f"cvss_v31.severity={reported_sev} does not match band for score {computed:.1f} "
            f"(expected {expected_sev})"
        )
    return GuardrailResult.ok()


# ---------------------------------------------------------------------------
# CVSS v3.1 reference formula (FIRST.org)

_METRIC_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},  # scope unchanged
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},   # scope changed
    "UI": {"N": 0.85, "R": 0.62},
    "C":  {"N": 0.0, "L": 0.22, "H": 0.56},
    "I":  {"N": 0.0, "L": 0.22, "H": 0.56},
    "A":  {"N": 0.0, "L": 0.22, "H": 0.56},
}


def _score(vector: str) -> float:
    parts = dict(p.split(":") for p in vector.split("/")[1:])
    scope_changed = parts["S"] == "C"

    av = _METRIC_WEIGHTS["AV"][parts["AV"]]
    ac = _METRIC_WEIGHTS["AC"][parts["AC"]]
    pr = _METRIC_WEIGHTS["PR_C" if scope_changed else "PR_U"][parts["PR"]]
    ui = _METRIC_WEIGHTS["UI"][parts["UI"]]
    c = _METRIC_WEIGHTS["C"][parts["C"]]
    i = _METRIC_WEIGHTS["I"][parts["I"]]
    a = _METRIC_WEIGHTS["A"][parts["A"]]

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0
    if scope_changed:
        raw = min(1.08 * (impact + exploitability), 10.0)
    else:
        raw = min(impact + exploitability, 10.0)
    # Round up to nearest tenth
    return _roundup(raw)


def _roundup(x: float) -> float:
    # CVSS v3.1 Roundup: round to one decimal place, always up
    return int(x * 10 + 0.99999) / 10 if x > 0 else 0.0


def _severity_band(score: float) -> str:
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"
