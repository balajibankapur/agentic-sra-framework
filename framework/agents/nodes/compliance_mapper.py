"""Compliance Mapper agent — SDD §2.2.

STUB in P5-B — real implementation lands in P5-C. Returns state unchanged
so the pipeline can be exercised end-to-end.
"""

from __future__ import annotations

from framework.agents.state import SRAState


def run_compliance_mapper(state: SRAState) -> dict:
    # P5-B stub: no findings produced.
    return {}
