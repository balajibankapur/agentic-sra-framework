"""Dequeue node — pops the next threat id from the queue into current_threat.

Routes to END via a conditional edge when the queue is empty.
"""

from __future__ import annotations

from framework.agents.state import SRAState


def run_dequeue(state: SRAState) -> dict:
    if not state.threat_queue:
        return {"current_threat": None}
    next_id = state.threat_queue[0]
    return {
        "current_threat": next_id,
        "threat_queue": state.threat_queue[1:],
        # reset per-threat findings
        "compliance_findings": [],
        "code_findings": [],
        # Reset per-threat warnings too. `warnings` has no LangGraph reducer,
        # so each node's return replaces it; upstream nodes accumulate onto
        # the list explicitly and Threat/Control/Risk copies the result onto
        # the SRA entry, so the reviewer sees why a section is missing.
        "warnings": [],
    }
