"""Threat/Control/Risk agent — SDD §2.4.

STUB in P5-B — real implementation lands in P5-E. Produces a placeholder
SRAEntry per threat so the pipeline output is a real, schema-valid draft
file (with `parse_error: false` since the stub always constructs a valid
entry from the Pydantic model).
"""

from __future__ import annotations

import kuzu

from framework.agents.state import SRAState
from framework.config import KUZU_DIR
from framework.sra.entry import CVSS, SRAEntry


def run_threat_control_risk(state: SRAState) -> dict:
    """Return {'current_entry': SRAEntry} — Report Generator consumes it."""
    if not state.current_threat:
        return {}

    # Look up the threat in Kuzu so the stub entry carries real data.
    db_path = KUZU_DIR / f"{state.device}.kuzu"
    conn = kuzu.Connection(kuzu.Database(str(db_path)))
    res = conn.execute(
        "MATCH (t:Threat {id: $id}) RETURN t.title AS title, t.stride AS stride, t.priority AS priority;",
        parameters={"id": state.current_threat},
    )
    title = "(unknown threat)"
    stride = "T"
    priority = "Medium"
    if res.has_next():
        row = res.get_next()
        title = row[0] or title
        stride = (row[1] or "T")[0].upper()
        if stride not in {"S", "T", "R", "I", "D", "E"}:
            stride = "T"
        priority = row[2] or priority

    entry = SRAEntry(
        threat_id=state.current_threat,
        title=title[:120],
        stride=stride,
        assets_affected=[],
        existing_controls=[],
        gap_analysis=[],
        cvss_v31=CVSS(
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
            base_score=6.5,
            severity="Medium",
        ),
        residual_risk="Medium",
        residual_risk_reason="P5-B stub — no analysis performed yet.",
        proposed_controls=[],
        proposed_doc_changes=[],
        proposed_code_changes=[],
        priority="P1" if priority in ("High", "Critical") else "P2",
        effort_engineer_weeks=0.0,
        narrative="P5-B stub entry — real agent lands in P5-E.",
    )
    # LangGraph reducer merges dict updates; Report Generator consumes + clears.
    return {"pending_entry": entry.model_dump()}
