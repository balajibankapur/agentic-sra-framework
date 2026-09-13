"""Report Generator agent — SDD §2.5.

Writes each finalized SRA entry incrementally to draft.md + draft.json
per SRS-AGT-0005 (crash-safe partial output). In P5-B this uses the
deterministic renderer only; the LLM narrative-polish call lands in P5-F.
"""

from __future__ import annotations

import json
from pathlib import Path

from framework.agents.state import SRAState
from framework.sra.entry import SRAEntry


def run_report_generator(state: SRAState) -> dict:
    """Append state.pending_entry to the draft files. Returns partial state update."""
    if not state.pending_entry:
        return {}

    entry = SRAEntry.model_validate(state.pending_entry)

    _append_json(state.draft_json_path, entry)
    _append_md(state.draft_md_path, entry)

    return {
        "completed_entries": state.completed_entries + 1,
        "pending_entry": None,
    }


# ---------------------------------------------------------------------------
# Deterministic renderers (no LLM)


def _append_json(path: Path, entry: SRAEntry) -> None:
    """Maintain draft.json as a JSON array. Upserts by threat_id so a
    targeted re-run of a single threat replaces the earlier entry
    instead of duplicating it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(existing, list):
                existing = []
        except json.JSONDecodeError:
            existing = []
    else:
        existing = []
    dumped = entry.model_dump(mode="json")
    replaced = False
    for i, e in enumerate(existing):
        if isinstance(e, dict) and e.get("threat_id") == entry.threat_id:
            existing[i] = dumped
            replaced = True
            break
    if not replaced:
        existing.append(dumped)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def _append_md(path: Path, entry: SRAEntry) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(
            "# Security Risk Assessment — draft\n\n"
            "One entry per threat. Each entry carries CVSS v3.1 scoring, "
            "gap analysis against FDA / IEC / AAMI / NIST, and proposed doc + code changes.\n\n",
            encoding="utf-8",
        )
    body = _render_entry_md(entry)
    with path.open("a", encoding="utf-8") as f:
        f.write(body)


def _render_entry_md(e: SRAEntry) -> str:
    lines: list[str] = []
    lines.append(f"---\n\n## {e.threat_id} · {e.title}\n")
    lines.append(f"**STRIDE:** {e.stride}   **CVSS:** {e.cvss_v31.base_score:.1f} {e.cvss_v31.severity}   "
                 f"**Priority:** {e.priority}   **Effort:** {e.effort_engineer_weeks:g} eng-weeks\n")
    lines.append(f"**Residual risk:** {e.residual_risk} — {e.residual_risk_reason}\n")
    if e.narrative:
        lines.append(f"\n{e.narrative}\n")
    if e.existing_controls:
        lines.append("\n**Existing controls (legacy):**\n")
        for c in e.existing_controls:
            lines.append(f"- `{c.id}` — {c.description}\n")
    if e.gap_analysis:
        lines.append("\n**Gap analysis:**\n\n")
        lines.append("| Clause | Verdict | Reason |\n|---|---|---|\n")
        for g in e.gap_analysis:
            lines.append(f"| `{g.clause_id}` | **{g.verdict.upper()}** | {g.reason} |\n")
    if e.proposed_controls:
        lines.append("\n**Proposed controls:**\n")
        for c in e.proposed_controls:
            lines.append(f"- `{c.id}` — {c.description}\n")
    if e.proposed_doc_changes:
        lines.append("\n**Proposed doc changes:**\n")
        for d in e.proposed_doc_changes:
            lines.append(f"- {d.doc} · **{d.action}** `{d.item_id}` — {d.body}\n")
    if e.proposed_code_changes:
        lines.append("\n**Proposed code changes:**\n\n")
        for cc in e.proposed_code_changes:
            lines.append(f"`{cc.path}:{cc.line}` ({cc.action})\n")
            lines.append(f"```\n{cc.hunk}\n```\n")
    if e.warnings:
        lines.append(f"\n_warnings: {', '.join(e.warnings)}_\n")
    if e.parse_error:
        lines.append("\n> **PARSE ERROR** — raw LLM output preserved in JSON file.\n")
    lines.append("\n")
    return "".join(lines)
