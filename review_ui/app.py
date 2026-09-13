"""Streamlit review UI — SDD §7.

Reads:
  output/<device>_sra_draft.json          (source of truth from Report Gen)
  output/<device>_review_state.json       (overlay of reviewer decisions)

Writes:
  output/<device>_review_state.json       on every Approve/Edit/Reject/Defer

Launched by `sra review --device <name>`. Single-file app, one reviewer
at a time (hard constraint per Phase 3 decision — no file lock, just a
banner).

Environment:
  SRA_DEVICE   which device's draft to render (set by the CLI wrapper)
"""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# When Streamlit runs this file directly, review_ui isn't on sys.path.
# Add the repo root so we can import both framework.* and review_ui.*.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import streamlit as st

from framework.config import KUZU_DIR, OUTPUT_DIR
from review_ui import job_manager


DEVICE = os.environ.get("SRA_DEVICE", "pmx100")
DRAFT_JSON = OUTPUT_DIR / f"{DEVICE}_sra_draft.json"
STATE_JSON = OUTPUT_DIR / f"{DEVICE}_review_state.json"


# ---------------------------------------------------------------------------
# State I/O


def load_draft() -> list[dict]:
    if not DRAFT_JSON.exists():
        return []
    try:
        return json.loads(DRAFT_JSON.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


def load_review_state() -> dict:
    if not STATE_JSON.exists():
        return {"device": DEVICE, "reviewer_name": "", "decisions": {}}
    try:
        return json.loads(STATE_JSON.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"device": DEVICE, "reviewer_name": "", "decisions": {}}


def save_review_state(state: dict) -> None:
    STATE_JSON.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_JSON.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(STATE_JSON)


def record_decision(
    review_state: dict,
    threat_id: str,
    action: str,
    reason: str = "",
    edited_entry: dict | None = None,
) -> None:
    review_state["decisions"][threat_id] = {
        "action": action,
        "reason": reason,
        "edited_entry": edited_entry,
        "reviewer": review_state.get("reviewer_name") or "unknown",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    save_review_state(review_state)


# ---------------------------------------------------------------------------
# Ask-the-graph passthrough — read-only Cypher against Kuzu


_WRITE_RE = re.compile(
    r"\b(CREATE|MERGE|DELETE|SET|DROP|ALTER|COPY|INSERT|REMOVE|LOAD)\b",
    re.IGNORECASE,
)


def ask_graph(query: str) -> list[dict] | str:
    import kuzu
    if _WRITE_RE.search(query):
        return "Refused: query contains a write operation."
    db_path = KUZU_DIR / f"{DEVICE}.kuzu"
    if not db_path.exists():
        return f"Kuzu database not found at {db_path}. Run `sra index`."
    conn = kuzu.Connection(kuzu.Database(str(db_path)))
    try:
        res = conn.execute(query)
    except Exception as e:
        return f"Cypher error: {e}"
    cols = res.get_column_names()
    rows: list[dict] = []
    while res.has_next():
        row = res.get_next()
        rows.append({cols[i]: v for i, v in enumerate(row)})
    return rows


# ---------------------------------------------------------------------------
# Rendering


def render_header(entries: list[dict], review_state: dict) -> None:
    st.title(f"SRA Review — {DEVICE}")
    st.caption("**One reviewer at a time.** State persists to "
               f"`{STATE_JSON.name}` on every action.")

    reviewer = st.text_input(
        "Reviewer name (recorded in provenance):",
        value=review_state.get("reviewer_name", ""),
        key="reviewer_name_input",
    )
    if reviewer != review_state.get("reviewer_name", ""):
        review_state["reviewer_name"] = reviewer
        save_review_state(review_state)

    # Progress summary
    decisions = review_state.get("decisions", {})
    from collections import Counter
    by_action = Counter(d.get("action", "pending") for d in decisions.values())
    reviewed = len(decisions)
    total = len(entries)

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total", total)
    col2.metric("Reviewed", reviewed)
    col3.metric("Approved", by_action.get("approved", 0) + by_action.get("edited", 0))
    col4.metric("Rejected", by_action.get("rejected", 0))
    col5.metric("Deferred", by_action.get("deferred", 0))
    st.progress(reviewed / total if total else 0.0)


def render_entry_card(
    entry: dict,
    review_state: dict,
    idx: int,
) -> None:
    tid = entry["threat_id"]
    decision = review_state.get("decisions", {}).get(tid, {}) or {}
    action = decision.get("action", "pending")

    # Status label prefix
    status_emoji = {
        "approved": "✅",
        "edited": "✏️",
        "rejected": "❌",
        "deferred": "⏸️",
        "pending": "⚪",
    }.get(action, "⚪")

    cvss = entry.get("cvss_v31") or {}
    header = (
        f"{status_emoji} **{tid}** — {entry.get('title', '')[:70]}   "
        f"· STRIDE {entry.get('stride', '?')}   "
        f"· CVSS {cvss.get('base_score', 0)} {cvss.get('severity', '')}   "
        f"· {entry.get('priority', '')}"
    )
    with st.expander(header, expanded=(action == "pending" and idx < 3)):
        _render_entry_body(entry, review_state, decision)


def _render_entry_body(entry: dict, review_state: dict, decision: dict) -> None:
    tid = entry["threat_id"]

    if entry.get("parse_error"):
        st.warning("⚠️ This entry failed guardrails during drafting. "
                   "Review the raw LLM response below and edit if needed.")

    edit_mode = st.session_state.get(f"edit_{tid}", False)

    if edit_mode:
        _render_edit_form(entry, review_state)
        return

    # Read-only view
    st.markdown(f"**Narrative.** {entry.get('narrative', '_(none)_')}")
    st.markdown(f"**Residual risk:** {entry.get('residual_risk', '?')} — "
                f"{entry.get('residual_risk_reason', '')}")
    st.markdown(f"**Effort:** {entry.get('effort_engineer_weeks', 0):g} eng-weeks")

    # Existing controls
    if entry.get("existing_controls"):
        st.markdown("**Existing controls (legacy):**")
        for c in entry["existing_controls"]:
            st.markdown(f"- `{c.get('id', '?')}` — {c.get('description', '')}")

    # Gap analysis
    if entry.get("gap_analysis"):
        st.markdown("**Gap analysis:**")
        rows = [{
            "Clause": g.get("clause_id", ""),
            "Verdict": g.get("verdict", ""),
            "Reason": g.get("reason", ""),
        } for g in entry["gap_analysis"]]
        st.dataframe(rows, hide_index=True, width="stretch")

    # Proposed controls
    if entry.get("proposed_controls"):
        st.markdown("**Proposed controls:**")
        for c in entry["proposed_controls"]:
            st.markdown(f"- `{c.get('id', '?')}` — {c.get('description', '')}")

    # Proposed doc changes
    if entry.get("proposed_doc_changes"):
        st.markdown("**Proposed doc changes:**")
        for d in entry["proposed_doc_changes"]:
            st.markdown(f"- **{d.get('doc', '?')}** · {d.get('action', '?')} · "
                        f"`{d.get('item_id', '?')}` — {d.get('body', '')}")

    # Proposed code changes
    if entry.get("proposed_code_changes"):
        st.markdown("**Proposed code changes:**")
        for c in entry["proposed_code_changes"]:
            st.code(
                f"# {c.get('path', '?')}:{c.get('line', 0)}  ({c.get('action', '')})\n"
                + c.get("hunk", ""),
                language="c",
            )

    # Warnings
    if entry.get("warnings"):
        with st.expander(f"Warnings ({len(entry['warnings'])})"):
            for w in entry["warnings"]:
                st.text(w)

    # Raw LLM response (parse_error cases)
    if entry.get("raw_llm_response"):
        with st.expander("Raw LLM response (parse_error diagnostic)"):
            st.code(entry["raw_llm_response"][:6000], language="json")

    # If already decided, show meta + let reviewer change their mind
    if decision.get("action") not in {None, "pending"}:
        st.info(
            f"**Decision:** {decision['action']} by {decision.get('reviewer', '?')} "
            f"at {decision.get('timestamp_utc', '?')}"
            + (f" — reason: {decision['reason']}" if decision.get("reason") else "")
        )

    # Action buttons
    b1, b2, b3, b4, b5 = st.columns(5)
    if b1.button("✅ Approve", key=f"approve_{tid}"):
        record_decision(review_state, tid, "approved")
        st.rerun()
    if b2.button("✏️ Edit", key=f"edit_btn_{tid}"):
        st.session_state[f"edit_{tid}"] = True
        st.rerun()
    if b3.button("❌ Reject", key=f"reject_btn_{tid}"):
        st.session_state[f"reject_prompt_{tid}"] = True
        st.rerun()
    if b4.button("⏸️ Defer", key=f"defer_{tid}"):
        record_decision(review_state, tid, "deferred")
        st.rerun()
    if b5.button("🔍 Ask graph", key=f"ask_{tid}"):
        st.session_state[f"ask_prompt_{tid}"] = True
        st.rerun()

    # Rejection prompt
    if st.session_state.get(f"reject_prompt_{tid}"):
        reason = st.text_input(
            "Rejection reason (required):",
            key=f"reject_reason_{tid}",
        )
        c1, c2 = st.columns(2)
        if c1.button("Confirm rejection", key=f"reject_confirm_{tid}"):
            if not reason.strip():
                st.error("Reason required.")
            else:
                record_decision(review_state, tid, "rejected", reason=reason.strip())
                st.session_state[f"reject_prompt_{tid}"] = False
                st.rerun()
        if c2.button("Cancel", key=f"reject_cancel_{tid}"):
            st.session_state[f"reject_prompt_{tid}"] = False
            st.rerun()

    # Ask-the-graph prompt
    if st.session_state.get(f"ask_prompt_{tid}"):
        default_q = (
            f"MATCH (t:Threat {{id: '{tid}'}})-[:APPLIES_TO]->(d:DFDElement) "
            f"RETURN d.id, d.kind LIMIT 5;"
        )
        q = st.text_area("Cypher (read-only):", value=default_q, key=f"cypher_{tid}", height=80)
        c1, c2 = st.columns(2)
        if c1.button("Run", key=f"cypher_run_{tid}"):
            result = ask_graph(q)
            if isinstance(result, str):
                st.error(result)
            else:
                st.dataframe(result, hide_index=True, width="stretch")
        if c2.button("Close", key=f"cypher_close_{tid}"):
            st.session_state[f"ask_prompt_{tid}"] = False
            st.rerun()


def _render_edit_form(entry: dict, review_state: dict) -> None:
    tid = entry["threat_id"]
    st.markdown("### Editing entry — save changes below")

    title = st.text_input("Title", value=entry.get("title", ""), key=f"e_title_{tid}")
    narrative = st.text_area("Narrative", value=entry.get("narrative", ""),
                             key=f"e_narrative_{tid}", height=100)
    priority = st.selectbox("Priority", ["P0", "P1", "P2"],
                             index=["P0", "P1", "P2"].index(entry.get("priority", "P2")),
                             key=f"e_priority_{tid}")
    residual = st.selectbox("Residual risk", ["High", "Medium", "Low"],
                             index=["High", "Medium", "Low"].index(entry.get("residual_risk", "Medium")),
                             key=f"e_residual_{tid}")
    residual_reason = st.text_input("Residual risk reason",
                                     value=entry.get("residual_risk_reason", ""),
                                     key=f"e_residual_reason_{tid}")
    effort = st.number_input("Effort (engineer-weeks)",
                              value=float(entry.get("effort_engineer_weeks", 0.0)),
                              step=0.5, key=f"e_effort_{tid}")

    # Full JSON edit for advanced fields
    full = st.text_area(
        "Full entry JSON (advanced — edit any of the 12 fields):",
        value=json.dumps(entry, indent=2, ensure_ascii=False),
        height=350,
        key=f"e_full_{tid}",
    )

    c1, c2 = st.columns(2)
    if c1.button("💾 Save edits", key=f"save_{tid}"):
        try:
            edited = json.loads(full)
            # Overlay the top-level scalar fields the reviewer set via UI
            edited["title"] = title
            edited["narrative"] = narrative
            edited["priority"] = priority
            edited["residual_risk"] = residual
            edited["residual_risk_reason"] = residual_reason
            edited["effort_engineer_weeks"] = float(effort)
            record_decision(review_state, tid, "edited", edited_entry=edited)
            st.session_state[f"edit_{tid}"] = False
            st.rerun()
        except json.JSONDecodeError as e:
            st.error(f"JSON parse error: {e}")
    if c2.button("Cancel", key=f"cancel_edit_{tid}"):
        st.session_state[f"edit_{tid}"] = False
        st.rerun()


# ---------------------------------------------------------------------------
# Main


def main() -> None:
    st.set_page_config(page_title=f"SRA Review — {DEVICE}", layout="wide")

    entries = load_draft()
    review_state = load_review_state()

    if not entries:
        st.title(f"SRA Review — {DEVICE}")
        st.warning(
            f"**No draft yet.**  Use the *Analysis Control* block in the sidebar "
            f"to start a draft — or run `sra draft --device {DEVICE}` in a terminal."
        )
        _render_progress_banner()
        _render_job_control_sidebar()
        _render_reset_sidebar()
        return

    _render_progress_banner()
    render_header(entries, review_state)

    # Sidebar filters
    st.sidebar.header("Filters")
    sort_by = st.sidebar.selectbox("Sort by",
                                    ["Priority + threat id", "Threat id (A→Z)", "CVSS score (high→low)"])
    show_only = st.sidebar.selectbox("Show",
                                      ["All", "Pending only", "Approved", "Rejected", "Deferred", "Parse errors"])
    page_size = st.sidebar.slider("Entries per page", min_value=10, max_value=100,
                                   value=25, step=5)

    # If the filter combo changed, reset to page 0.
    filter_key = f"{sort_by}|{show_only}|{page_size}"
    if st.session_state.get("_filter_key") != filter_key:
        st.session_state["_filter_key"] = filter_key
        st.session_state["_page"] = 0

    # Sidebar — job control + actions
    _render_job_control_sidebar()
    st.sidebar.divider()
    st.sidebar.header("Actions")
    if st.sidebar.button("📤 Export final artifacts", width="stretch"):
        _run_export_ui(review_state)
    _render_reset_sidebar()

    # Apply filters
    def _keep(e: dict) -> bool:
        a = review_state.get("decisions", {}).get(e["threat_id"], {}).get("action", "pending")
        if show_only == "All":
            return True
        if show_only == "Pending only":
            return a == "pending"
        if show_only == "Approved":
            return a in {"approved", "edited"}
        if show_only == "Rejected":
            return a == "rejected"
        if show_only == "Deferred":
            return a == "deferred"
        if show_only == "Parse errors":
            return bool(e.get("parse_error"))
        return True

    display = [e for e in entries if _keep(e)]

    # Apply sort
    if sort_by == "Threat id (A→Z)":
        display.sort(key=lambda e: e["threat_id"])
    elif sort_by == "CVSS score (high→low)":
        display.sort(key=lambda e: -(e.get("cvss_v31") or {}).get("base_score", 0))
    else:  # Priority + threat id
        priority_rank = {"P0": 0, "P1": 1, "P2": 2}
        display.sort(key=lambda e: (priority_rank.get(e.get("priority", "P2"), 3), e["threat_id"]))

    # Pagination
    total_display = len(display)
    total_pages = max(1, (total_display + page_size - 1) // page_size)
    current_page = min(st.session_state.get("_page", 0), total_pages - 1)
    st.session_state["_page"] = current_page
    start = current_page * page_size
    end = min(start + page_size, total_display)
    page_items = display[start:end]

    st.markdown(
        f"### {total_display} entries after filter "
        f"({len(entries)} total)   ·   showing {start + 1}-{end}   ·   "
        f"page {current_page + 1} of {total_pages}"
    )

    # Bulk action bar — approve all pending on this page
    pending_on_page = [
        e for e in page_items
        if review_state.get("decisions", {}).get(e["threat_id"], {}).get("action", "pending") == "pending"
    ]
    if pending_on_page:
        col_bulk, col_note = st.columns([1, 3])
        with col_bulk:
            if st.button(
                f"✅ Approve all {len(pending_on_page)} pending on this page",
                key=f"bulk_approve_{current_page}",
                width="stretch",
            ):
                for e in pending_on_page:
                    record_decision(review_state, e["threat_id"], "approved")
                st.rerun()
        with col_note:
            st.caption(
                "_Only pending entries on the current page are approved. "
                "Use the Show filter + a larger page size to scope wider._"
            )

    # Render page
    for i, e in enumerate(page_items):
        render_entry_card(e, review_state, i)

    # Pagination controls
    if total_pages > 1:
        st.divider()
        col_prev, col_mid, col_next = st.columns([1, 3, 1])
        with col_prev:
            if st.button("◀ Prev", disabled=(current_page == 0), width="stretch"):
                st.session_state["_page"] = max(0, current_page - 1)
                st.rerun()
        with col_mid:
            new_page = st.number_input(
                "Jump to page",
                min_value=1,
                max_value=total_pages,
                value=current_page + 1,
                step=1,
                label_visibility="collapsed",
            )
            if new_page - 1 != current_page:
                st.session_state["_page"] = int(new_page) - 1
                st.rerun()
        with col_next:
            if st.button("Next ▶", disabled=(current_page >= total_pages - 1), width="stretch"):
                st.session_state["_page"] = min(total_pages - 1, current_page + 1)
                st.rerun()


def _render_job_control_sidebar() -> None:
    """Sidebar Analysis Control block — Start / Stop / status of a draft run."""
    st.sidebar.divider()
    st.sidebar.header("Analysis Control")

    job_status = job_manager.status(DEVICE)

    if job_status.alive:
        st.sidebar.info(
            f"⚙️ **Draft running** (pid {job_status.pid})\n\n"
            f"profile: `{job_status.profile}`  ·  "
            f"limit: {job_status.limit or 'all'}\n\n"
            f"entries: **{job_status.entries_done}** / "
            f"{job_status.limit or '?'}   ·   "
            f"turns: {job_status.llm_turns}   ·   "
            f"est. cost: ${job_status.cost_usd_est:.4f}"
        )
        if st.sidebar.button("⏹ Stop draft", width="stretch", type="primary"):
            job_manager.stop_draft(DEVICE)
            st.sidebar.warning("SIGTERM sent. Reloading …")
            st.rerun()
        if st.sidebar.button("🔄 Refresh status", width="stretch"):
            st.rerun()
    else:
        with st.sidebar.form("start_draft_form", clear_on_submit=False):
            st.markdown("**Start a new draft**")
            profile = st.selectbox(
                "Profile",
                ["hybrid", "free", "openai"],
                index=0,
                help="hybrid = free tier for 4 agents + OpenAI for the TCR agent",
            )
            limit_val = st.number_input(
                "Threat limit (0 = all)",
                min_value=0, max_value=500, value=10, step=5,
                help="0 processes every threat in the graph",
            )
            category = st.text_input("Category filter (optional)",
                                      value="",
                                      help="e.g. OTA, BLE, EMR — leave blank for all")
            submitted = st.form_submit_button("▶ Start draft", width="stretch",
                                               type="primary")
            if submitted:
                try:
                    job_manager.start_draft(
                        DEVICE,
                        profile=profile,
                        limit=(int(limit_val) or None),
                        category=(category.strip() or None),
                    )
                    st.sidebar.success("Draft started in background.")
                    st.rerun()
                except Exception as e:
                    st.sidebar.error(f"Start failed: {e}")


def _render_reset_sidebar() -> None:
    """Sidebar Reset block — three levels of scope, confirmation required."""
    st.sidebar.divider()
    st.sidebar.header("Reset")

    if job_manager.is_running(DEVICE):
        st.sidebar.caption("_(disabled while a draft is running)_")
        return

    scope = st.sidebar.radio(
        "Scope",
        ["Draft + review only", "…also indices", "…also cloned corpus"],
        index=0,
        help=(
            "Draft + review only: wipe draft, prompts, review state, final artifacts.\n"
            "…also indices: additionally drop Chroma + Kuzu + JSON extracts (needs `sra index` after).\n"
            "…also cloned corpus: additionally drop input/<device>/ (needs `sra init` after)."
        ),
    )
    confirm = st.sidebar.checkbox("I'm sure — delete the listed files")
    if st.sidebar.button("🗑 Reset", width="stretch", disabled=not confirm):
        deleted = job_manager.reset(
            DEVICE,
            include_indices=(scope == "…also indices" or scope == "…also cloned corpus"),
            include_corpus=(scope == "…also cloned corpus"),
        )
        st.sidebar.success(f"Deleted {len(deleted)} items.")
        # Reset in-session UI state so a stale page render doesn't linger
        for k in list(st.session_state.keys()):
            del st.session_state[k]
        st.rerun()


def _render_progress_banner() -> None:
    """Top-of-page banner shown while a draft job is running."""
    js = job_manager.status(DEVICE)
    if not js.alive:
        return
    limit = js.limit or 1
    frac = min(1.0, js.entries_done / limit) if limit else 0.0
    st.info(
        f"⚙️  **Draft running** — {js.entries_done} / {js.limit or '?'} entries · "
        f"{js.llm_turns} LLM turns · est. cost ${js.cost_usd_est:.4f}   "
        f"_(click **Refresh status** in the sidebar to update; the page won't auto-refresh)_"
    )
    if js.limit:
        st.progress(frac)


def _run_export_ui(review_state: dict) -> None:
    """Trigger sra export from within the UI and surface the result."""
    from framework.config import OUTPUT_DIR
    from framework.sra.export import run_export

    with st.spinner("Rendering MD + PDF + DOCX + provenance …"):
        try:
            run_export(device=DEVICE, profile="hybrid")
        except Exception as e:
            st.sidebar.error(f"Export failed: {e}")
            return
    st.sidebar.success("Exported. Files:")
    for name in (f"{DEVICE}_sra_final.md", f"{DEVICE}_sra_final.pdf",
                 f"{DEVICE}_sra_final.docx", f"{DEVICE}_provenance.json"):
        p = OUTPUT_DIR / name
        if p.exists():
            st.sidebar.markdown(f"- `{p.name}` ({p.stat().st_size:,} B)")


main()
