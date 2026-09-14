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
PROMPTS_JSONL = OUTPUT_DIR / f"{DEVICE}_prompts.jsonl"


AGENT_ORDER = [
    "ingestion",
    "compliance_mapper",
    "code_analysis:planner",
    "code_analysis:interpreter",
    "threat_control_risk",
    "report_generator",
]

# Tool name -> (which MCP server it's wrapped by, which backend it actually hits)
TOOL_BACKEND: dict[str, tuple[str, str]] = {
    "vector.search":     ("corpus-vector",   "Chroma vector DB (device_docs / device_code / regulatory collections)"),
    "vector.get_chunk":  ("corpus-vector",   "Chroma vector DB"),
    "graph.cypher":      ("corpus-graph",    "Kuzu property graph (2181 nodes / 1636 edges)"),
    "graph.neighbors":   ("corpus-graph",    "Kuzu property graph"),
    "graph.path":        ("corpus-graph",    "Kuzu property graph"),
    "files.read":        ("corpus-files",    "Filesystem — input/<device>/ (140 files, 9.7 MB)"),
    "files.grep":        ("corpus-files",    "Filesystem — regex over firmware/**/*.[ch]"),
    "files.list_dir":    ("corpus-files",    "Filesystem"),
}


def _tool_backend(tool_name: str) -> tuple[str, str]:
    """Return (mcp_server_name, backend_description) for a tool."""
    return TOOL_BACKEND.get(tool_name, ("(unknown)", "(unknown backend)"))


def load_prompt_log() -> list[dict]:
    """Read every LLM turn from <device>_prompts.jsonl."""
    if not PROMPTS_JSONL.exists():
        return []
    turns: list[dict] = []
    for line in PROMPTS_JSONL.open("r", encoding="utf-8", errors="ignore"):
        line = line.strip()
        if not line:
            continue
        try:
            turns.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return turns


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

    # Agent trace — which LLM turns produced this entry
    with st.expander("🔍 Agent trace"):
        _render_entry_agent_trace(tid)

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
    b1, b2, b3, b4, b5, b6 = st.columns(6)
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
    rerun_disabled = job_manager.is_running(DEVICE)
    if b6.button("🔁 Rerun", key=f"rerun_btn_{tid}", disabled=rerun_disabled,
                 help=("Re-draft just this entry with additional reviewer context "
                       "appended to the TCR agent's prompt.")):
        st.session_state[f"rerun_prompt_{tid}"] = True
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

    # Rerun-with-extra-context prompt
    if st.session_state.get(f"rerun_prompt_{tid}"):
        st.markdown("**Rerun this entry with additional context**")
        st.caption(
            "The text below is appended to the Threat/Control/Risk agent's user "
            "message for this single re-run. Use it to tell the agent about a "
            "constraint it missed, a design choice you want reflected, or a "
            "specific control to consider. The draft entry will be replaced "
            "(upserted by threat_id), prompts.jsonl gets a new turn appended, "
            "and any prior review decision for this entry is cleared."
        )
        extra = st.text_area(
            "Additional context / instructions",
            value=st.session_state.get(f"rerun_extra_{tid}", ""),
            key=f"rerun_extra_input_{tid}",
            height=120,
            placeholder="e.g. Consider that firmware/app_mcu/ble/ble_pairing.c already "
                        "wraps the mbedtls pairing API, so propose the diff at line 45 "
                        "rather than a new file.",
        )
        profile = st.selectbox(
            "Profile",
            ["hybrid", "free", "openai"],
            index=0,
            key=f"rerun_profile_{tid}",
        )
        st.caption(
            "_On `free` or `hybrid`, Gemini/Groq handle most agents. If those "
            "rate-limit or 503, the LLM Router automatically falls back to "
            "OpenAI `gpt-4o-mini` (recorded in the provenance file). The star "
            "agent (Threat/Control/Risk) always uses `gpt-4o` on hybrid+openai._"
        )
        c1, c2 = st.columns(2)
        if c1.button("▶ Start rerun", key=f"rerun_go_{tid}", type="primary"):
            if not extra.strip():
                st.error("Please provide some additional context, or Cancel.")
            else:
                try:
                    job_manager.start_draft(
                        DEVICE,
                        profile=profile,
                        threat=tid,
                        extra_context=extra.strip(),
                    )
                    st.session_state[f"rerun_prompt_{tid}"] = False
                    st.session_state[f"rerun_extra_{tid}"] = ""
                    st.success(f"Rerun of {tid} started in background.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Start failed: {e}")
        if c2.button("Cancel", key=f"rerun_cancel_{tid}"):
            st.session_state[f"rerun_prompt_{tid}"] = False
            st.session_state[f"rerun_extra_{tid}"] = ""
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

    # Sidebar filters (always visible regardless of active tab)
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

    # Main area: two tabs — reviewer workflow + agent activity log
    tab_review, tab_agents = st.tabs(["📋 Review", "🔍 Agent Activity"])
    with tab_agents:
        render_agent_activity_tab()
    with tab_review:
        _render_review_body(entries, review_state, sort_by, show_only, page_size)


def _render_review_body(
    entries: list[dict],
    review_state: dict,
    sort_by: str,
    show_only: str,
    page_size: int,
) -> None:
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


@st.fragment(run_every=3)
def _render_job_status_sidebar_fragment() -> None:
    """Auto-refreshing sidebar status panel while a draft is running."""
    job_status = job_manager.status(DEVICE)
    if job_status.alive:
        st.info(
            f"⚙️ **Draft running** (pid {job_status.pid})\n\n"
            f"profile: `{job_status.profile}`  ·  "
            f"limit: {job_status.limit or 'all'}\n\n"
            f"entries: **{job_status.entries_done}** / "
            f"{job_status.limit or '?'}   ·   "
            f"turns: {job_status.llm_turns}   ·   "
            f"est. cost: ${job_status.cost_usd_est:.4f}"
        )
        if st.button("⏹ Stop draft", width="stretch", type="primary",
                      key="stop_draft_frag"):
            job_manager.stop_draft(DEVICE)
            st.rerun(scope="app")


def _render_job_control_sidebar() -> None:
    """Sidebar Analysis Control block — Start / Stop / status of a draft run."""
    st.sidebar.divider()
    st.sidebar.header("Analysis Control")

    job_status = job_manager.status(DEVICE)

    if job_status.alive:
        with st.sidebar:
            _render_job_status_sidebar_fragment()
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
            strategy = st.selectbox(
                "Ingestion strategy",
                ["priority", "code-linked"],
                index=0,
                help=(
                    "priority (default): order threats by priority band, "
                    "then id. Best for full 225-threat runs.\n\n"
                    "code-linked: round-robin across the subsystems where "
                    "seeded VULNs live (ble/ota/emr/spi/…). Best for a small "
                    "pilot (limit 25–50) where you want to exercise VULN recall."
                ),
            )
            submitted = st.form_submit_button("▶ Start draft", width="stretch",
                                               type="primary")
            if submitted:
                try:
                    job_manager.start_draft(
                        DEVICE,
                        profile=profile,
                        limit=(int(limit_val) or None),
                        category=(category.strip() or None),
                        strategy=strategy,
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


@st.fragment(run_every=3)
def _render_progress_banner() -> None:
    """Top-of-page banner. Auto-refreshes every 3 s via st.fragment while
    a draft is running. When the job transitions running -> not-running,
    triggers a full-page rerun so newly-drafted entries appear."""
    js = job_manager.status(DEVICE)
    prev_alive = st.session_state.get("_prev_job_alive", False)

    if js.alive:
        st.session_state["_prev_job_alive"] = True
        limit = js.limit or 1
        frac = min(1.0, js.entries_done / limit) if limit else 0.0
        st.info(
            f"⚙️  **Draft running** — {js.entries_done} / {js.limit or '?'} entries · "
            f"{js.llm_turns} LLM turns · est. cost ${js.cost_usd_est:.4f}   "
            f"_(auto-refreshing every 3 s)_"
        )
        if js.limit:
            st.progress(frac)
    elif prev_alive:
        # Job just finished — full-page rerun so entry cards appear
        st.session_state["_prev_job_alive"] = False
        st.success(
            f"✅  **Draft complete** — {js.entries_done} entries · "
            f"{js.llm_turns} LLM turns · total cost ${js.cost_usd_est:.4f}"
        )
        st.rerun(scope="app")


def render_agent_activity_tab() -> None:
    """Log viewer over <device>_prompts.jsonl — every LLM turn, per-agent,
    per-entry, with expandable full detail for demonstrating what the
    agents actually did."""
    _render_pipeline_overview()

    turns = load_prompt_log()

    if not turns:
        st.info(
            "No agent activity yet — start a draft (**Analysis Control** in the sidebar) "
            "to see live LLM turns here."
        )
        return

    # -- Summary cards --------------------------------------------------------
    from collections import Counter
    by_agent = Counter(t.get("agent", "?") for t in turns)
    by_model = Counter(t.get("model", "?") for t in turns)
    total_cost = sum(float(t.get("cost_usd_est", 0.0)) for t in turns)
    total_in = sum(int(t.get("tokens_in", 0)) for t in turns)
    total_out = sum(int(t.get("tokens_out", 0)) for t in turns)
    errors = sum(1 for t in turns if t.get("error"))
    fallbacks = sum(1 for t in turns if t.get("fallback_used"))

    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Total LLM turns", len(turns))
    m2.metric("Tokens in / out", f"{total_in:,} / {total_out:,}")
    m3.metric("Est. cost", f"${total_cost:.4f}")
    m4.metric("Errors (retried)", errors)
    m5.metric("Fallbacks used", fallbacks)

    with st.expander("Breakdown by agent + model", expanded=True):
        col_a, col_m = st.columns(2)
        with col_a:
            st.markdown("**By agent**")
            for a, n in sorted(by_agent.items(), key=lambda x: -x[1]):
                st.markdown(f"- `{a}` — {n} turns")
        with col_m:
            st.markdown("**By model**")
            for m, n in sorted(by_model.items(), key=lambda x: -x[1]):
                cost_m = sum(float(t.get("cost_usd_est", 0.0)) for t in turns if t.get("model") == m)
                st.markdown(f"- `{m}` — {n} turns  (${cost_m:.4f})")
    st.caption(
        "_Only agents that call an LLM appear above. `ingestion` runs a "
        "deterministic Cypher query and `report_generator` writes files "
        "deterministically — neither produces LLM turns. That's a Phase 4 "
        "design decision to keep the free-profile cost at $0 and drafting "
        "deterministic where reasoning isn't needed._"
    )

    # -- Filters --------------------------------------------------------------
    st.divider()
    st.markdown("### Turn log")

    f1, f2, f3 = st.columns([2, 2, 1])
    agents_seen = sorted({t.get("agent", "?") for t in turns})
    with f1:
        agent_pick = st.selectbox("Filter by agent", ["All"] + agents_seen, index=0)
    entries_seen = sorted({t.get("entry_id", "") for t in turns if t.get("entry_id")})
    with f2:
        entry_pick = st.selectbox("Filter by threat", ["All"] + entries_seen, index=0)
    with f3:
        show_errors = st.checkbox("Errors only", value=False)

    def _keep_turn(t: dict) -> bool:
        if agent_pick != "All" and t.get("agent") != agent_pick:
            return False
        if entry_pick != "All" and t.get("entry_id") != entry_pick:
            return False
        if show_errors and not t.get("error"):
            return False
        return True

    filtered = [t for t in turns if _keep_turn(t)]
    st.caption(f"{len(filtered)} of {len(turns)} turns")

    for i, t in enumerate(filtered):
        _render_turn_card(t, i)


def _render_pipeline_overview() -> None:
    """Static top-of-tab explainer: what each agent does, which tools it
    calls, which backend those tools hit. Answers 'how did the agents
    actually get the answer?'"""
    with st.expander("📐 Pipeline overview — what each agent does and which databases it hits",
                     expanded=False):
        st.markdown("""
The pipeline runs as a **LangGraph state machine** — one LangGraph node per agent,
threats fed through in a loop:

```
Kuzu graph                      START → ingestion → dequeue ─┐
   ▲                                                         ▼
   │ Cypher                                          compliance_mapper
   │                                                         ▼
   ├──────────────────── graph.cypher ───────────      code_analysis
   │                                                     :planner
   │                                                         ▼
   │                                                     grep firmware
   │                                                         ▼
   │                                                    code_analysis
   │                                                     :interpreter
   │                                                         ▼
   │                                              threat_control_risk ⭐
   │                                                         ▼
   │                                                 report_generator
Chroma vector DB                                             ▼
   ▲                                                      dequeue ────┐
   │ semantic search                                         ▼        │
   ├── vector.search ───── (device_docs, device_code,     empty? END  │
   │                        regulatory collections)          │        │
Filesystem                                              loop back ────┘
   ▲
   │ read + grep
   └── files.read / files.grep ──── firmware/**/*.[ch] + docs
```

**Every store access goes through an MCP tool**, so the agent code is backend-agnostic
(you could swap Kuzu → Neo4j or Chroma → Qdrant without touching agents).
""")

        st.markdown("**Which agent hits which database:**")
        st.markdown(
            "| Agent | LLM? | MCP tools it calls | Backend that answers |\n"
            "|---|---|---|---|\n"
            "| `ingestion` | ❌ no | (direct Cypher; MCP-equivalent: `graph.cypher`) | **Kuzu** — one query enumerating all threats, ordered per `--strategy` |\n"
            "| `compliance_mapper` | ✅ yes | `graph.cypher` × 2, then `vector.search` | **Kuzu** for threat + linked controls; **Chroma `regulatory` collection** for FDA/IEC/AAMI/NIST clauses |\n"
            "| `code_analysis:planner` | ✅ yes | *(none — reads compliance findings)* | *(none)* |\n"
            "| Python (between planner + interpreter) | — | `files.grep` × N | **Filesystem** — regex over `firmware/**/*.[ch]` |\n"
            "| `code_analysis:interpreter` | ✅ yes | *(reads grep results from state)* | *(none)* |\n"
            "| `threat_control_risk` ⭐ | ✅ yes (`gpt-4o`) | `graph.cypher` × 4-5, `vector.get_chunk` × N | **Kuzu** for threat/controls/CodeArtifacts/known IDs; **Chroma** for clause-body substring verify |\n"
            "| `report_generator` | ❌ no | *(direct file writes)* | **Local disk** — upserts `output/<device>_sra_draft.{md,json}` |"
        )

        st.markdown("**MCP servers ↔ backends:**")
        st.markdown(
            "| MCP server | Wraps | Tools exposed | Guardrails at this layer |\n"
            "|---|---|---|---|\n"
            "| `corpus-vector` | Chroma persistent client at `stores/chroma/` | `search`, `get_chunk`, `list_collections` | — |\n"
            "| `corpus-graph` | Kuzu embedded DB at `stores/kuzu/<device>.kuzu` | `cypher`, `neighbors`, `path`, `list_schema` | **Read-only** — refuses CREATE/MERGE/DELETE/SET/DROP/ALTER/COPY/INSERT/REMOVE/LOAD |\n"
            "| `corpus-files` | Local filesystem rooted at `input/<device>/` | `read`, `list_dir`, `grep` | **Path-traversal safe** — refuses paths that escape the device root; read cap 200 KB per call |"
        )
        st.caption(
            "_The MCP servers are also runnable standalone (`sra mcp {vector\\|graph\\|files}`) "
            "so Claude Code, Cursor, or any MCP client can query the corpus with the same tool contract._"
        )


def _render_turn_card(t: dict, idx: int) -> None:
    ok = "❌" if t.get("error") else "✅"
    fb = " · ⚡fallback" if t.get("fallback_used") else ""
    header = (
        f"{ok} **{t.get('agent','?')}**  ·  `{t.get('model','?')}`  "
        f"·  entry `{t.get('entry_id','?')}`  ·  "
        f"tokens {t.get('tokens_in',0):,}/{t.get('tokens_out',0):,}  ·  "
        f"{t.get('latency_ms',0)}ms  ·  ${t.get('cost_usd_est',0):.5f}{fb}"
    )
    with st.expander(header, expanded=False):
        st.caption(
            f"timestamp: `{t.get('timestamp_utc','?')}`  ·  "
            f"prompt_version: `{t.get('prompt_version','?')}`  ·  "
            f"prompt_hash: `{t.get('prompt_hash','?')}`"
        )
        if t.get("error"):
            st.error(f"**error:** {t['error'][:600]}")
            if t.get("fallback_used"):
                st.info(f"Fell back to: `{t['fallback_used']}`")
        tab_prompt, tab_response, tab_tools = st.tabs(["📤 Prompt", "📥 Response", "🛠 Tool calls"])
        with tab_prompt:
            prompt = t.get("prompt", {}) or {}
            st.markdown("**System prompt**")
            st.code(prompt.get("system", "")[:8000] if isinstance(prompt, dict) else str(prompt)[:8000],
                    language="markdown")
            st.markdown("**User message**")
            st.code(prompt.get("user", "")[:8000] if isinstance(prompt, dict) else "", language="markdown")
        with tab_response:
            response = t.get("response", "")
            if response:
                # Try pretty-print if JSON
                try:
                    parsed = json.loads(response)
                    st.json(parsed)
                except (json.JSONDecodeError, TypeError):
                    st.code(response[:12000], language="text")
            else:
                st.caption("_(empty response)_")
        with tab_tools:
            tool_calls = t.get("tool_calls", []) or []
            if not tool_calls:
                st.caption(
                    "_(no tool calls recorded before this LLM turn — some agents "
                    "read only from state populated by an earlier agent)_"
                )
            else:
                st.caption(
                    f"**{len(tool_calls)} MCP tool call(s) made before this LLM "
                    f"turn.** Each call goes through an MCP tool wrapper (same "
                    f"contract external clients like Claude Code would use)."
                )
                for j, tc in enumerate(tool_calls):
                    tool = tc.get("tool", "?")
                    mcp_server, backend = _tool_backend(tool)
                    args = tc.get("args", {}) or {}

                    st.markdown(
                        f"### Tool call {j+1} — `{tool}`\n"
                        f"**MCP server:** `{mcp_server}`   ·   "
                        f"**Backend:** {backend}   ·   "
                        f"**Result:** `{tc.get('result_summary', '?')}` "
                        f"({tc.get('result_size', 0)} rows/chars)"
                    )

                    # Show the "query" in the best format per tool
                    if tool.startswith("graph."):
                        query = args.get("query") or args.get("node_id", "")
                        if query:
                            st.markdown("**Cypher / node query:**")
                            st.code(query, language="cypher")
                        params = args.get("params") or args.get("edge_type") or ""
                        if params:
                            st.markdown(f"**Params:** `{params}`")
                    elif tool.startswith("vector."):
                        q = args.get("query") or args.get("chunk_id", "")
                        collection = args.get("collection", "device_docs")
                        st.markdown(
                            f"**Search query** _(against `{collection}` collection, "
                            f"k={args.get('k', 6)})_:"
                        )
                        st.code(q, language="text")
                        if args.get("filters"):
                            st.markdown(f"**Filters:** `{args['filters']}`")
                    elif tool.startswith("files."):
                        st.markdown("**Args:**")
                        st.json(args)

                    st.divider()


def _render_entry_agent_trace(entry_id: str) -> None:
    """Small in-card expander showing the LLM turns that produced this entry."""
    turns = [t for t in load_prompt_log() if t.get("entry_id") == entry_id]
    if not turns:
        st.caption("_(no LLM turns recorded for this entry)_")
        return
    st.markdown("**Agent trace for this entry:**")
    st.markdown(
        "| # | Agent | Model | Tokens in/out | Latency | Cost | Status |\n"
        "|---|---|---|---|---|---|---|\n"
        + "\n".join(
            f"| {i+1} | `{t.get('agent','?')}` | `{t.get('model','?')}` | "
            f"{t.get('tokens_in',0)}/{t.get('tokens_out',0)} | "
            f"{t.get('latency_ms',0)}ms | ${t.get('cost_usd_est',0):.5f} | "
            f"{'❌ ' + (t.get('error','')[:40]+'…') if t.get('error') else '✅'}"
            f"{' ⚡fallback' if t.get('fallback_used') else ''} |"
            for i, t in enumerate(turns)
        )
    )
    total_cost = sum(float(t.get("cost_usd_est", 0)) for t in turns)
    total_latency = sum(int(t.get("latency_ms", 0)) for t in turns)
    st.caption(
        f"**{len(turns)} LLM turns** for `{entry_id}` — "
        f"total ${total_cost:.5f} · {total_latency}ms wall time"
    )


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
