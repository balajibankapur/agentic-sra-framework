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


# ---------------------------------------------------------------------------
# Glossary — plain-English expansions of the abbreviations reviewers see.


STRIDE_MEANING: dict[str, str] = {
    "S": "Spoofing — an attacker pretends to be someone / something else",
    "T": "Tampering — data or firmware is modified in an unauthorized way",
    "R": "Repudiation — a user denies having taken an action, no proof exists",
    "I": "Information disclosure — sensitive data leaks to someone not allowed to see it",
    "D": "Denial of service — the device is made unavailable or unusable",
    "E": "Elevation of privilege — a low-privilege actor gains higher access",
}

PRIORITY_MEANING: dict[str, str] = {
    "P0": "P0 — Critical, must be fixed before the next release",
    "P1": "P1 — High, planned for the next release window",
    "P2": "P2 — Medium, backlog / next major version",
    "P3": "P3 — Low, tracked but deferred",
}

SEVERITY_MEANING: dict[str, str] = {
    "critical": "Critical — a working exploit would compromise patient safety or PHI",
    "high":     "High — significant risk if exploited, needs prompt mitigation",
    "medium":   "Medium — meaningful risk but partial mitigations exist",
    "low":      "Low — limited impact, monitor and defer",
    "none":     "None — no material risk beyond baseline",
}

# Full names for the regulatory standards that appear as clause id prefixes.
STANDARD_FULL: dict[str, str] = {
    "FDA-2023":    "FDA 2023 Premarket Cybersecurity Guidance",
    "IEC-CR":      "IEC 62443-4-2 · Component Requirements",
    "IEC":         "IEC 62443 series",
    "AAMI-TIR57":  "AAMI TIR57 Principles for Medical Device Cybersecurity",
    "AAMI":        "AAMI TIR57",
    "NIST-800-193":"NIST SP 800-193 · Platform Firmware Resiliency",
    "NIST":        "NIST SP 800-53 / 800-193",
}

# General acronym glossary. Each entry appears both in the top-of-page
# glossary AND is auto-detected in the detail panel so we can list only the
# ones used in the currently-open entry.
ACRONYMS: list[tuple[str, str]] = [
    # Framework / process
    ("SRA",     "Security Risk Assessment — the FDA-required document this tool drafts"),
    ("STRIDE",  "Threat category framework: Spoofing, Tampering, Repudiation, Info disclosure, Denial of service, Elevation of privilege"),
    ("CVSS",    "Common Vulnerability Scoring System v3.1 — 0-10 severity score (0 none, 10 critical)"),
    ("CVE",     "Common Vulnerabilities and Exposures — an entry in the public vulnerability database"),
    ("CWE",     "Common Weakness Enumeration — the category of software weakness that leads to a CVE"),
    ("DFD",     "Data Flow Diagram — element used in threat modeling (process, data store, external entity)"),
    ("MCP",     "Model Context Protocol — the tool contract each agent uses to reach a database"),
    # Regulatory
    ("FDA",     "US Food and Drug Administration — the regulator this SRA is drafted for"),
    ("IEC 62443","International standard for industrial-automation cybersecurity, applied to medical devices"),
    ("AAMI TIR57","US medical-device cybersecurity technical report"),
    ("NIST 800-193","US firmware-resilience standard: Protect, Detect, Recover"),
    ("HIPAA",   "US Health Insurance Portability and Accountability Act — protects patient data (PHI)"),
    ("PHI",     "Protected Health Information — patient data protected by HIPAA"),
    ("PII",     "Personally Identifiable Information"),
    # Attack patterns
    ("MITM",    "Man-In-The-Middle — attacker sits between two parties and can read or modify traffic"),
    ("DoS",     "Denial of Service — an attack that makes the device unusable"),
    ("DDoS",    "Distributed Denial of Service — DoS from many attacker sources at once"),
    ("RCE",     "Remote Code Execution — the attacker runs arbitrary code on the device"),
    ("XSS",     "Cross-Site Scripting — attacker injects code into a web page viewed by others"),
    ("CSRF",    "Cross-Site Request Forgery — trick a logged-in user into unwanted actions"),
    ("Replay",  "Replay attack — attacker resends a captured valid message to cause an unintended action"),
    ("Spoofing","Attacker pretends to be a trusted device or user"),
    # Wireless / connectivity
    ("BLE",     "Bluetooth Low Energy — the short-range wireless protocol the device uses"),
    ("Wi-Fi",   "Wireless LAN (IEEE 802.11)"),
    ("OTA",     "Over-The-Air firmware update — new firmware pushed to the device wirelessly"),
    ("FOTA",    "Firmware Over-The-Air — same as OTA"),
    # Crypto / auth
    ("MFA",     "Multi-Factor Authentication — password plus at least one other factor"),
    ("TLS",     "Transport Layer Security — encryption for data in transit (HTTPS uses TLS)"),
    ("DTLS",    "Datagram TLS — TLS for UDP-based traffic"),
    ("AES",     "Advanced Encryption Standard — symmetric block cipher"),
    ("ECDSA",   "Elliptic Curve Digital Signature Algorithm — asymmetric signatures"),
    ("RSA",     "Rivest-Shamir-Adleman — asymmetric encryption / signatures"),
    ("SHA-256", "Secure Hash Algorithm 256-bit — cryptographic hash function"),
    ("HMAC",    "Hash-based Message Authentication Code — signed hash for integrity"),
    ("Ed25519", "Modern elliptic-curve signature scheme (safer default than ECDSA)"),
    ("PSK",     "Pre-Shared Key — same secret key on both sides"),
    ("RNG",     "Random Number Generator (should be cryptographic — CSPRNG)"),
    ("PKI",     "Public Key Infrastructure — certificates + CAs"),
    # Hardware / firmware
    ("SPI",     "Serial Peripheral Interface — short-range hardware bus"),
    ("I2C",     "Inter-Integrated Circuit — short-range hardware bus"),
    ("UART",    "Universal Asynchronous Receiver-Transmitter — serial debug port"),
    ("JTAG",    "Debug interface exposed on hardware (must be locked in production)"),
    ("SWD",     "Serial Wire Debug — ARM debug interface"),
    ("MCU",     "Microcontroller Unit — the embedded CPU"),
    ("BOM",     "Bill of Materials — parts list, incl. software (SBOM)"),
    ("SBOM",    "Software Bill of Materials — required by FDA 2023 guidance"),
    ("HSM",     "Hardware Security Module — dedicated secure crypto chip"),
    ("TEE",     "Trusted Execution Environment — isolated CPU mode for secrets"),
    ("NVM",     "Non-Volatile Memory — retains data when powered off (flash)"),
    # Medical / operational
    ("EMR",     "Electronic Medical Record system — the hospital-side system the device talks to"),
    ("HL7",     "Health Level 7 — medical data interchange standard"),
    ("FHIR",    "Fast Healthcare Interoperability Resources — modern HL7 REST format"),
    ("UDI",     "Unique Device Identifier — FDA per-device serial identifier"),
]


# Precompiled lookup for fast contains-check (case-insensitive whole-token match).
_ACRONYM_LOOKUP = {a[0]: a[1] for a in ACRONYMS}


def _terms_used_in(entry: dict) -> list[tuple[str, str]]:
    """Return the acronyms from ACRONYMS that appear in the entry's text.

    Scans title, narrative, residual-risk reason, existing/proposed controls,
    and proposed doc/code changes. Matches on whole word boundaries so 'BLE'
    doesn't fire on 'ABLE'.
    """
    import re
    haystacks = [
        entry.get("title", ""),
        entry.get("narrative", ""),
        entry.get("residual_risk_reason", ""),
    ]
    for c in entry.get("existing_controls", []) or []:
        haystacks.append(c.get("description", ""))
    for c in entry.get("proposed_controls", []) or []:
        haystacks.append(c.get("description", ""))
    for d in entry.get("proposed_doc_changes", []) or []:
        haystacks.append(d.get("body", ""))
    for c in entry.get("proposed_code_changes", []) or []:
        haystacks.append(c.get("hunk", ""))
    blob = "  ".join(str(h) for h in haystacks if h)

    seen: list[tuple[str, str]] = []
    for term, meaning in ACRONYMS:
        # Word-boundary regex; special-case terms containing spaces/dots/dashes.
        pat = r"(?<![A-Za-z0-9])" + re.escape(term) + r"(?![A-Za-z0-9])"
        if re.search(pat, blob, flags=re.IGNORECASE):
            seen.append((term, meaning))
    return seen


def _stride_short(letter: str) -> str:
    """Return e.g. 'I — Info disclosure' for the compact table cell."""
    short_map = {
        "S": "S · Spoofing",
        "T": "T · Tampering",
        "R": "R · Repudiation",
        "I": "I · Info disclosure",
        "D": "D · Denial of service",
        "E": "E · Elevation of privilege",
    }
    return short_map.get((letter or "").strip().upper()[:1], letter or "")


def _standard_for(clause_id: str) -> str:
    """Best-effort friendly name for an FDA-2023-V.B.3-style clause id."""
    up = (clause_id or "").upper()
    for prefix, name in STANDARD_FULL.items():
        if up.startswith(prefix.upper()):
            return name
    return "—"


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
    decisions = review_state.get("decisions", {})
    from collections import Counter
    by_action = Counter(d.get("action", "pending") for d in decisions.values())
    reviewed = len(decisions)
    total = len(entries)
    approved = by_action.get("approved", 0) + by_action.get("edited", 0)
    pct = int(round(100 * reviewed / total)) if total else 0

    reviewer_display = review_state.get("reviewer_name") or "unassigned"

    st.markdown(
        f"""
        <div class="hero-band">
          <div class="hero-row">
            <div>
              <div class="hero-title">Cybersecurity Risk Assessment <span class="device-chip">device · {DEVICE}</span></div>
              <div class="hero-sub">Review each drafted entry and approve, edit, or reject it.  Reviewer: <b>{reviewer_display}</b></div>
            </div>
            <div class="hero-badge">
              <div class="hero-badge-num">{pct}%</div>
              <div class="hero-badge-label">reviewed</div>
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total", total)
    col2.metric("Reviewed", reviewed)
    col3.metric("Approved", approved)
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
    severity = str(cvss.get("severity", "")).lower()
    cvss_score = cvss.get("base_score", 0)
    # Color the CVSS chip by severity using Streamlit's inline color markdown
    if severity == "critical":
        cvss_chip = f":red[**CVSS {cvss_score} {severity.upper()}**]"
    elif severity == "high":
        cvss_chip = f":orange[**CVSS {cvss_score} {severity.upper()}**]"
    elif severity == "medium":
        cvss_chip = f":blue[**CVSS {cvss_score} {severity.upper()}**]"
    elif severity == "low":
        cvss_chip = f":green[**CVSS {cvss_score} {severity.upper()}**]"
    else:
        cvss_chip = f"**CVSS {cvss_score}**"

    priority = entry.get("priority", "")
    prio_chip = (
        f":red[**{priority}**]" if priority == "P0"
        else f":orange[**{priority}**]" if priority == "P1"
        else f"**{priority}**"
    )

    header = (
        f"{status_emoji}  **{tid}**  ·  {entry.get('title', '')[:80]}  "
        f"  ·  STRIDE **{entry.get('stride', '?')}**"
        f"  ·  {cvss_chip}  ·  {prio_chip}"
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

    # Read-only view — facts strip at top for at-a-glance reading
    cvss = entry.get("cvss_v31") or {}
    facts_html = f"""
    <div class="facts-strip">
      <div class="fact-cell"><div class="fact-label">Priority</div><div class="fact-value">{entry.get('priority', '—')}</div></div>
      <div class="fact-cell"><div class="fact-label">CVSS</div><div class="fact-value">{cvss.get('base_score', 0)} <span class="fact-tag">{cvss.get('severity', '')}</span></div></div>
      <div class="fact-cell"><div class="fact-label">Residual risk</div><div class="fact-value">{entry.get('residual_risk', '—')}</div></div>
      <div class="fact-cell"><div class="fact-label">Effort</div><div class="fact-value">{entry.get('effort_engineer_weeks', 0):g} <span class="fact-tag">eng-weeks</span></div></div>
      <div class="fact-cell"><div class="fact-label">STRIDE</div><div class="fact-value">{entry.get('stride', '—')}</div></div>
    </div>
    """
    st.markdown(facts_html, unsafe_allow_html=True)

    st.markdown(f"**What's the risk?**  {entry.get('narrative', '_(none)_')}")
    if entry.get("residual_risk_reason"):
        st.caption(f"**Why residual risk is {entry.get('residual_risk', '?')}:** {entry['residual_risk_reason']}")

    # Existing controls
    if entry.get("existing_controls"):
        st.markdown("**Existing controls (legacy):**")
        for c in entry["existing_controls"]:
            st.markdown(f"- `{c.get('id', '?')}` — {c.get('description', '')}")

    # Gap analysis
    if entry.get("gap_analysis"):
        st.markdown("**Gap analysis — which regulation clauses are met, partially met, or missing:**")
        rows = [{
            "Standard": _standard_for(g.get("clause_id", "")),
            "Clause": g.get("clause_id", ""),
            "Verdict": (g.get("verdict", "") or "").title(),
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
    st.markdown("")  # small spacer
    b1, b2, b3, b4, b5, b6 = st.columns(6)
    if b1.button("✅ Approve", key=f"approve_{tid}", type="primary", width="stretch"):
        record_decision(review_state, tid, "approved")
        st.rerun()
    if b2.button("✏️ Edit", key=f"edit_btn_{tid}", width="stretch"):
        st.session_state[f"edit_{tid}"] = True
        st.rerun()
    if b3.button("❌ Reject", key=f"reject_btn_{tid}", width="stretch"):
        st.session_state[f"reject_prompt_{tid}"] = True
        st.rerun()
    if b4.button("⏸️ Defer", key=f"defer_{tid}", width="stretch"):
        record_decision(review_state, tid, "deferred")
        st.rerun()
    if b5.button("🔍 Ask graph", key=f"ask_{tid}", width="stretch"):
        st.session_state[f"ask_prompt_{tid}"] = True
        st.rerun()
    rerun_disabled = job_manager.is_running(DEVICE)
    if b6.button("🔁 Rerun", key=f"rerun_btn_{tid}", disabled=rerun_disabled,
                 width="stretch",
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
# Modern UI styling


_MODERN_CSS = """
<style>
/* ---- global reset ---- */
html, body, [class*="css"] {
  font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI",
               "Roboto", system-ui, sans-serif !important;
  -webkit-font-smoothing: antialiased;
  color: #111827;
}
.main .block-container {
  padding-top: 1.2rem;
  padding-bottom: 3rem;
}
#MainMenu, footer,
.stDeployButton,
[data-testid="stToolbar"],
[data-testid="stDecoration"],
[data-testid="stStatusWidget"],
[data-testid="stAppDeployButton"],
[data-testid="stAppToolbar"] { visibility: hidden !important; height: 0 !important; }
header[data-testid="stHeader"] { background: transparent; height: 0; }

/* ---- headings ---- */
h1, h2, h3, h4 {
  color: #1E2761;
  font-weight: 700;
  letter-spacing: -0.02em;
}
h1 { font-size: 1.8rem; }
h2 { font-size: 1.35rem; }
h3 { font-size: 1.1rem; margin-top: 1rem; }

/* ---- hero band ---- */
.hero-band {
  background: linear-gradient(135deg, #1E2761 0%, #2E3F8F 60%, #4356B2 100%);
  color: white;
  padding: 1.4rem 1.8rem;
  border-radius: 16px;
  margin-bottom: 1.2rem;
  box-shadow: 0 6px 24px rgba(30, 39, 97, 0.18);
}
.hero-band .hero-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
}
.hero-title {
  font-size: 1.65rem;
  font-weight: 700;
  color: white;
  letter-spacing: -0.02em;
  line-height: 1.2;
}
.hero-sub {
  color: rgba(255,255,255,0.78);
  font-size: 0.95rem;
  margin-top: 6px;
}
.device-chip {
  display: inline-block;
  background: rgba(255,255,255,0.15);
  border: 1px solid rgba(255,255,255,0.28);
  padding: 3px 12px;
  border-radius: 999px;
  font-size: 0.78rem;
  font-weight: 500;
  margin-left: 10px;
  vertical-align: middle;
  letter-spacing: 0.02em;
}
.hero-badge {
  text-align: center;
  padding: 8px 20px;
  background: rgba(255,255,255,0.12);
  border: 1px solid rgba(255,255,255,0.24);
  border-radius: 12px;
  min-width: 110px;
}
.hero-badge-num {
  font-size: 1.9rem;
  font-weight: 700;
  color: #FFAD1F;
  line-height: 1;
}
.hero-badge-label {
  font-size: 0.75rem;
  color: rgba(255,255,255,0.8);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin-top: 4px;
}

/* ---- KPI metrics ---- */
div[data-testid="stMetric"] {
  background: white;
  border: 1px solid #E5E7EB;
  border-radius: 12px;
  padding: 14px 18px;
  box-shadow: 0 1px 3px rgba(0,0,0,0.04);
  transition: transform 0.15s ease, box-shadow 0.15s ease;
}
div[data-testid="stMetric"]:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(0,0,0,0.06);
}
div[data-testid="stMetric"] label {
  color: #6B7280 !important;
  font-size: 0.72rem !important;
  font-weight: 600 !important;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
div[data-testid="stMetric"] [data-testid="stMetricValue"] {
  color: #1E2761;
  font-size: 1.75rem;
  font-weight: 700;
}

/* ---- progress bar ---- */
div[data-testid="stProgress"] > div > div > div {
  background: linear-gradient(90deg, #1E2761 0%, #FFAD1F 100%);
  border-radius: 999px;
}
div[data-testid="stProgress"] > div > div {
  background: #F3F4F6;
  border-radius: 999px;
}

/* ---- expanders (entry cards) ---- */
div[data-testid="stExpander"] {
  border: 1px solid #E5E7EB;
  border-radius: 12px;
  background: white;
  box-shadow: 0 1px 3px rgba(0,0,0,0.04);
  margin-bottom: 10px;
  overflow: hidden;
  transition: border-color 0.15s ease, box-shadow 0.15s ease;
}
div[data-testid="stExpander"]:hover {
  border-color: #C7D2FE;
  box-shadow: 0 4px 14px rgba(30,39,97,0.08);
}
div[data-testid="stExpander"] summary {
  padding: 12px 16px;
  font-weight: 500;
  cursor: pointer;
}
div[data-testid="stExpander"] summary:hover {
  background: #F9FAFB;
}

/* ---- buttons ---- */
.stButton > button {
  border-radius: 8px;
  border: 1px solid #D1D5DB;
  font-weight: 500;
  transition: all 0.15s ease;
  padding: 6px 14px;
}
.stButton > button:hover {
  border-color: #1E2761;
  color: #1E2761;
  background: #F8FAFC;
}
.stButton > button[kind="primary"] {
  background: #1E2761;
  border: none;
  color: white;
  box-shadow: 0 2px 6px rgba(30,39,97,0.25);
}
.stButton > button[kind="primary"]:hover {
  background: #2E3F8F;
  color: white;
  transform: translateY(-1px);
  box-shadow: 0 4px 10px rgba(30,39,97,0.3);
}

/* ---- sidebar ---- */
section[data-testid="stSidebar"] {
  background: #F8FAFC;
  border-right: 1px solid #E5E7EB;
}
section[data-testid="stSidebar"] h2,
section[data-testid="stSidebar"] h3 {
  font-size: 0.72rem !important;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: #6B7280 !important;
  font-weight: 700;
  margin-top: 1rem;
  margin-bottom: 6px;
}
section[data-testid="stSidebar"] hr {
  margin: 12px 0;
  border-color: #E5E7EB;
}

/* ---- tabs ---- */
button[data-baseweb="tab"] {
  font-weight: 500 !important;
  padding: 10px 22px !important;
  font-size: 0.95rem !important;
}
button[data-baseweb="tab"][aria-selected="true"] {
  color: #1E2761 !important;
  border-bottom-color: #1E2761 !important;
  border-bottom-width: 3px !important;
}
div[data-baseweb="tab-list"] {
  gap: 0 !important;
  border-bottom: 1px solid #E5E7EB;
}

/* ---- alerts ---- */
div[data-testid="stAlert"] {
  border-radius: 10px;
  border: 1px solid transparent;
  padding: 12px 16px;
}
div[data-testid="stAlert"][data-baseweb] { border-left: 3px solid; }

/* ---- inputs ---- */
div[data-testid="stTextInput"] input,
div[data-testid="stTextArea"] textarea,
div[data-testid="stNumberInput"] input,
div[data-baseweb="select"] > div {
  border-radius: 8px !important;
  border-color: #D1D5DB !important;
}
div[data-testid="stTextInput"] input:focus,
div[data-testid="stTextArea"] textarea:focus {
  border-color: #1E2761 !important;
  box-shadow: 0 0 0 3px rgba(30,39,97,0.12) !important;
}

/* ---- code + inline code ---- */
code {
  background: #F3F4F6;
  border-radius: 5px;
  padding: 1px 6px;
  font-family: "JetBrains Mono", "SF Mono", ui-monospace, monospace;
  font-size: 0.88em;
  color: #1E2761;
}
div[data-testid="stCodeBlock"] {
  border-radius: 10px;
  border: 1px solid #E5E7EB;
  overflow: hidden;
}

/* ---- dataframe ---- */
div[data-testid="stDataFrame"] {
  border-radius: 10px;
  border: 1px solid #E5E7EB;
  overflow: hidden;
}

/* ---- facts strip (top of each entry) ---- */
.facts-strip {
  display: flex;
  gap: 10px;
  background: #F8FAFC;
  border: 1px solid #E5E7EB;
  border-radius: 12px;
  padding: 12px 16px;
  margin-bottom: 14px;
  flex-wrap: wrap;
}
.fact-cell {
  flex: 1 1 100px;
  min-width: 100px;
}
.fact-label {
  font-size: 0.68rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: #6B7280;
  font-weight: 600;
  margin-bottom: 4px;
}
.fact-value {
  font-size: 1.05rem;
  font-weight: 700;
  color: #1E2761;
}
.fact-tag {
  display: inline-block;
  font-size: 0.7rem;
  font-weight: 500;
  color: #6B7280;
  background: #EEF2FF;
  padding: 1px 6px;
  border-radius: 999px;
  margin-left: 2px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

/* ---- compact table-style rows ---- */
.row-header {
  display: grid;
  grid-template-columns: 1.3fr 1.6fr 6.5fr 1.4fr 0.9fr 1.1fr;
  gap: 16px;
  padding: 8px 20px 6px;
  margin-bottom: 4px;
  border-bottom: 1px solid #E5E7EB;
}
/* Prevent status pill from wrapping */
.pill { white-space: nowrap; }
.row-header .rc {
  font-size: 0.68rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: #6B7280;
  font-weight: 600;
}
.row-tid {
  font-family: "JetBrains Mono", "SF Mono", ui-monospace, monospace;
  font-size: 0.82rem;
  color: #6B7280;
  letter-spacing: 0.02em;
}
.row-title {
  font-size: 0.98rem;
  font-weight: 600;
  color: #1E2761;
  line-height: 1.35;
}
.pill-wrap { text-align: right; padding-top: 4px; }
.pill {
  display: inline-block;
  padding: 3px 12px;
  border-radius: 999px;
  font-size: 0.72rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.pill-approved, .pill-edited { background:#DCFCE7; color:#166534; }
.pill-rejected               { background:#FEE2E2; color:#991B1B; }
.pill-deferred               { background:#FEF3C7; color:#92400E; }
.pill-pending                { background:#E5E7EB; color:#374151; }

.card-chips { margin-bottom: 8px; display: flex; gap: 8px; flex-wrap: wrap; }
.chip {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 6px;
  font-size: 0.78rem;
  font-weight: 500;
  border: 1px solid transparent;
}
.chip-sev-critical { background:#FEE2E2; color:#991B1B; border-color:#FCA5A5; }
.chip-sev-high     { background:#FED7AA; color:#9A3412; border-color:#FDBA74; }
.chip-sev-medium   { background:#DBEAFE; color:#1E40AF; border-color:#93C5FD; }
.chip-sev-low      { background:#DCFCE7; color:#166534; border-color:#86EFAC; }
.chip-sev-none     { background:#F3F4F6; color:#6B7280; border-color:#D1D5DB; }
.chip-prio-p0      { background:#FEE2E2; color:#991B1B; border-color:#FCA5A5; }
.chip-prio-p1      { background:#FED7AA; color:#9A3412; border-color:#FDBA74; }
.chip-prio-p2      { background:#EEF2FF; color:#3730A3; border-color:#C7D2FE; }
.chip-prio-p3, .chip-prio-na { background:#F3F4F6; color:#6B7280; border-color:#D1D5DB; }
.chip-stride       { background:#F3F4F6; color:#374151; border-color:#D1D5DB; }

.detail-inline-divider {
  border-top: 1px dashed #E5E7EB;
  margin: 14px -4px 12px;
}

/* Only bordered vertical blocks (i.e. st.container(border=True)) that CONTAIN
   a .card-marker as a direct-child element get the card treatment. */
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .card-marker) {
  border-radius: 8px !important;
  background: white !important;
  margin-bottom: 4px !important;
  padding: 4px 0 !important;
  transition: box-shadow 0.15s ease, border-color 0.15s ease, background 0.15s ease;
  position: relative;
  overflow: hidden;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .card-marker):hover {
  box-shadow: 0 2px 8px rgba(30,39,97,0.08);
  z-index: 2;
}
/* Selected row gets larger padding + rounded corners restore */
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .card-marker.sel) {
  border-radius: 12px !important;
  margin-top: 8px !important;
  margin-bottom: 8px !important;
  padding: 8px 0 !important;
}

/* Hidden marker element — used only for :has() styling of the parent card. */
.card-marker { display: none; }

/* Zebra stripe (alternate rows) — noticeable but not distracting. */
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .card-marker.row-even) {
  background: #FFFFFF !important;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .card-marker.row-odd) {
  background: #EEF2FF !important;
}

/* Left color-bar keyed to severity. */
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .card-marker)::before {
  content: "";
  position: absolute;
  top: 0; bottom: 0; left: 0;
  width: 5px;
  background: #D1D5DB;
  z-index: 1;
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .card-marker.sev-critical)::before { background: #DC2626; }
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .card-marker.sev-high)::before     { background: #F97316; }
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .card-marker.sev-medium)::before   { background: #3B82F6; }
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .card-marker.sev-low)::before      { background: #16A34A; }

/* Selected card — navy tint + heavier left border. */
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .card-marker.sel) {
  background: #EEF2FF !important;
  box-shadow: 0 6px 20px rgba(30,39,97,0.12);
}
div[data-testid="stVerticalBlock"]:has(> div[data-testid="stElementContainer"] .card-marker.sel)::before {
  width: 7px;
}

/* ---- empty state card ---- */
.empty-state {
  background: linear-gradient(135deg, #F8FAFC 0%, #EEF2FF 100%);
  border: 1px dashed #C7D2FE;
  border-radius: 16px;
  padding: 3.5rem 2rem;
  text-align: center;
  margin: 1rem 0;
}
.empty-icon { font-size: 3rem; margin-bottom: 12px; }
.empty-title { font-size: 1.3rem; font-weight: 700; color: #1E2761; margin-bottom: 6px; }
.empty-sub { color: #6B7280; font-size: 0.95rem; line-height: 1.6; }
.empty-sub code { background: #E0E7FF; color: #1E2761; }

/* ---- divider ---- */
hr { border-color: #E5E7EB; }
</style>
"""


def _inject_modern_css() -> None:
    st.markdown(_MODERN_CSS, unsafe_allow_html=True)


def _render_reviewer_sidebar(review_state: dict) -> None:
    """Reviewer identity input, tucked into the sidebar (set-and-forget)."""
    with st.sidebar:
        st.markdown("### Reviewer")
        reviewer = st.text_input(
            "Your name",
            value=review_state.get("reviewer_name", ""),
            key="reviewer_name_input",
            label_visibility="collapsed",
            placeholder="e.g. balaji@example.com",
        )
        if reviewer != review_state.get("reviewer_name", ""):
            review_state["reviewer_name"] = reviewer
            save_review_state(review_state)
        st.caption(f"Recorded in `{STATE_JSON.name}` on every action.")


# ---------------------------------------------------------------------------
# Main


def main() -> None:
    st.set_page_config(
        page_title=f"Cybersecurity Risk Assessment — {DEVICE}",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    _inject_modern_css()

    entries = load_draft()
    review_state = load_review_state()
    _render_reviewer_sidebar(review_state)

    if not entries:
        st.markdown(
            f"""
            <div class="hero-band">
              <div class="hero-title">Cybersecurity Risk Assessment <span class="device-chip">device · {DEVICE}</span></div>
              <div class="hero-sub">Draft, review, and export an FDA-ready risk assessment for a connected medical device.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(
            f"""
            <div class="empty-state">
              <div class="empty-icon">📝</div>
              <div class="empty-title">No draft yet</div>
              <div class="empty-sub">Start a draft from <b>Analysis Control</b> in the sidebar,<br/>or run <code>sra draft --device {DEVICE}</code> in a terminal.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        _render_progress_banner()
        _render_job_control_sidebar()
        _render_reset_sidebar()
        return

    _render_progress_banner()
    render_header(entries, review_state)

    # Sidebar filters (always visible regardless of active tab)
    st.sidebar.header("Filter & sort")
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
    st.sidebar.header("Export")
    if st.sidebar.button("📤 Generate final report (PDF + DOCX)", width="stretch"):
        _run_export_ui(review_state)
    _render_reset_sidebar()

    # Main area: two tabs — reviewer workflow + agent activity log
    n_turns = 0
    if PROMPTS_JSONL.exists():
        try:
            n_turns = sum(1 for _ in PROMPTS_JSONL.open("r", encoding="utf-8", errors="ignore") if _.strip())
        except OSError:
            pass
    tab_review, tab_agents = st.tabs([
        f"📋  Review entries ({len(entries)})",
        f"🔍  How the agents got the answer ({n_turns} steps)",
    ])
    with tab_agents:
        render_agent_activity_tab()
    with tab_review:
        _render_review_body(entries, review_state, sort_by, show_only, page_size)


_STATUS_DOTS = {
    "approved": "🟢 Approved",
    "edited":   "🟢 Edited",
    "rejected": "🔴 Rejected",
    "deferred": "🟡 Deferred",
    "pending":  "⚪ Pending",
}


def _render_review_body(
    entries: list[dict],
    review_state: dict,
    sort_by: str,
    show_only: str,
    page_size: int,   # unused in master-detail mode; kept for signature compat
) -> None:
    # ---- filter ----------------------------------------------------------
    def _keep(e: dict) -> bool:
        a = review_state.get("decisions", {}).get(e["threat_id"], {}).get("action", "pending")
        if show_only == "All":          return True
        if show_only == "Pending only": return a == "pending"
        if show_only == "Approved":     return a in {"approved", "edited"}
        if show_only == "Rejected":     return a == "rejected"
        if show_only == "Deferred":     return a == "deferred"
        if show_only == "Parse errors": return bool(e.get("parse_error"))
        return True

    display = [e for e in entries if _keep(e)]

    # ---- sort ------------------------------------------------------------
    if sort_by == "Threat id (A→Z)":
        display.sort(key=lambda e: e["threat_id"])
    elif sort_by == "CVSS score (high→low)":
        display.sort(key=lambda e: -(e.get("cvss_v31") or {}).get("base_score", 0))
    else:  # Priority + threat id
        priority_rank = {"P0": 0, "P1": 1, "P2": 2}
        display.sort(key=lambda e: (priority_rank.get(e.get("priority", "P2"), 3), e["threat_id"]))

    total_display = len(display)

    # Glossary expander — collapsible reference so any reviewer can look up
    # what CVSS / STRIDE / FDA-2023 etc. mean without leaving the page.
    with st.expander("📖 What do these terms mean? (glossary)", expanded=False):
        st.markdown(
            "\n".join(f"- **{term}** — {meaning}" for term, meaning in ACRONYMS)
        )

    st.markdown(
        f"##### {total_display} entries after filter "
        f"<span style='color:#6B7280;font-weight:400'>· {len(entries)} total</span>",
        unsafe_allow_html=True,
    )

    # ---- bulk approve above table ---------------------------------------
    pending_all = [
        e for e in display
        if review_state.get("decisions", {}).get(e["threat_id"], {}).get("action", "pending") == "pending"
    ]
    if pending_all:
        cbulk, cnote = st.columns([1, 3])
        if cbulk.button(
            f"✅ Approve all {len(pending_all)} pending entries",
            key="bulk_approve_all_filtered",
            width="stretch",
        ):
            for e in pending_all:
                record_decision(review_state, e["threat_id"], "approved")
            st.rerun()
        cnote.caption("_Approves every pending entry that matches the current filter._")

    if not display:
        st.info("No entries match the current filter.")
        return

    # Selection state — remembered across reruns so an Approve action
    # keeps the same entry open.
    _sel_key = "_selected_tid"

    # ---- compact-row table with inline expansion ------------------------
    # Header row (table column labels)
    st.markdown(
        """
        <div class='row-header'>
          <div class='rc rc-status'>Status</div>
          <div class='rc rc-tid'>Threat ID</div>
          <div class='rc rc-title'>Title</div>
          <div class='rc rc-cvss'>CVSS</div>
          <div class='rc rc-prio'>Priority</div>
          <div class='rc rc-act'></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    for idx, e in enumerate(display):
        decision = review_state.get("decisions", {}).get(e["threat_id"], {}) or {}
        action = decision.get("action", "pending")
        cvss = e.get("cvss_v31") or {}
        severity = (cvss.get("severity", "") or "").lower() or "none"
        priority = e.get("priority", "") or ""
        stride_letter = (e.get("stride", "") or "").strip().upper()[:1]
        row_class = "odd" if idx % 2 else "even"

        status_pill_class = f"pill pill-{action}"
        status_label = {
            "approved": "Approved",
            "edited":   "Edited",
            "rejected": "Rejected",
            "deferred": "Deferred",
            "pending":  "Pending",
        }.get(action, "Pending")

        sev_class = f"chip chip-sev-{severity}"
        prio_class = f"chip chip-prio-{priority.lower() if priority else 'na'}"

        is_selected = (st.session_state.get(_sel_key) == e["threat_id"])
        sel_marker = "sel" if is_selected else "unsel"

        with st.container(border=True):
            # Hidden marker div — CSS :has() styles the parent row from this.
            st.markdown(
                f"<div class='card-marker sev-{severity} row-{row_class} {sel_marker}'></div>",
                unsafe_allow_html=True,
            )

            # -------- compact single-line row --------
            c_status, c_tid, c_title, c_cvss, c_prio, c_btn = st.columns(
                [1.3, 1.6, 6.5, 1.4, 0.9, 1.1],
                vertical_alignment="center",
            )
            c_status.markdown(
                f"<span class='{status_pill_class}'>{status_label}</span>",
                unsafe_allow_html=True,
            )
            c_tid.markdown(
                f"<span class='row-tid'>{e['threat_id']}</span>",
                unsafe_allow_html=True,
            )
            c_title.markdown(
                f"<span class='row-title'>{e.get('title', '')}</span>",
                unsafe_allow_html=True,
            )
            c_cvss.markdown(
                f"<span class='{sev_class}'>{cvss.get('base_score', 0)} · {(cvss.get('severity', '') or '—').title()}</span>",
                unsafe_allow_html=True,
            )
            c_prio.markdown(
                f"<span class='{prio_class}'>{priority or '—'}</span>",
                unsafe_allow_html=True,
            )
            with c_btn:
                label = "▲ Close" if is_selected else "Details ▶"
                if st.button(
                    label,
                    key=f"open_{e['threat_id']}",
                    type=("primary" if is_selected else "secondary"),
                    width="stretch",
                ):
                    st.session_state[_sel_key] = (
                        None if is_selected else e["threat_id"]
                    )
                    st.rerun()

            # -------- inline expansion --------
            if is_selected:
                st.markdown(
                    "<div class='detail-inline-divider'></div>",
                    unsafe_allow_html=True,
                )
                st.markdown(
                    f"##### {e.get('title', '')}"
                )
                st.caption(
                    f"**Category:** {STRIDE_MEANING.get(stride_letter, stride_letter or '—')}  \n"
                    f"**CVSS:** {cvss.get('base_score', 0)} / 10 — {SEVERITY_MEANING.get(severity, severity or '—')}  \n"
                    f"**Priority:** {PRIORITY_MEANING.get(priority, priority or '—')}"
                )
                if action != "pending":
                    st.caption(
                        f"_{status_label} by **{decision.get('reviewer', 'unknown')}** "
                        f"at {(decision.get('timestamp_utc', '') or '')[:19].replace('T', ' ')} UTC_"
                    )
                used = _terms_used_in(e)
                if used:
                    with st.expander(
                        f"📖 Abbreviations used in this entry ({len(used)})",
                        expanded=False,
                    ):
                        for term, meaning in used:
                            st.markdown(f"- **{term}** — {meaning}")
                _render_entry_body(e, review_state, decision)


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
    st.sidebar.header("Run analysis")

    job_status = job_manager.status(DEVICE)

    if job_status.alive:
        with st.sidebar:
            _render_job_status_sidebar_fragment()
    else:
        with st.sidebar.form("start_draft_form", clear_on_submit=False):
            st.markdown("**Draft a new assessment**")
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
    st.sidebar.header("Clear data")

    if job_manager.is_running(DEVICE):
        st.sidebar.caption("_(disabled while a draft is running)_")
        return

    scope = st.sidebar.radio(
        "What to clear",
        ["Just the draft & my review", "…also the indices", "…also the cloned corpus"],
        index=0,
        help=(
            "Just the draft & my review: wipe draft, prompts, review state, final artifacts.\n"
            "…also the indices: additionally drop Chroma + Kuzu + JSON extracts (needs `sra index` after).\n"
            "…also the cloned corpus: additionally drop input/<device>/ (needs `sra init` after)."
        ),
    )
    confirm = st.sidebar.checkbox("Yes, delete these files")
    if st.sidebar.button("🗑 Clear now", width="stretch", disabled=not confirm):
        deleted = job_manager.reset(
            DEVICE,
            include_indices=(scope in {"…also the indices", "…also the cloned corpus"}),
            include_corpus=(scope == "…also the cloned corpus"),
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
