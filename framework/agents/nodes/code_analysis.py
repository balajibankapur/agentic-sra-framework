"""Code Analysis agent — SDD §2.3 (real).

Two-turn design:
  Turn 1 (planner)    LLM proposes {control_id, expected_symbol, regex}
                      probes for each control listed in compliance findings.
  Python              runs each grep against firmware/**/*.{c,h} and
                      collects file:line hits + snippets.
  Turn 2 (interpreter)LLM reads the grep results and emits CodeFinding
                      list with presence verdict + citations.

Both turns share the same prompt YAML and system prompt; the user
messages differ (planner input vs interpreter input).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from framework.agents.guardrails import GuardrailContext, run_guardrails
from framework.agents.guardrails.registry import bind_schema_check
from framework.agents.llm_router import LLMRouter
from framework.agents.prompt_store import load_prompt
from framework.agents.state import CodeFinding, SRAState
from framework.agents.tools import ToolLog

AGENT_NAME = "code_analysis"


class ProbeOut(BaseModel):
    control_id: str
    expected_symbol: str = Field(max_length=100)
    regex: str = Field(max_length=200)


class PlannerOutput(BaseModel):
    probes: list[ProbeOut] = Field(default_factory=list)


class CodeFindingOut(BaseModel):
    control_id: str
    expected_symbol: str = Field(max_length=100)
    presence: Literal["confirmed", "insufficient", "absent"]
    citations: list[str] = Field(default_factory=list)
    note: str = Field(max_length=300)


class InterpreterOutput(BaseModel):
    findings: list[CodeFindingOut] = Field(default_factory=list)


# The interpreter's schema is what the guardrails run against for this agent.
bind_schema_check(AGENT_NAME, InterpreterOutput)


def run_code_analysis(state: SRAState) -> dict:
    if not state.current_threat:
        return {}

    # Collect controls to verify (only ones Compliance Mapper found present/partial).
    controls_to_verify: list[dict] = []
    seen: set[str] = set()
    for f in state.compliance_findings:
        # LangGraph may hand us back plain dicts or Pydantic models depending
        # on how the state was merged — handle both.
        verdict = f.verdict if hasattr(f, "verdict") else f.get("verdict")
        controls_list = f.existing_controls if hasattr(f, "existing_controls") else f.get("existing_controls", [])
        clause_id = f.clause_id if hasattr(f, "clause_id") else f.get("clause_id")
        if verdict not in {"present", "partial"}:
            continue
        for cid in controls_list or []:
            if cid in seen or not cid.startswith("CTRL:"):
                continue
            seen.add(cid)
            controls_to_verify.append({"control_id": cid, "clause_id": clause_id, "verdict": verdict})

    if not controls_to_verify:
        # Nothing for Code Analysis to check; still produce an entry noting so.
        return {"code_findings": []}

    tools = ToolLog(device=state.device)
    prompt = load_prompt(AGENT_NAME)
    router = LLMRouter(device=state.device, profile=state.profile,
                       prompt_log_path=state.prompt_log_path)

    # Fetch control descriptions so the planner LLM has meaningful context.
    ctrl_rows = tools.graph_cypher(
        "MATCH (c:Control) WHERE c.id IN $ids RETURN c.id AS id, c.description AS description;",
        params={"ids": [c["control_id"] for c in controls_to_verify]},
    )
    ctrl_desc = {r["id"]: r["description"] for r in ctrl_rows}
    for c in controls_to_verify:
        c["description"] = ctrl_desc.get(c["control_id"], "")

    # ---- Turn 1: Planner --------------------------------------------------
    planner_msg = _planner_message(state.current_threat, controls_to_verify)
    turn1 = router.call(
        agent_name=AGENT_NAME + ":planner",
        prompt=prompt,
        user_message=planner_msg,
        threat_id=state.current_threat,
        tool_calls_log=tools.as_records(),
    )
    if turn1.parsed_json is None:
        return {"code_findings": [],
                "warnings": [f"code_analysis[{state.current_threat}]: planner returned unparseable JSON"]}
    try:
        planner_out = PlannerOutput.model_validate(turn1.parsed_json)
    except Exception as e:
        return {"code_findings": [],
                "warnings": [f"code_analysis[{state.current_threat}]: planner schema fail: {e}"]}

    if not planner_out.probes:
        return {"code_findings": [],
                "warnings": [f"code_analysis[{state.current_threat}]: planner produced no probes"]}

    # ---- Python: run the greps -------------------------------------------
    probe_results: list[dict] = []
    tools_before = len(tools.calls)
    for probe in planner_out.probes[:6]:  # honor max_tool_iterations
        try:
            hits = tools.files_grep(
                pattern=probe.regex,
                glob="firmware/**/*.[ch]",
                max_hits=8,
                case_insensitive=True,
                context=0,
            )
        except Exception as e:
            hits = []
            probe_results.append({
                "control_id": probe.control_id, "expected_symbol": probe.expected_symbol,
                "regex": probe.regex, "error": str(e)[:150], "hits": [],
            })
            continue
        # Trim result payload to what the LLM needs
        thin_hits = [{"path": h["path"], "line": h["line"], "match": h["match"][:180]}
                     for h in hits[:8]]
        probe_results.append({
            "control_id": probe.control_id, "expected_symbol": probe.expected_symbol,
            "regex": probe.regex, "hits": thin_hits,
        })

    grep_calls_made = len(tools.calls) - tools_before

    # ---- Turn 2: Interpreter --------------------------------------------
    interp_msg = _interpreter_message(state.current_threat, probe_results)
    turn2 = router.call(
        agent_name=AGENT_NAME + ":interpreter",
        prompt=prompt,
        user_message=interp_msg,
        threat_id=state.current_threat,
        tool_calls_log=tools.as_records(),
    )
    if turn2.parsed_json is None:
        return {"code_findings": [],
                "warnings": [f"code_analysis[{state.current_threat}]: interpreter returned unparseable JSON"]}

    # ---- Guardrails on interpreter output ---------------------------------
    ctx = GuardrailContext(
        threat_id=state.current_threat,
        device=state.device,
        agent_name=AGENT_NAME,
    )
    passed, hard, soft = run_guardrails(turn2.parsed_json, ctx, prompt.guardrails_post)
    warnings: list[str] = list(soft)
    if not passed:
        return {"code_findings": [],
                "warnings": warnings + [f"code_analysis[{state.current_threat}]: hard-fail — {h}"
                                        for h in hard]}

    # ---- Convert to CodeFinding models -----------------------------------
    findings_out: list[CodeFinding] = []
    for f in turn2.parsed_json.get("findings", []):
        try:
            findings_out.append(CodeFinding(
                control_id=f["control_id"],
                expected_symbol=f["expected_symbol"][:100],
                presence=f["presence"],
                citations=list(f.get("citations", []))[:5],
                note=f.get("note", "")[:300],
            ))
        except (KeyError, TypeError):
            continue

    return {"code_findings": findings_out, "warnings": warnings}


# ---------------------------------------------------------------------------
# User-message assembly


def _planner_message(threat_id: str, controls: list[dict]) -> str:
    parts = [
        f"Turn 1 — Grep Plan for threat {threat_id}\n",
        "Controls to verify (verdicts came from Compliance Mapper):",
        "<CORPUS_UNTRUSTED>",
    ]
    for c in controls:
        parts.append(f"  - control_id: {c['control_id']}")
        parts.append(f"    description: {c.get('description', '(none)')}")
        parts.append(f"    clause_that_referenced_it: {c['clause_id']}")
        parts.append(f"    compliance_verdict: {c['verdict']}")
    parts.append("</CORPUS_UNTRUSTED>\n")
    parts.append(
        "Return JSON of shape "
        "{\"probes\": [{control_id, expected_symbol, regex}, ...]}. "
        "One probe per control. Regex is Python, matched line-by-line, case-insensitive."
    )
    return "\n".join(parts)


def _interpreter_message(threat_id: str, probe_results: list[dict]) -> str:
    parts = [
        f"Turn 2 — Interpretation for threat {threat_id}\n",
        "Grep results for each probe you proposed:",
        "<CORPUS_UNTRUSTED>",
    ]
    for pr in probe_results:
        parts.append(f"  - control_id: {pr['control_id']}")
        parts.append(f"    expected_symbol: {pr['expected_symbol']}")
        parts.append(f"    regex_used: {pr['regex']}")
        if pr.get("error"):
            parts.append(f"    error: {pr['error']}")
            parts.append("    hits: []")
            continue
        hits = pr.get("hits", [])
        if not hits:
            parts.append("    hits: []")
            continue
        parts.append(f"    hits ({len(hits)}):")
        for h in hits:
            parts.append(f"      - path: {h['path']}")
            parts.append(f"        line: {h['line']}")
            parts.append(f"        match: {h['match']!r}")
    parts.append("</CORPUS_UNTRUSTED>\n")
    parts.append(
        "Return JSON of shape "
        "{\"findings\": [{control_id, expected_symbol, presence, citations, note}, ...]}. "
        "One finding per probe. presence in {confirmed, insufficient, absent}. "
        "citations up to 5 per control, each as <path>:<line>. note under 300 chars."
    )
    return "\n".join(parts)
