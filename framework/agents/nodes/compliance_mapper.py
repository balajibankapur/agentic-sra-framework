"""Compliance Mapper agent — SDD §2.2 (real).

For the current threat:
  1. Fetch threat details + linked existing controls from Kuzu.
  2. Retrieve candidate clauses from the `regulatory` collection in Chroma.
  3. Call the LLM (Gemini 2.5 Flash on free/hybrid, gpt-4o-mini on openai).
  4. Parse + validate the JSON verdict.
  5. Run post guardrails (schema, quote, citation, banned_crypto).
  6. Return findings for the state (or a placeholder finding + warning
     on hard-fail so the pipeline continues).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from framework.agents.guardrails import GuardrailContext, run_guardrails
from framework.agents.guardrails.registry import bind_schema_check
from framework.agents.llm_router import LLMRouter
from framework.agents.prompt_store import load_prompt
from framework.agents.state import ClauseFinding, SRAState
from framework.agents.tools import ToolLog


AGENT_NAME = "compliance_mapper"


# Pydantic schema the LLM output must satisfy for this agent.
class ComplianceFindingOut(BaseModel):
    clause_id: str
    clause_short_title: str = Field(max_length=120)
    verdict: Literal["present", "partial", "missing"]
    quote: str = Field(max_length=400)
    reason: str = Field(max_length=300)
    existing_controls: list[str] = Field(default_factory=list)


class ComplianceMapperOutput(BaseModel):
    findings: list[ComplianceFindingOut] = Field(default_factory=list)


# Register the schema binding once at import time.
bind_schema_check(AGENT_NAME, ComplianceMapperOutput)


def run_compliance_mapper(state: SRAState) -> dict:
    if not state.current_threat:
        return {}

    tools = ToolLog(device=state.device)

    # 1. Threat details + linked controls
    threat_rows = tools.graph_cypher(
        "MATCH (t:Threat {id: $id}) "
        "RETURN t.id AS id, t.title AS title, t.description AS description, "
        "t.stride AS stride, t.stride_category AS stride_category, "
        "t.priority AS priority, t.state AS state;",
        params={"id": state.current_threat},
    )
    if not threat_rows:
        return {"compliance_findings": [],
                "warnings": [f"compliance_mapper: threat {state.current_threat} not in graph"]}
    threat = threat_rows[0]

    control_rows = tools.graph_cypher(
        "MATCH (c:Control)-[:MITIGATES]->(t:Threat {id: $id}) "
        "RETURN c.id AS id, c.description AS description, c.kind AS kind;",
        params={"id": state.current_threat},
    )
    known_control_ids = {r["id"] for r in control_rows}

    # 2. Retrieve candidate clauses
    query_text = (
        f"{threat.get('title', '')} — {threat.get('description', '')[:600]}"
    )
    clause_hits = tools.vector_search(
        query=query_text,
        k=6,
        collection="regulatory",
    )
    if not clause_hits:
        return {"compliance_findings": [],
                "warnings": [f"compliance_mapper: no regulatory clauses retrieved for {state.current_threat} "
                             f"— was `sra index --regulatory` run?"]}

    # 3. Build the user message
    prompt = load_prompt(AGENT_NAME)
    user_msg = _build_user_message(threat, control_rows, clause_hits)

    # 4. Call LLM
    router = LLMRouter(device=state.device, profile=state.profile,
                       prompt_log_path=state.prompt_log_path)
    result = router.call(
        agent_name=AGENT_NAME,
        prompt=prompt,
        user_message=user_msg,
        threat_id=state.current_threat,
        tool_calls_log=tools.as_records(),
    )
    if result.parsed_json is None:
        return {"compliance_findings": [],
                "warnings": [f"compliance_mapper: LLM returned unparseable JSON for {state.current_threat}"]}

    # 5. Guardrails
    ctx = GuardrailContext(
        threat_id=state.current_threat,
        retrieved_chunks={c["id"]: c["text"] for c in clause_hits},
        known_node_ids=known_control_ids,
        device=state.device,
        agent_name=AGENT_NAME,
    )
    passed, hard, soft = run_guardrails(result.parsed_json, ctx, prompt.guardrails_post)

    warnings: list[str] = list(soft)
    if not passed:
        return {
            "compliance_findings": [],
            "warnings": warnings + [
                f"compliance_mapper[{state.current_threat}]: hard-fail — {h}" for h in hard
            ],
        }

    # 6. Convert to ClauseFinding models
    findings_out: list[ClauseFinding] = []
    for f in result.parsed_json.get("findings", []):
        try:
            findings_out.append(ClauseFinding(
                clause_id=f["clause_id"],
                clause_short_title=f.get("clause_short_title", "")[:120],
                verdict=f["verdict"],
                quote=f["quote"][:400],
                reason=f.get("reason", "")[:300],
                existing_controls=list(f.get("existing_controls", [])),
            ))
        except (KeyError, TypeError):
            continue

    return {"compliance_findings": findings_out, "warnings": warnings}


def _build_user_message(threat: dict, controls: list[dict], clauses: list[dict]) -> str:
    parts: list[str] = []
    parts.append("Threat under analysis:")
    parts.append("<CORPUS_UNTRUSTED>")
    parts.append(f"  id: {threat.get('id')}")
    parts.append(f"  title: {threat.get('title')}")
    parts.append(f"  stride: {threat.get('stride')} ({threat.get('stride_category')})")
    parts.append(f"  priority: {threat.get('priority')}")
    parts.append(f"  state: {threat.get('state')}")
    parts.append(f"  description: {threat.get('description')}")
    parts.append("</CORPUS_UNTRUSTED>\n")

    if controls:
        parts.append("Existing legacy controls linked to this threat:")
        parts.append("<CORPUS_UNTRUSTED>")
        for c in controls:
            parts.append(f"  - id: {c.get('id')}")
            parts.append(f"    description: {c.get('description')}")
        parts.append("</CORPUS_UNTRUSTED>\n")
    else:
        parts.append("Existing legacy controls linked to this threat: (none listed)\n")

    parts.append("Candidate regulatory clauses (retrieved by semantic search):")
    parts.append("<CORPUS_UNTRUSTED>")
    for c in clauses:
        md = c.get("metadata", {}) or {}
        parts.append(f"  - clause_id: {md.get('clause_id', c.get('id'))}")
        parts.append(f"    standard: {md.get('standard', '')}")
        parts.append(f"    section: {md.get('section', '')}")
        parts.append(f"    title: {md.get('title', '')}")
        parts.append("    body: |")
        for line in (c.get("text") or "").splitlines():
            parts.append(f"      {line}")
    parts.append("</CORPUS_UNTRUSTED>\n")

    parts.append(
        "Return JSON of shape "
        "{\"findings\": [{clause_id, clause_short_title, verdict, quote, reason, existing_controls}, ...]}. "
        "Include one entry per candidate clause. Verdicts: present | partial | missing. "
        "Only cite existing_controls from the list above. Quote is verbatim from the clause body."
    )
    return "\n".join(parts)
