"""Guardrail #1 — citation verification (hard-fail).

Checks that every cited node id in the entry actually exists as a node
in the Kuzu graph. Prevents the LLM from inventing SRS/SDD/SDS/CTRL/
CODE ids.

The check walks common fields where ids appear:
  - existing_controls[*].id, proposed_controls[*].id  (must start with CTRL:)
  - findings[*].existing_controls[*]                  (Compliance Mapper output)
  - proposed_doc_changes[*].item_id                   (must match SRS-/SDD-/SDS-/SAD- pattern)
  - proposed_code_changes[*].path                     (path must exist as CodeArtifact)

Clause ids (FDA-*/IEC-*/AAMI-*/NIST-*) are verified by regex pattern only,
since Clause nodes are optional in the graph (may only live in vector store).
"""

from __future__ import annotations

import re
from typing import Any

from framework.agents.guardrails import GuardrailContext, GuardrailResult


_CTRL_RE = re.compile(r"^CTRL:")
_DOC_ID_RE = re.compile(r"^(SRS|SDD|SDS|SAD)-[A-Z]+-(\d{4}|SEC-NEW-\d+)$")
_CLAUSE_RE = re.compile(r"^(FDA-\d{4}|IEC-\d{5}-\d-\d|AAMI-TIR\d+|NIST-\d{3}-\d{3})-[A-Z0-9]+(\.[A-Z0-9]+)*$")


def check(entry: dict[str, Any], ctx: GuardrailContext) -> GuardrailResult:
    known = ctx.known_node_ids
    problems: list[str] = []

    # Control ids
    for path, cid in _collect(entry, "id"):
        if not cid:
            continue
        if not isinstance(cid, str):
            continue
        # CTRL:PROPOSED:* is new — allowed even if not in graph
        if cid.startswith("CTRL:PROPOSED:"):
            continue
        if cid.startswith("CTRL:"):
            if known and cid not in known:
                problems.append(f"{path}: {cid!r} not present in graph")

    # Compliance Mapper findings often carry existing_controls: list[str]
    findings = entry.get("findings")
    if isinstance(findings, list):
        for i, f in enumerate(findings):
            for j, cid in enumerate(f.get("existing_controls", []) or []):
                if isinstance(cid, str) and cid.startswith("CTRL:") and known and cid not in known:
                    problems.append(f"findings[{i}].existing_controls[{j}]: {cid!r} not in graph")

    # Doc change item ids
    for path, doc in _collect(entry, "item_id"):
        if isinstance(doc, str) and not _DOC_ID_RE.match(doc):
            problems.append(f"{path}: {doc!r} does not match SRS/SDD/SDS/SAD pattern")

    # Clause ids
    for path, cl in _collect(entry, "clause_id"):
        if isinstance(cl, str) and not _CLAUSE_RE.match(cl):
            problems.append(f"{path}: {cl!r} does not match a known clause id pattern")

    # Code artifact paths (only when we know the graph's code paths)
    if known:
        code_paths_in_graph = {nid.split(":", 2)[1] for nid in known
                               if isinstance(nid, str) and nid.startswith("CODE:")}
        for path, cp in _collect(entry, "path"):
            if isinstance(cp, str) and cp.startswith("firmware/"):
                if code_paths_in_graph and cp not in code_paths_in_graph:
                    problems.append(f"{path}: {cp!r} not present as CodeArtifact in graph")

    if problems:
        return GuardrailResult.hard_fail(*problems[:8])
    return GuardrailResult.ok()


def _collect(obj: Any, key: str, path: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            sub = f"{path}.{k}" if path else k
            if k == key:
                out.append((sub, v))
            else:
                out.extend(_collect(v, key, sub))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            out.extend(_collect(item, key, f"{path}[{i}]"))
    return out
