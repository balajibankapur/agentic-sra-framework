"""Rollup — build the Provenance file from prompts.jsonl.

Walks the per-turn LLM log written by LLM Router and aggregates it into
one EntryProvenance per threat (models used, prompt versions, token
counts, per-agent cost, fallback events), plus a top-level Provenance
carrying device / commit SHAs / totals.

Called from `sra export`.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from framework.sra.provenance import EntryProvenance, Provenance


def build_provenance(
    device: str,
    profile: str,
    corpus_commit_sha: str,
    framework_commit_sha: str,
    prompts_log_path: Path,
    draft_json_path: Path,
    started_at_utc: datetime | None = None,
) -> Provenance:
    """Assemble a Provenance object from the run's prompts.jsonl."""
    entries: dict[str, EntryProvenance] = {}
    total_cost = 0.0
    earliest: datetime | None = started_at_utc

    if prompts_log_path.exists():
        for line in prompts_log_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            entry_id = r.get("entry_id") or ""
            if not entry_id:
                continue
            agent = r.get("agent", "unknown")
            model = r.get("model", "")
            tokens_in = int(r.get("tokens_in", 0))
            tokens_out = int(r.get("tokens_out", 0))
            cost = float(r.get("cost_usd_est", 0.0))
            total_cost += cost

            ep = entries.setdefault(entry_id, EntryProvenance(threat_id=entry_id))
            # Use the agent's canonical name (drop `:planner`/`:interpreter` suffixes)
            base_agent = agent.split(":", 1)[0]
            ep.prompt_versions.setdefault(base_agent, r.get("prompt_version", ""))
            ep.models_used[base_agent] = model
            tok = ep.tokens.setdefault(base_agent, {"in": 0, "out": 0})
            tok["in"] += tokens_in
            tok["out"] += tokens_out

            if r.get("fallback_used"):
                ep.guardrail_results.setdefault("fallbacks", []).append(
                    f"{agent}: {r['fallback_used']}"
                )

            ts_str = r.get("timestamp_utc")
            if ts_str:
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    if earliest is None or ts < earliest:
                        earliest = ts
                except ValueError:
                    pass

    # Merge in warnings + parse_error info from the draft entries.
    if draft_json_path.exists():
        try:
            draft = json.loads(draft_json_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            draft = []
        for e in draft:
            if not isinstance(e, dict):
                continue
            tid = e.get("threat_id")
            if not tid:
                continue
            ep = entries.setdefault(tid, EntryProvenance(threat_id=tid))
            if e.get("warnings"):
                ep.guardrail_results.setdefault("warnings", []).extend(
                    str(w) for w in e["warnings"]
                )
            if e.get("parse_error"):
                ep.guardrail_results.setdefault("parse_error", []).append(
                    "TCR entry marked parse_error — raw response preserved in draft.json"
                )

    return Provenance(
        device=device,
        profile=profile,  # type: ignore[arg-type]
        corpus_commit_sha=corpus_commit_sha,
        framework_commit_sha=framework_commit_sha,
        started_at_utc=earliest or datetime.now(timezone.utc),
        completed_at_utc=datetime.now(timezone.utc),
        total_cost_usd_est=round(total_cost, 5),
        entries=entries,
    )
