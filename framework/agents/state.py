"""LangGraph state per SDD §6.

The whole draft pipeline mutates one SRAState object as it walks each threat
through Ingestion -> Compliance Mapper -> Code Analysis -> TCR -> Report.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


class ClauseFinding(BaseModel):
    clause_id: str
    clause_short_title: str
    verdict: Literal["present", "partial", "missing"]
    quote: str
    reason: str
    existing_controls: list[str] = Field(default_factory=list)


class CodeFinding(BaseModel):
    control_id: str
    expected_symbol: str
    presence: Literal["confirmed", "insufficient", "absent"]
    citations: list[str] = Field(default_factory=list)
    note: str


class SRAState(BaseModel):
    # Immutable per run
    device: str
    profile: Literal["free", "hybrid", "openai"] = "hybrid"
    started_at_utc: datetime
    corpus_commit_sha: str
    framework_commit_sha: str
    prompt_log_path: Path
    draft_md_path: Path
    draft_json_path: Path

    # Mutated during the run
    threat_queue: list[str] = Field(default_factory=list)
    current_threat: str | None = None
    compliance_findings: list[ClauseFinding] = Field(default_factory=list)
    code_findings: list[CodeFinding] = Field(default_factory=list)
    completed_entries: int = 0
    fallback_used: dict[str, str] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)

    class Config:
        arbitrary_types_allowed = True
