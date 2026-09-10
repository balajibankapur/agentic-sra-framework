"""Provenance schemas per SDD §9.

Provenance records how each SRA entry was produced: models used, prompt
versions, guardrail results, review decisions, timestamps.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class EntryProvenance(BaseModel):
    threat_id: str
    prompt_versions: dict[str, str] = Field(default_factory=dict)
    models_used: dict[str, str] = Field(default_factory=dict)
    tokens: dict[str, dict[str, int]] = Field(default_factory=dict)
    guardrail_results: dict[str, list[str]] = Field(default_factory=dict)
    review_decision: Literal["approved", "edited", "rejected", "deferred", "pending"] = "pending"
    reviewer_name: str | None = None
    review_timestamp_utc: datetime | None = None
    review_notes: str = ""


class Provenance(BaseModel):
    device: str
    profile: Literal["free", "hybrid", "openai"]
    corpus_commit_sha: str
    framework_commit_sha: str
    embedding_model: str = "openai/text-embedding-3-large"
    started_at_utc: datetime
    completed_at_utc: datetime | None = None
    total_cost_usd_est: float = 0.0
    entries: dict[str, EntryProvenance] = Field(default_factory=dict)
