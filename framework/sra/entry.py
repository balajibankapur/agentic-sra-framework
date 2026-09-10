"""SRAEntry — the 12-field SRA entry per SDD §8.

This is the source-of-truth data model. Every agent output and every UI
render goes through this schema.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class CVSS(BaseModel):
    vector: str  # e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    base_score: float = Field(ge=0.0, le=10.0)
    temporal_score: float | None = Field(default=None, ge=0.0, le=10.0)
    environmental_score: float | None = Field(default=None, ge=0.0, le=10.0)
    severity: Literal["None", "Low", "Medium", "High", "Critical"]


class ControlRef(BaseModel):
    id: str  # "CTRL:crc-32-image-check" or "CTRL:PROPOSED:ed25519-image-sig"
    description: str
    kind: Literal["legacy", "proposed"]


class GapItem(BaseModel):
    clause_id: str  # "FDA-2023-V.B.3"
    verdict: Literal["present", "partial", "missing"]
    quote: str = Field(max_length=400)
    reason: str = Field(max_length=300)


class DocChange(BaseModel):
    doc: Literal["SRS.md", "SDD.md", "SDS.md", "SAD.md"]
    action: Literal["add", "modify", "delete"]
    item_id: str
    body: str


class CodeChange(BaseModel):
    path: str
    line: int = Field(ge=0)
    action: Literal["add", "modify", "delete", "create_file"]
    hunk: str


class SRAEntry(BaseModel):
    # 1
    threat_id: str
    # 2
    title: str
    # 3
    stride: Literal["S", "T", "R", "I", "D", "E"]
    # 4
    assets_affected: list[str] = Field(default_factory=list)
    # 5
    existing_controls: list[ControlRef] = Field(default_factory=list)
    # 6
    gap_analysis: list[GapItem] = Field(default_factory=list)
    # 7
    cvss_v31: CVSS
    # 8
    residual_risk: Literal["High", "Medium", "Low"]
    residual_risk_reason: str
    # 9
    proposed_controls: list[ControlRef] = Field(default_factory=list)
    # 10
    proposed_doc_changes: list[DocChange] = Field(default_factory=list)
    # 11
    proposed_code_changes: list[CodeChange] = Field(default_factory=list)
    # 12
    priority: Literal["P0", "P1", "P2"]
    effort_engineer_weeks: float = Field(ge=0.0)
    # Non-numbered metadata (always present)
    narrative: str = ""
    warnings: list[str] = Field(default_factory=list)
    parse_error: bool = False
    raw_llm_response: str | None = None
