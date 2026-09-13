"""Shared pytest fixtures."""

from __future__ import annotations

import pytest

from framework.agents.guardrails import GuardrailContext
from framework.sra.entry import CVSS, ControlRef, DocChange, GapItem, SRAEntry


@pytest.fixture
def valid_entry() -> dict:
    """A schema-valid, guardrail-clean SRA entry (dumped as dict)."""
    entry = SRAEntry(
        threat_id="T-OTA-P01-T",
        title="Unsigned firmware image accepted at install",
        stride="T",
        assets_affected=["DFD:T-OTA-P01"],
        existing_controls=[
            ControlRef(id="CTRL:crc-32-image-check",
                       description="CRC-32 image integrity check (legacy)",
                       kind="legacy"),
        ],
        gap_analysis=[
            GapItem(
                clause_id="FDA-2023-V.B.3",
                verdict="missing",
                quote="Firmware images and any over-the-air or in-field update artifacts "
                      "shall be protected with cryptographic authenticity verification",
                reason="Only CRC-32 present; no signature verification.",
            ),
        ],
        cvss_v31=CVSS(
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            base_score=10.0,
            severity="Critical",
        ),
        residual_risk="Low",
        residual_risk_reason="Ed25519 signature verify closes the attack surface.",
        proposed_controls=[
            ControlRef(id="CTRL:PROPOSED:ed25519-image-sig",
                       description="Ed25519 signature over firmware manifest + image",
                       kind="proposed"),
        ],
        proposed_doc_changes=[
            DocChange(doc="SRS.md", action="add", item_id="SRS-SEC-NEW-01",
                      body="Firmware images shall be signed with Ed25519."),
        ],
        priority="P0",
        effort_engineer_weeks=2.0,
        narrative="OTA install accepts firmware with only CRC-32. Add Ed25519.",
    )
    return entry.model_dump(mode="json")


@pytest.fixture
def ctx_empty() -> GuardrailContext:
    return GuardrailContext(threat_id="T-OTA-P01-T", agent_name="threat_control_risk")


@pytest.fixture
def ctx_with_chunks(valid_entry) -> GuardrailContext:
    """Context with a retrieved chunk that matches the entry's quote."""
    quote_text = valid_entry["gap_analysis"][0]["quote"]
    return GuardrailContext(
        threat_id="T-OTA-P01-T",
        retrieved_chunks={"FDA-2023-V.B.3": f"prefix ... {quote_text} ... suffix"},
        known_node_ids={"CTRL:crc-32-image-check"},
        agent_name="threat_control_risk",
    )
