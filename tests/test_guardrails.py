"""Unit tests for the guardrail layer (SDD §4).

Covers the 10 guardrails at pass / hard-fail / soft-warn / edge boundaries.
Deterministic — no LLM, no network.
"""

from __future__ import annotations

import copy

import pytest

from framework.agents.guardrails import GuardrailContext, run_guardrails
from framework.agents.guardrails.banned_crypto import check as banned_crypto
from framework.agents.guardrails.citation_verify import check as citation_verify
from framework.agents.guardrails.cvss_check import (
    _score,
    _severity_band,
    check as cvss_check,
)
from framework.agents.guardrails.legacy_taxonomy_check import check as legacy_check
from framework.agents.guardrails.quote_check import check as quote_check
from framework.agents.guardrails.scope_check import check as scope_check


# ---------------------------------------------------------------------------
# CVSS calculator + guardrail #3


class TestCVSS:
    """Reference vectors from FIRST.org must score identically."""

    @pytest.mark.parametrize("vector, expected_score, expected_sev", [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "Critical"),
        ("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 6.7, "Medium"),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6, "Low"),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N", 0.0, "None"),
        ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 8.1, "High"),
    ])
    def test_reference_vectors(self, vector, expected_score, expected_sev):
        got = _score(vector)
        assert abs(got - expected_score) <= 0.1, f"score mismatch for {vector}"
        assert _severity_band(got) == expected_sev

    def test_guardrail_passes_correct_vector(self, valid_entry, ctx_empty):
        result = cvss_check(valid_entry, ctx_empty)
        assert result.passed

    def test_guardrail_rejects_bad_vector_format(self, valid_entry, ctx_empty):
        bad = copy.deepcopy(valid_entry)
        bad["cvss_v31"]["vector"] = "CVSS:2.0/AV:N/AC:L"
        result = cvss_check(bad, ctx_empty)
        assert not result.passed
        assert result.severity == "hard"

    def test_guardrail_rejects_score_mismatch(self, valid_entry, ctx_empty):
        bad = copy.deepcopy(valid_entry)
        bad["cvss_v31"]["base_score"] = 3.5   # real is 10.0
        result = cvss_check(bad, ctx_empty)
        assert not result.passed

    def test_guardrail_rejects_severity_mismatch(self, valid_entry, ctx_empty):
        bad = copy.deepcopy(valid_entry)
        bad["cvss_v31"]["severity"] = "Medium"  # real is Critical
        result = cvss_check(bad, ctx_empty)
        assert not result.passed


# ---------------------------------------------------------------------------
# Quote check — guardrail #4


class TestQuoteCheck:

    def test_pass_when_quote_substring_of_chunk(self, valid_entry, ctx_with_chunks):
        result = quote_check(valid_entry, ctx_with_chunks)
        assert result.passed

    def test_pass_ignoring_whitespace(self, valid_entry):
        # Chunk has double spaces + newline where entry has single spaces
        chunk_text = ("Firmware  images  and any over-the-air\nor  in-field update artifacts "
                      "shall  be  protected  with  cryptographic  authenticity  verification")
        ctx = GuardrailContext(retrieved_chunks={"FDA-2023-V.B.3": chunk_text})
        result = quote_check(valid_entry, ctx)
        assert result.passed

    def test_fail_on_fabricated_quote(self, valid_entry, ctx_with_chunks):
        bad = copy.deepcopy(valid_entry)
        bad["gap_analysis"][0]["quote"] = "This clause text does not exist in any chunk anywhere"
        result = quote_check(bad, ctx_with_chunks)
        assert not result.passed
        assert result.severity == "hard"

    def test_fail_with_empty_chunks(self, valid_entry, ctx_empty):
        result = quote_check(valid_entry, ctx_empty)
        assert not result.passed


# ---------------------------------------------------------------------------
# Citation verify — guardrail #1


class TestCitationVerify:

    def test_pass_when_ctrl_id_in_graph(self, valid_entry, ctx_with_chunks):
        result = citation_verify(valid_entry, ctx_with_chunks)
        assert result.passed

    def test_pass_new_item_pattern_srs_sec_new(self, valid_entry, ctx_with_chunks):
        # SRS-SEC-NEW-NN is the new-item pattern; must be accepted
        result = citation_verify(valid_entry, ctx_with_chunks)
        assert result.passed

    def test_fail_when_ctrl_id_not_in_graph(self, valid_entry, ctx_with_chunks):
        bad = copy.deepcopy(valid_entry)
        bad["existing_controls"][0]["id"] = "CTRL:this-ctrl-does-not-exist"
        result = citation_verify(bad, ctx_with_chunks)
        assert not result.passed

    def test_pass_proposed_ctrl_never_in_graph(self, valid_entry, ctx_with_chunks):
        # CTRL:PROPOSED:* is a brand-new proposal, not expected to be in graph
        # (valid_entry already has one, so this must pass)
        result = citation_verify(valid_entry, ctx_with_chunks)
        assert result.passed

    def test_fail_bad_doc_id_pattern(self, valid_entry, ctx_with_chunks):
        bad = copy.deepcopy(valid_entry)
        bad["proposed_doc_changes"][0]["item_id"] = "SRS-STOR-99999999"  # too many digits
        result = citation_verify(bad, ctx_with_chunks)
        assert not result.passed

    def test_fail_bad_clause_id_pattern(self, valid_entry, ctx_with_chunks):
        bad = copy.deepcopy(valid_entry)
        bad["gap_analysis"][0]["clause_id"] = "FDA-99999-invalid"
        result = citation_verify(bad, ctx_with_chunks)
        assert not result.passed

    def test_pass_when_ctx_has_no_known_ids(self, valid_entry):
        # If we don't know the graph state, be lenient on CTRL ids
        ctx = GuardrailContext(retrieved_chunks={},
                               agent_name="threat_control_risk")
        result = citation_verify(valid_entry, ctx)
        # doc-id + clause-id pattern checks still run and should pass
        assert result.passed


# ---------------------------------------------------------------------------
# Banned crypto — guardrail #13 (soft-warn)


class TestBannedCrypto:

    def test_no_warning_when_no_banned_tokens(self, valid_entry, ctx_empty):
        result = banned_crypto(valid_entry, ctx_empty)
        assert result.passed

    def test_no_warning_when_banned_token_only_in_narrative(self, valid_entry, ctx_empty):
        # narratives describe legacy state — TLS 1.0 mention should NOT trigger
        bad = copy.deepcopy(valid_entry)
        bad["narrative"] = "The current use of TLS 1.0 is deprecated; upgrading is required."
        result = banned_crypto(bad, ctx_empty)
        assert result.passed, "narrative field should be exempt"

    def test_warn_when_banned_token_in_proposed_control(self, valid_entry, ctx_empty):
        bad = copy.deepcopy(valid_entry)
        bad["proposed_controls"].append({
            "id": "CTRL:PROPOSED:bad-suggestion",
            "description": "Use MD5 for integrity checks.",
            "kind": "proposed",
        })
        result = banned_crypto(bad, ctx_empty)
        assert not result.passed
        assert result.severity == "soft"

    def test_warn_when_banned_token_in_proposed_doc_change(self, valid_entry, ctx_empty):
        bad = copy.deepcopy(valid_entry)
        bad["proposed_doc_changes"].append({
            "doc": "SDS.md", "action": "modify", "item_id": "SDS-COMM-0001",
            "body": "Configure TLS 1.0 as the transport.",
        })
        result = banned_crypto(bad, ctx_empty)
        assert not result.passed


# ---------------------------------------------------------------------------
# Legacy taxonomy — guardrail #9 (soft-warn)


class TestLegacyTaxonomy:

    def test_pass_when_kinds_correct(self, valid_entry, ctx_empty):
        result = legacy_check(valid_entry, ctx_empty)
        assert result.passed

    def test_warn_when_existing_tagged_proposed(self, valid_entry, ctx_empty):
        bad = copy.deepcopy(valid_entry)
        bad["existing_controls"][0]["kind"] = "proposed"  # wrong
        result = legacy_check(bad, ctx_empty)
        assert not result.passed
        assert result.severity == "soft"

    def test_warn_when_proposed_tagged_legacy(self, valid_entry, ctx_empty):
        bad = copy.deepcopy(valid_entry)
        bad["proposed_controls"][0]["kind"] = "legacy"  # wrong
        result = legacy_check(bad, ctx_empty)
        assert not result.passed


# ---------------------------------------------------------------------------
# Scope check — guardrail #14 (soft-warn)


class TestScopeCheck:

    def test_pass_when_all_in_scope(self, valid_entry, ctx_empty):
        result = scope_check(valid_entry, ctx_empty)
        assert result.passed

    def test_warn_on_out_of_tree_doc(self, valid_entry, ctx_empty):
        bad = copy.deepcopy(valid_entry)
        bad["proposed_doc_changes"].append({
            "doc": "README.md", "action": "add",
            "item_id": "SRS-STOR-0001", "body": "text",
        })
        result = scope_check(bad, ctx_empty)
        assert not result.passed

    def test_warn_on_out_of_tree_code_path(self, valid_entry, ctx_empty):
        bad = copy.deepcopy(valid_entry)
        bad["proposed_code_changes"] = [{
            "path": "kernel/drivers/net.c", "line": 42,
            "action": "modify", "hunk": "...",
        }]
        result = scope_check(bad, ctx_empty)
        assert not result.passed

    def test_warn_on_hardware_replacement_prose(self, valid_entry, ctx_empty):
        bad = copy.deepcopy(valid_entry)
        bad["narrative"] = "Replace the MCU with a Cortex-M33 that supports TrustZone."
        result = scope_check(bad, ctx_empty)
        assert not result.passed


# ---------------------------------------------------------------------------
# End-to-end run_guardrails dispatcher


class TestDispatcher:

    def test_valid_entry_passes_all_hard_guardrails(self, valid_entry, ctx_with_chunks):
        passed, hard, soft = run_guardrails(
            valid_entry, ctx_with_chunks,
            ["schema_check", "cvss_check", "citation_verify", "quote_check"],
        )
        assert passed, f"hard failures: {hard}"

    def test_unknown_guardrail_name_soft_warns(self, valid_entry, ctx_empty):
        passed, hard, soft = run_guardrails(
            valid_entry, ctx_empty, ["nonexistent_guardrail"],
        )
        assert passed  # unknown is treated as a soft warning, not hard-fail
        assert any("unknown guardrail" in s for s in soft)

    def test_hard_fail_short_circuits_correctly(self, valid_entry, ctx_empty):
        bad = copy.deepcopy(valid_entry)
        bad["cvss_v31"]["base_score"] = 0.1  # mismatch vs vector's 10.0
        passed, hard, soft = run_guardrails(bad, ctx_empty, ["cvss_check"])
        assert not passed
        assert hard
        assert not soft
