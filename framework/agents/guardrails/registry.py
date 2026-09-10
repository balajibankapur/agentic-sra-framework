"""Guardrail registry — maps guardrail names in prompt YAML to callables.

New guardrail modules register here so `run_guardrails(...)` can find them
by name (e.g. `"cvss_check"`) from a prompt's `guardrails_post` list.
"""

from __future__ import annotations

from typing import Any, Callable

from framework.agents.guardrails import GuardrailContext, GuardrailResult
from framework.agents.guardrails.cvss_check import check as cvss_check
from framework.agents.guardrails.schema_check import make_schema_check
from framework.sra.entry import SRAEntry


# Bind schema_check to the SRAEntry Pydantic model for the TCR agent.
# When other agents need schema checks, they'll get their own binding.
_sra_entry_schema_check = make_schema_check(SRAEntry)


RESOLVERS: dict[str, Callable[[dict[str, Any], GuardrailContext], GuardrailResult]] = {
    "schema_check": _sra_entry_schema_check,
    "cvss_check": cvss_check,
    # citation_verify, quote_check, banned_crypto, legacy_taxonomy_check,
    # scope_check, citation_verify_file — added in later sub-phases.
}
