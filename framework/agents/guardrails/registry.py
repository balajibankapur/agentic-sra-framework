"""Guardrail registry — maps guardrail names in prompt YAML to callables.

New guardrail modules register here so `run_guardrails(...)` can find them
by name (e.g. `"cvss_check"`) from a prompt's `guardrails_post` list.
"""

from __future__ import annotations

from typing import Any, Callable

from framework.agents.guardrails import GuardrailContext, GuardrailResult
from framework.agents.guardrails.banned_crypto import check as banned_crypto
from framework.agents.guardrails.citation_verify import check as citation_verify
from framework.agents.guardrails.citation_verify_file import check as citation_verify_file
from framework.agents.guardrails.cvss_check import check as cvss_check
from framework.agents.guardrails.legacy_taxonomy_check import check as legacy_taxonomy_check
from framework.agents.guardrails.quote_check import check as quote_check
from framework.agents.guardrails.schema_check import make_schema_check
from framework.agents.guardrails.scope_check import check as scope_check
from framework.sra.entry import SRAEntry


# Default schema_check binding uses the SRAEntry Pydantic model (for TCR).
# Compliance Mapper and other agents pass their own binding through
# `bind_schema_check(agent_name, model)` before running guardrails.
_default_schema_check = make_schema_check(SRAEntry)
_SCHEMA_BINDINGS: dict[str, Callable[[dict[str, Any], GuardrailContext], GuardrailResult]] = {}


def bind_schema_check(agent_name: str, model) -> None:
    """Register a per-agent schema_check binding (called at agent startup)."""
    _SCHEMA_BINDINGS[agent_name] = make_schema_check(model)


def _resolve_schema_check(entry: dict[str, Any], ctx: GuardrailContext) -> GuardrailResult:
    # ctx.threat_id doesn't help; use a magic __agent__ key stashed in ctx
    agent = getattr(ctx, "agent_name", "") or ""
    fn = _SCHEMA_BINDINGS.get(agent, _default_schema_check)
    return fn(entry, ctx)


RESOLVERS: dict[str, Callable[[dict[str, Any], GuardrailContext], GuardrailResult]] = {
    "schema_check": _resolve_schema_check,
    "cvss_check": cvss_check,
    "citation_verify": citation_verify,
    "citation_verify_file": citation_verify_file,
    "quote_check": quote_check,
    "banned_crypto": banned_crypto,
    "legacy_taxonomy_check": legacy_taxonomy_check,
    "scope_check": scope_check,
}
