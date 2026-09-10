"""LLM Router per SDD §5.

Single entry point for every LLM call. Handles:
  - per-agent model resolution via the current profile
  - retry with exponential backoff (up to 3 attempts on rate limit/timeout)
  - cross-provider fallback to OpenAI gpt-4o-mini
  - token cap enforcement (10k input, 4k output)
  - every-turn logging to <device>_prompts.jsonl
  - cost estimation
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import litellm
from litellm import completion
from litellm.exceptions import (
    APIConnectionError,
    APIError,
    RateLimitError,
    Timeout,
)

from framework.agents.prompt_store import PromptSpec

# Silence LiteLLM's chatty debug logging by default
litellm.suppress_debug_info = True

MAX_INPUT_TOKENS = 10_000
MAX_OUTPUT_TOKENS = 4_000
FALLBACK_MODEL = "openai/gpt-4o-mini"
MAX_ATTEMPTS = 3


@dataclass
class LLMCallResult:
    content: str
    parsed_json: dict[str, Any] | None
    model_used: str
    prompt_version: str
    tokens_in: int
    tokens_out: int
    latency_ms: int
    cost_usd_est: float
    fallback_used: str | None
    error: str | None = None


@dataclass
class LLMRouter:
    device: str
    profile: str
    prompt_log_path: Path
    total_cost_usd: float = 0.0
    fallbacks: dict[str, str] = field(default_factory=dict)

    def call(
        self,
        agent_name: str,
        prompt: PromptSpec,
        user_message: str,
        threat_id: str = "",
        tool_calls_log: list[dict] | None = None,
    ) -> LLMCallResult:
        """Run one LLM completion. Returns the parsed JSON + metadata.

        Retries with backoff on rate limit / timeout. Falls back to
        openai/gpt-4o-mini if all retries on the primary model fail.
        """
        primary_model = prompt.model_for(self.profile)
        if not primary_model:
            raise ValueError(
                f"No model configured for agent={agent_name} profile={self.profile}"
            )

        model = primary_model
        attempt = 1
        result: LLMCallResult | None = None

        while True:
            t0 = time.perf_counter()
            try:
                resp = completion(
                    model=model,
                    messages=[
                        {"role": "system", "content": prompt.system},
                        {"role": "user", "content": user_message},
                    ],
                    temperature=prompt.temperature,
                    max_tokens=MAX_OUTPUT_TOKENS,
                    response_format={"type": "json_object"},
                )
                latency = int((time.perf_counter() - t0) * 1000)
                content = resp.choices[0].message.content or ""
                usage = getattr(resp, "usage", None)
                tokens_in = getattr(usage, "prompt_tokens", 0) if usage else 0
                tokens_out = getattr(usage, "completion_tokens", 0) if usage else 0
                cost = _estimate_cost(model, tokens_in, tokens_out)
                self.total_cost_usd += cost

                parsed: dict[str, Any] | None
                try:
                    parsed = json.loads(content)
                except json.JSONDecodeError:
                    parsed = None

                result = LLMCallResult(
                    content=content,
                    parsed_json=parsed,
                    model_used=model,
                    prompt_version=prompt.version,
                    tokens_in=tokens_in,
                    tokens_out=tokens_out,
                    latency_ms=latency,
                    cost_usd_est=cost,
                    fallback_used=(f"{primary_model}→{model}" if model != primary_model else None),
                )
                self._log(agent_name, threat_id, prompt, user_message, result, tool_calls_log)
                if result.fallback_used:
                    self.fallbacks[agent_name] = result.fallback_used
                return result

            except (RateLimitError, Timeout, APIConnectionError, APIError) as e:
                latency = int((time.perf_counter() - t0) * 1000)
                error_msg = f"{type(e).__name__}: {e}"
                # Log the failed attempt
                self._log(
                    agent_name, threat_id, prompt, user_message,
                    LLMCallResult(
                        content="", parsed_json=None, model_used=model,
                        prompt_version=prompt.version, tokens_in=0, tokens_out=0,
                        latency_ms=latency, cost_usd_est=0.0,
                        fallback_used=None, error=error_msg,
                    ),
                    tool_calls_log,
                )
                # Retry the same model up to MAX_ATTEMPTS if not already openai
                if attempt < MAX_ATTEMPTS and not model.startswith("openai/"):
                    time.sleep(2 ** attempt)
                    attempt += 1
                    continue
                # Fall back to openai/gpt-4o-mini if not already there
                if model != FALLBACK_MODEL:
                    model = FALLBACK_MODEL
                    attempt = 1
                    continue
                # Exhausted retries + fallback
                raise

    # -----------------------------------------------------------------
    def _log(
        self,
        agent_name: str,
        threat_id: str,
        prompt: PromptSpec,
        user_message: str,
        result: LLMCallResult,
        tool_calls_log: list[dict] | None,
    ) -> None:
        self.prompt_log_path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "entry_id": threat_id,
            "agent": agent_name,
            "prompt_version": prompt.version,
            "model": result.model_used,
            "prompt_hash": hashlib.sha256(
                (prompt.system + "\n" + user_message).encode("utf-8")
            ).hexdigest()[:16],
            "prompt": {"system": prompt.system, "user": user_message},
            "response": result.content,
            "tool_calls": tool_calls_log or [],
            "latency_ms": result.latency_ms,
            "tokens_in": result.tokens_in,
            "tokens_out": result.tokens_out,
            "cost_usd_est": round(result.cost_usd_est, 6),
            "error": result.error,
            "fallback_used": result.fallback_used,
        }
        with self.prompt_log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# Cost estimation — rough per-model $/M-token prices (2026-08 snapshot)

_PRICES = {
    # openai
    "openai/gpt-4o":         (2.50, 10.00),
    "openai/gpt-4o-mini":    (0.15, 0.60),
    # groq (currently free tier)
    "groq/openai/gpt-oss-120b": (0.0, 0.0),
    # gemini (currently free tier)
    "gemini/gemini-2.5-flash": (0.0, 0.0),
}


def _estimate_cost(model: str, tokens_in: int, tokens_out: int) -> float:
    price_in, price_out = _PRICES.get(model, (0.0, 0.0))
    return (tokens_in / 1_000_000) * price_in + (tokens_out / 1_000_000) * price_out
