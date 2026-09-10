"""Prompt Store per SDD §3.

Loads per-agent YAML prompts, resolves the model for the current profile,
and hands the assembled prompt to the LLM router. Prompts are cached in
memory per `sra draft` run and live-edited between runs.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


PROMPTS_DIR = Path(__file__).parent / "prompts"


@dataclass
class PromptSpec:
    agent_name: str          # "compliance_mapper" | ...
    version: str             # "1.0"
    model_profile: dict[str, str]  # {"free": "...", "hybrid": "...", "openai": "..."}
    temperature: float
    system: str              # the system prompt text
    output_schema: dict[str, Any]  # JSON schema for the response
    guardrails_post: list[str]     # ["schema_check", "cvss_check", ...]
    max_tool_iterations: int = 6
    file_mtime: float = 0.0
    file_path: Path = Path()

    def model_for(self, profile: str) -> str:
        """Resolve the LiteLLM model id for the requested profile.

        Falls back to `hybrid` when the requested profile is not defined.
        """
        return self.model_profile.get(profile, self.model_profile.get("hybrid", ""))


def load_prompt(agent_name: str, prompts_dir: Path | None = None) -> PromptSpec:
    """Load one agent's prompt YAML.

    Cached by file path + mtime so live edits between runs pick up the new
    version without a full process restart.
    """
    root = prompts_dir or PROMPTS_DIR
    path = root / f"{agent_name}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"Prompt YAML not found: {path}")
    mtime = path.stat().st_mtime
    return _load_cached(path, mtime, agent_name)


@lru_cache(maxsize=32)
def _load_cached(path: Path, mtime: float, agent_name: str) -> PromptSpec:
    raw = yaml.safe_load(path.read_text())
    return PromptSpec(
        agent_name=agent_name,
        version=str(raw.get("version", "0.0")),
        model_profile=raw.get("model_profile", {}),
        temperature=float(raw.get("temperature", 0.0)),
        system=raw.get("system", ""),
        output_schema=raw.get("output_schema", {}),
        guardrails_post=list(raw.get("guardrails_post", [])),
        max_tool_iterations=int(raw.get("max_tool_iterations", 6)),
        file_mtime=mtime,
        file_path=path,
    )
