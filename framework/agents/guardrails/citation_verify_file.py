"""Guardrail (Code Analysis) — every cited `<path>:<line>` must exist.

For each citation string in the entry, verify:
  1. The path resolves inside input/<device>/ (no traversal).
  2. The file exists.
  3. The line number is within the file's total line count.

Runs in the corpus-files server's read function to reuse path safety.
"""

from __future__ import annotations

import re
from typing import Any

from framework.agents.guardrails import GuardrailContext, GuardrailResult
from framework.config import device_input_dir

_CITE_RE = re.compile(r"^(?P<path>[^:]+):(?P<line>\d+)$")


def check(entry: dict[str, Any], ctx: GuardrailContext) -> GuardrailResult:
    problems: list[str] = []
    for path_prefix, citations in _collect_citations(entry):
        for c in citations:
            if not isinstance(c, str):
                continue
            m = _CITE_RE.match(c.strip())
            if not m:
                problems.append(f"{path_prefix}: {c!r} is not <path>:<line>")
                continue
            rel = m.group("path")
            line = int(m.group("line"))
            file_path = device_input_dir(ctx.device or "pmx100") / rel
            try:
                resolved = file_path.resolve()
                resolved.relative_to(device_input_dir(ctx.device or "pmx100").resolve())
            except Exception:
                problems.append(f"{path_prefix}: {c!r} escapes device root")
                continue
            if not resolved.exists() or not resolved.is_file():
                problems.append(f"{path_prefix}: file {rel!r} does not exist")
                continue
            try:
                total_lines = sum(1 for _ in resolved.open("rb"))
            except OSError:
                problems.append(f"{path_prefix}: cannot read {rel!r}")
                continue
            if line < 1 or line > total_lines:
                problems.append(f"{path_prefix}: line {line} out of range for {rel!r} "
                                f"(has {total_lines} lines)")

    if problems:
        return GuardrailResult.hard_fail(*problems[:8])
    return GuardrailResult.ok()


def _collect_citations(obj: Any, path: str = "") -> list[tuple[str, list]]:
    """Walk obj and yield every list of citations found under a `citations` key."""
    out: list[tuple[str, list]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            sub = f"{path}.{k}" if path else k
            if k == "citations" and isinstance(v, list):
                out.append((sub, v))
            else:
                out.extend(_collect_citations(v, sub))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            out.extend(_collect_citations(item, f"{path}[{i}]"))
    return out
