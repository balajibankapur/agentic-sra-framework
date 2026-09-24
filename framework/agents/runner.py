"""Runner — assembles the SRAState and invokes the LangGraph pipeline.

The CLI's `sra draft` subcommand delegates here.
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from framework.agents.graph import build_graph
from framework.agents.state import SRAState
from framework.config import OUTPUT_DIR, REPO_ROOT, device_input_dir, device_manifest_path

console = Console()


def _framework_commit_sha() -> str:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
        return out.decode().strip()
    except Exception:
        return "unknown"


def _corpus_commit_sha(device: str) -> str:
    manifest = device_manifest_path(device)
    if not manifest.exists():
        return "unknown"
    try:
        return json.loads(manifest.read_text()).get("commit_sha", "unknown")
    except Exception:
        return "unknown"


def run_draft(
    device: str,
    profile: Literal["free", "hybrid", "openai"] = "hybrid",
    category: str | None = None,
    threat: str | None = None,
    limit: int | None = None,
    strategy: str = "priority",
    extra_context: str = "",
    resume: bool = False,
) -> SRAState:
    """Kick off the LangGraph draft pipeline for one device.

    Returns the terminal SRAState (for the CLI to print a summary from).
    """
    if not device_input_dir(device).exists():
        raise FileNotFoundError(
            f"input/{device}/ not found. Run: sra init --repo <URL> --device {device}"
        )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    draft_md = OUTPUT_DIR / f"{device}_sra_draft.md"
    draft_json = OUTPUT_DIR / f"{device}_sra_draft.json"
    prompt_log = OUTPUT_DIR / f"{device}_prompts.jsonl"
    review_state = OUTPUT_DIR / f"{device}_review_state.json"

    targeted_rerun = bool(threat)   # single-threat re-run keeps prior state

    if not targeted_rerun:
        # Full or filtered runs: wipe stale draft-side outputs so the new run
        # is unbiased. review_state is wiped too — old decisions were made
        # against a previous draft and silently reapplying them would corrupt
        # the final. Save the file first if you want to preserve decisions.
        for p in (draft_md, draft_json, prompt_log, review_state):
            if p.exists():
                if p == review_state:
                    console.print(f"[yellow]Note:[/] wiping stale review decisions in "
                                  f"[dim]{p.name}[/].")
                p.unlink()
    else:
        # Targeted rerun of one threat: PRESERVE draft (Report Generator
        # upserts by threat_id), prompts log (append), and review_state
        # (only that entry's decision, if any, is cleared below).
        console.print(f"[cyan]Targeted rerun[/] for [bold]{threat}[/] — "
                      f"draft + prompts log preserved; this entry will replace "
                      f"any earlier version.")
        if review_state.exists():
            try:
                st = json.loads(review_state.read_text())
                if threat in (st.get("decisions") or {}):
                    del st["decisions"][threat]
                    review_state.write_text(json.dumps(st, indent=2))
                    console.print(f"  cleared prior review decision for [bold]{threat}[/]")
            except (json.JSONDecodeError, OSError):
                pass

    initial_state = SRAState(
        device=device,
        profile=profile,
        started_at_utc=datetime.now(timezone.utc),
        corpus_commit_sha=_corpus_commit_sha(device),
        framework_commit_sha=_framework_commit_sha(),
        prompt_log_path=prompt_log,
        draft_md_path=draft_md,
        draft_json_path=draft_json,
        extra_context=extra_context or "",
    )

    console.print(f"[bold]sra draft[/] · device=[cyan]{device}[/] profile=[cyan]{profile}[/]"
                  + (f" category=[cyan]{category}[/]" if category else "")
                  + (f" threat=[cyan]{threat}[/]" if threat else "")
                  + (f" limit=[cyan]{limit}[/]" if limit else "")
                  + (" [green]resume[/]" if resume else ""))
    console.print(f"  corpus commit:    [dim]{initial_state.corpus_commit_sha[:12]}[/]")
    console.print(f"  framework commit: [dim]{initial_state.framework_commit_sha[:12]}[/]")

    graph = build_graph(category=category, threat=threat, limit=limit,
                        strategy=strategy, resume=resume)

    # Stream state updates so we can show a live counter as entries land.
    # graph.stream() yields the FINAL state accumulator on completion.
    final_state_dict: dict | None = None
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("running pipeline…", total=None)
        # LangGraph recursion limit needs to cover the loop:
        # each threat cycles ~5 nodes; generous cap = 200 threats × 6 + 20
        for step in graph.stream(initial_state, {"recursion_limit": 1500}, stream_mode="values"):
            final_state_dict = step
            if isinstance(step, dict) and step.get("completed_entries") is not None:
                progress.update(task, description=f"drafted {step['completed_entries']} entries")

    if final_state_dict is None:
        raise RuntimeError("graph produced no state — check LangGraph install")
    final_state = SRAState.model_validate(final_state_dict)

    console.print(f"\n[bold green]✓ done[/] — {final_state.completed_entries} SRA entries drafted")
    console.print(f"  draft md:   [green]{draft_md}[/]")
    console.print(f"  draft json: [green]{draft_json}[/]")
    if prompt_log.exists():
        console.print(f"  prompts:    [green]{prompt_log}[/]")
    return final_state
