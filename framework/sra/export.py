"""SRA export — assembles the final artifacts.

Reads the draft MD + JSON (produced incrementally by Report Generator
during `sra draft`), reads prompts.jsonl (per-turn LLM log), and writes:

  output/<device>_sra_final.md        cleaned draft + summary table on top
  output/<device>_sra_final.pdf       via pandoc + Chrome
  output/<device>_sra_final.docx      via pandoc
  output/<device>_sra_final.json      1:1 copy of draft.json for now
  output/<device>_provenance.json     rollup from prompts.jsonl

Before the review UI (P5-G) lands, `final` is essentially `draft with
review status pending`. Once review is in place, only approved / edited
entries land in final; rejected are excluded.
"""

from __future__ import annotations

import json
import shutil
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table

from framework.agents.runner import _corpus_commit_sha, _framework_commit_sha
from framework.config import OUTPUT_DIR
from framework.render_doc import render as render_pdf_docx
from framework.sra.rollup import build_provenance

console = Console()


def run_export(device: str, profile: str = "hybrid") -> None:
    draft_md = OUTPUT_DIR / f"{device}_sra_draft.md"
    draft_json = OUTPUT_DIR / f"{device}_sra_draft.json"
    prompts_log = OUTPUT_DIR / f"{device}_prompts.jsonl"

    if not draft_json.exists():
        raise FileNotFoundError(
            f"{draft_json} not found. Run: sra draft --device {device}"
        )

    entries = json.loads(draft_json.read_text(encoding="utf-8"))
    if not isinstance(entries, list) or not entries:
        raise RuntimeError(f"{draft_json} contains no entries.")

    review_state_path = OUTPUT_DIR / f"{device}_review_state.json"
    final_md = OUTPUT_DIR / f"{device}_sra_final.md"
    final_pdf = OUTPUT_DIR / f"{device}_sra_final.pdf"
    final_docx = OUTPUT_DIR / f"{device}_sra_final.docx"
    final_json = OUTPUT_DIR / f"{device}_sra_final.json"
    prov_path = OUTPUT_DIR / f"{device}_provenance.json"

    # Apply review decisions if present:
    #   approved / (no state)  -> entry as-is
    #   edited                 -> substitute reviewer's edited_entry
    #   rejected / deferred    -> drop from final
    entries, rejected_count, deferred_count, edited_count, reviewer = _apply_review_state(
        entries, review_state_path
    )

    # 1. Final JSON is the reviewed entry set
    final_json.write_text(
        json.dumps(entries, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # 2. Final markdown = header + summary + draft body
    _write_final_md(device=device, entries=entries, final_md=final_md,
                    draft_md=draft_md)

    # 3. PDF + DOCX
    render_pdf_docx(final_md, final_pdf, final_docx)

    # 4. Provenance
    prov = build_provenance(
        device=device,
        profile=profile,
        corpus_commit_sha=_corpus_commit_sha(device),
        framework_commit_sha=_framework_commit_sha(),
        prompts_log_path=prompts_log,
        draft_json_path=draft_json,
    )
    prov_path.write_text(prov.model_dump_json(indent=2), encoding="utf-8")

    # 5. Summary to terminal
    _print_summary(device, entries, prov, final_md, final_pdf, final_docx, prov_path,
                   rejected_count=rejected_count, deferred_count=deferred_count,
                   edited_count=edited_count, reviewer=reviewer)


def _apply_review_state(
    entries: list[dict],
    state_path: Path,
) -> tuple[list[dict], int, int, int, str]:
    """Overlay reviewer decisions onto the draft entries.

    Returns (final_entries, rejected_count, deferred_count, edited_count, reviewer).
    """
    if not state_path.exists():
        return entries, 0, 0, 0, ""
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return entries, 0, 0, 0, ""

    decisions = state.get("decisions", {}) or {}
    reviewer = state.get("reviewer_name", "") or ""
    kept: list[dict] = []
    rejected = deferred = edited = 0
    for e in entries:
        d = decisions.get(e["threat_id"]) or {}
        action = d.get("action", "pending")
        if action == "rejected":
            rejected += 1
            continue
        if action == "deferred":
            deferred += 1
            continue
        if action == "edited" and d.get("edited_entry"):
            edited += 1
            kept.append(d["edited_entry"])
            continue
        # approved OR pending -> keep the draft entry
        kept.append(e)
    return kept, rejected, deferred, edited, reviewer


# ---------------------------------------------------------------------------
# Renderers


def _write_final_md(
    *,
    device: str,
    entries: list[dict],
    final_md: Path,
    draft_md: Path,
) -> None:
    """Prepend a header + summary table to the draft MD."""
    stats = _entry_stats(entries)

    header: list[str] = []
    header.append(f"# Security Risk Assessment — {device}\n")
    header.append(f"*Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · "
                  f"{len(entries)} entries · {stats['parse_errors']} parse-error entries*\n\n")

    header.append("## Summary\n\n")
    header.append("| Metric | Count |\n|---|---|\n")
    header.append(f"| Threats analysed | {len(entries)} |\n")
    header.append(f"| Priority P0 (Critical) | {stats['priority']['P0']} |\n")
    header.append(f"| Priority P1 (High) | {stats['priority']['P1']} |\n")
    header.append(f"| Priority P2 (Medium) | {stats['priority']['P2']} |\n")
    header.append(f"| CVSS Critical (≥ 9.0) | {stats['sev']['Critical']} |\n")
    header.append(f"| CVSS High (7.0-8.9) | {stats['sev']['High']} |\n")
    header.append(f"| CVSS Medium (4.0-6.9) | {stats['sev']['Medium']} |\n")
    header.append(f"| CVSS Low / None | {stats['sev']['Low'] + stats['sev']['None']} |\n")
    header.append(f"| Residual High | {stats['residual']['High']} |\n")
    header.append(f"| Residual Medium | {stats['residual']['Medium']} |\n")
    header.append(f"| Residual Low | {stats['residual']['Low']} |\n")
    header.append(f"| Total estimated effort (eng-weeks) | {stats['effort']:.1f} |\n\n")

    header.append("## Entry index\n\n")
    header.append("| Threat | Priority | CVSS | Residual | Effort |\n"
                  "|---|---|---|---|---|\n")
    for e in entries:
        cvss = e.get("cvss_v31") or {}
        header.append(
            f"| `{e['threat_id']}` — {e['title'][:50]} "
            f"| {e.get('priority', '')} "
            f"| {cvss.get('base_score', 0)} {cvss.get('severity', '')} "
            f"| {e.get('residual_risk', '')} "
            f"| {e.get('effort_engineer_weeks', 0):g}wk |\n"
        )
    header.append("\n")

    # Take the draft's per-entry body (skip its top-level header)
    body = ""
    if draft_md.exists():
        raw = draft_md.read_text(encoding="utf-8")
        # Drop the draft's own "# Security Risk Assessment — draft" preamble
        if "---" in raw:
            body = raw[raw.index("---"):]
        else:
            body = raw

    final_md.write_text("".join(header) + body, encoding="utf-8")


def _entry_stats(entries: list[dict]) -> dict:
    prio = Counter(e.get("priority", "P2") for e in entries)
    sev = Counter((e.get("cvss_v31") or {}).get("severity", "None") for e in entries)
    residual = Counter(e.get("residual_risk", "Medium") for e in entries)
    parse_errors = sum(1 for e in entries if e.get("parse_error"))
    effort = sum(float(e.get("effort_engineer_weeks", 0.0)) for e in entries)
    return {
        "priority": {"P0": prio["P0"], "P1": prio["P1"], "P2": prio["P2"]},
        "sev": {"Critical": sev["Critical"], "High": sev["High"],
                "Medium": sev["Medium"], "Low": sev["Low"], "None": sev["None"]},
        "residual": {"High": residual["High"], "Medium": residual["Medium"],
                     "Low": residual["Low"]},
        "parse_errors": parse_errors,
        "effort": effort,
    }


# ---------------------------------------------------------------------------
# Summary


def _print_summary(
    device: str,
    entries: list[dict],
    prov,
    final_md: Path,
    final_pdf: Path,
    final_docx: Path,
    prov_path: Path,
    rejected_count: int = 0,
    deferred_count: int = 0,
    edited_count: int = 0,
    reviewer: str = "",
) -> None:
    stats = _entry_stats(entries)
    table = Table(title=f"sra export — {device}", show_header=False)
    if reviewer:
        table.add_row("reviewer", reviewer)
    if rejected_count or deferred_count or edited_count:
        table.add_row("review decisions",
                      f"edited={edited_count}  rejected={rejected_count}  deferred={deferred_count}")
    table.add_row("entries in final", str(len(entries)))
    table.add_row("  P0 / P1 / P2",
                  f"{stats['priority']['P0']} / {stats['priority']['P1']} / {stats['priority']['P2']}")
    table.add_row("  Critical / High / Medium / Low",
                  f"{stats['sev']['Critical']} / {stats['sev']['High']} / "
                  f"{stats['sev']['Medium']} / {stats['sev']['Low'] + stats['sev']['None']}")
    table.add_row("  parse_error", str(stats["parse_errors"]))
    table.add_row("total est. effort (eng-weeks)", f"{stats['effort']:.1f}")
    table.add_row("LLM cost (USD)", f"${prov.total_cost_usd_est:.4f}")
    table.add_row("corpus commit", prov.corpus_commit_sha[:12])
    table.add_row("framework commit", prov.framework_commit_sha[:12])
    console.print(table)

    console.print(f"\nWritten:")
    console.print(f"  [green]{final_md}[/]  ({final_md.stat().st_size:,} bytes)")
    console.print(f"  [green]{final_pdf}[/]  ({final_pdf.stat().st_size:,} bytes)")
    console.print(f"  [green]{final_docx}[/]  ({final_docx.stat().st_size:,} bytes)")
    console.print(f"  [green]{prov_path}[/]  ({prov_path.stat().st_size:,} bytes)")
