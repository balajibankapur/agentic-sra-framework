"""Evaluation — recall of seeded VULN-XX ground truth by the SRA draft.

Ground truth is the 34 hand-authored VULN entries under
input/<device>/corpus/<device>/vulnerability_plan.md (also present as
graph nodes in stores/extracts/<device>/vulnerabilities.json).

Each VULN has (target_file, target_symbol). For each VULN we ask:
  1. Did any SRA draft entry propose a code change touching the same file?
     -> file_match
  2. Did the hunk mention the target symbol?
     -> symbol_match
  3. What priority did the corresponding SRA entry get?
     -> priority correlation

Metrics reported:
  - VULN recall (file-level)  = files_hit / 34
  - VULN recall (symbol-level) = symbols_hit / 34
  - Coverage per severity band
  - Coverage stratified by Semgrep detectability
     (yes / partial / no — the framework's distinctive value is the "no" band
     which requires regulatory-intent reasoning that plain SAST cannot catch)
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console
from rich.table import Table

from framework.config import EXTRACTS_DIR, OUTPUT_DIR

console = Console()


@dataclass
class VulnHit:
    vuln_id: str
    target_file: str
    target_symbol: str
    severity: str
    semgrep: str            # yes | partial | no
    file_match: bool = False
    symbol_match: bool = False
    matched_entry_id: str = ""
    matched_entry_priority: str = ""
    matched_entry_cvss: float = 0.0


@dataclass
class EvalReport:
    device: str
    total_vulns: int
    total_entries: int
    entries_with_code_changes: int
    parse_error_entries: int
    warned_entries: int
    hits: list[VulnHit] = field(default_factory=list)

    @property
    def file_recall(self) -> float:
        return sum(1 for h in self.hits if h.file_match) / self.total_vulns if self.total_vulns else 0.0

    @property
    def symbol_recall(self) -> float:
        return sum(1 for h in self.hits if h.symbol_match) / self.total_vulns if self.total_vulns else 0.0

    def recall_by_semgrep(self) -> dict[str, tuple[int, int]]:
        """{semgrep_bucket: (file_hits, total_in_bucket)}."""
        out: dict[str, tuple[int, int]] = {}
        for bucket in ("yes", "partial", "no"):
            total = sum(1 for h in self.hits if h.semgrep == bucket)
            hits = sum(1 for h in self.hits if h.semgrep == bucket and h.file_match)
            out[bucket] = (hits, total)
        return out

    def recall_by_severity(self) -> dict[str, tuple[int, int]]:
        out: dict[str, tuple[int, int]] = {}
        for bucket in ("Critical", "High", "Medium", "Low"):
            total = sum(1 for h in self.hits if h.severity.startswith(bucket))
            hits = sum(1 for h in self.hits if h.severity.startswith(bucket) and h.file_match)
            out[bucket] = (hits, total)
        return out


def _load_seeded_vulns(device: str) -> list[dict]:
    """Read stores/extracts/<device>/vulnerabilities.json."""
    path = EXTRACTS_DIR / device / "vulnerabilities.json"
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found. Run: sra extract --device {device}"
        )
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("nodes", [])


def _load_sra_draft(device: str) -> list[dict]:
    path = OUTPUT_DIR / f"{device}_sra_draft.json"
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found. Run: sra draft --device {device}"
        )
    return json.loads(path.read_text(encoding="utf-8"))


def _normalise_path(p: str) -> str:
    p = p.strip().strip("`").strip("'").strip('"')
    if p.startswith("firmware/"):
        return p
    if not p.startswith(("firmware/", "app_mcu/", "safety_mcu/", "shared/")):
        return p
    return f"firmware/{p}"


def evaluate(device: str) -> EvalReport:
    vulns = _load_seeded_vulns(device)
    entries = _load_sra_draft(device)

    # Build fast lookups of every proposed code change: file -> entry list
    file_to_entries: dict[str, list[dict]] = {}
    hunks_by_file: dict[str, list[str]] = {}
    entries_with_code = 0
    parse_error = 0
    warned = 0
    for e in entries:
        if e.get("parse_error"):
            parse_error += 1
        if e.get("warnings"):
            warned += 1
        code_changes = e.get("proposed_code_changes") or []
        if not code_changes:
            continue
        entries_with_code += 1
        for cc in code_changes:
            path = _normalise_path(cc.get("path", ""))
            if not path:
                continue
            file_to_entries.setdefault(path, []).append(e)
            hunks_by_file.setdefault(path, []).append(cc.get("hunk", "") or "")

    hits: list[VulnHit] = []
    for v in vulns:
        target_file = _normalise_path(v.get("target_file", ""))
        target_symbol = (v.get("target_symbol") or "").strip().rstrip("()")

        hit = VulnHit(
            vuln_id=v["id"],
            target_file=target_file,
            target_symbol=target_symbol,
            severity=v.get("severity", ""),
            semgrep=(v.get("semgrep") or "").lower(),
        )

        matched_entries = file_to_entries.get(target_file, [])
        if matched_entries:
            hit.file_match = True
            best = matched_entries[0]
            hit.matched_entry_id = best.get("threat_id", "")
            hit.matched_entry_priority = best.get("priority", "")
            hit.matched_entry_cvss = (best.get("cvss_v31") or {}).get("base_score", 0.0)
            # Symbol-level match: any hunk on this file mentions the symbol
            if target_symbol:
                combined = "\n".join(hunks_by_file.get(target_file, []))
                if re.search(rf"\b{re.escape(target_symbol)}\b", combined):
                    hit.symbol_match = True
        hits.append(hit)

    return EvalReport(
        device=device,
        total_vulns=len(vulns),
        total_entries=len(entries),
        entries_with_code_changes=entries_with_code,
        parse_error_entries=parse_error,
        warned_entries=warned,
        hits=hits,
    )


def print_report(report: EvalReport) -> None:
    console.rule(f"[bold]VULN recall — {report.device}[/]")

    summary = Table(title="Pipeline output shape", show_header=False)
    summary.add_row("SRA entries drafted", str(report.total_entries))
    summary.add_row("  with proposed code changes", str(report.entries_with_code_changes))
    summary.add_row("  parse_error", str(report.parse_error_entries))
    summary.add_row("  with warnings", str(report.warned_entries))
    summary.add_row("Seeded VULNs (ground truth)", str(report.total_vulns))
    console.print(summary)

    metric = Table(title="Recall against seeded VULNs")
    metric.add_column("Metric")
    metric.add_column("Hit / Total", justify="right")
    metric.add_column("Rate", justify="right")
    file_hits = sum(1 for h in report.hits if h.file_match)
    sym_hits = sum(1 for h in report.hits if h.symbol_match)
    metric.add_row("File-level recall",
                   f"{file_hits} / {report.total_vulns}",
                   f"{report.file_recall:.1%}")
    metric.add_row("Symbol-level recall",
                   f"{sym_hits} / {report.total_vulns}",
                   f"{report.symbol_recall:.1%}")
    console.print(metric)

    sem = Table(title="Recall by Semgrep detectability (framework value = 'no' band)")
    sem.add_column("Semgrep")
    sem.add_column("Hit / Total", justify="right")
    sem.add_column("Rate", justify="right")
    for bucket, (h, t) in report.recall_by_semgrep().items():
        rate = f"{h/t:.1%}" if t else "—"
        sem.add_row(bucket, f"{h} / {t}", rate)
    console.print(sem)

    sev = Table(title="Recall by seeded VULN severity")
    sev.add_column("Severity")
    sev.add_column("Hit / Total", justify="right")
    sev.add_column("Rate", justify="right")
    for bucket, (h, t) in report.recall_by_severity().items():
        rate = f"{h/t:.1%}" if t else "—"
        sev.add_row(bucket, f"{h} / {t}", rate)
    console.print(sev)

    missed = [h for h in report.hits if not h.file_match]
    if missed:
        console.print(f"\n[yellow]Missed VULNs ({len(missed)}):[/]")
        for h in missed[:15]:
            console.print(f"  {h.vuln_id:10s} {h.severity:9s} {h.semgrep:7s} "
                          f"target=[dim]{h.target_file}[/]")
        if len(missed) > 15:
            console.print(f"  … and {len(missed) - 15} more")

    hit_rows = [h for h in report.hits if h.file_match]
    if hit_rows:
        console.print(f"\n[green]Recalled VULNs ({len(hit_rows)}):[/]")
        for h in hit_rows[:15]:
            sym_mark = "✓sym" if h.symbol_match else " sym?"
            console.print(f"  {h.vuln_id:10s} {sym_mark:6s} via [cyan]{h.matched_entry_id}[/] "
                          f"P={h.matched_entry_priority}  CVSS={h.matched_entry_cvss}")
        if len(hit_rows) > 15:
            console.print(f"  … and {len(hit_rows) - 15} more")


def write_report_json(report: EvalReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "device": report.device,
        "total_vulns": report.total_vulns,
        "total_entries": report.total_entries,
        "entries_with_code_changes": report.entries_with_code_changes,
        "parse_error_entries": report.parse_error_entries,
        "warned_entries": report.warned_entries,
        "file_recall": report.file_recall,
        "symbol_recall": report.symbol_recall,
        "recall_by_semgrep": {k: {"hit": h, "total": t} for k, (h, t) in report.recall_by_semgrep().items()},
        "recall_by_severity": {k: {"hit": h, "total": t} for k, (h, t) in report.recall_by_severity().items()},
        "hits": [h.__dict__ for h in report.hits],
    }, indent=2), encoding="utf-8")
