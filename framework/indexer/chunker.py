"""Parse the legacy corpus into typed chunks for the vector DB.

Each parser returns a list of Chunk objects with stable ids + rich metadata.
The vector indexer batches these into embedding calls.

Design: metadata is what makes retrieval useful — every chunk carries source,
kind, item_id (where applicable), category, and subsystem so agents can filter.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


# ---------------------------------------------------------------------------
# Data model


@dataclass
class Chunk:
    id: str                          # stable id for Chroma (deterministic across runs)
    text: str                        # chunk content — what gets embedded
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helpers


_ITEM_ID_RE = re.compile(r"^\*\*([A-Z][A-Z0-9]+(?:-[A-Z0-9]+)+)\*\*\s*·?\s*(.*)$")
# Category header: `## SRS · STOR — storage — eMMC filesystem, ...`
_CAT_HEADER_RE = re.compile(r"^##\s+(?:SRS|SDD|SDS|SAD)\s*·\s*([A-Z]+)\s*—\s*(.+)$")


def _slugify(text: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "-", text.strip().lower())
    return s.strip("-")[:60]


def _clean(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


# ---------------------------------------------------------------------------
# 1. Structured requirement docs — SRS / SDD / SDS / SAD
#     one Chunk per **ID** item block


def chunk_srs_like(path: Path, kind: str) -> list[Chunk]:
    """Parse SRS.md / SDD.md / SDS.md / SAD.md into per-item chunks.

    Each item has the shape:

        **SRS-STOR-0001** · Title
        Body paragraph.
        *Priority:* High · *Traces to:* SAD-STOR-0001 · *Verify:* UT-STOR-0001
    """
    doc_stem = path.stem  # 'SRS', 'SDD', ...
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()

    chunks: list[Chunk] = []
    current_category = ""
    current_category_desc = ""

    i = 0
    while i < len(lines):
        line = lines[i]

        m_cat = _CAT_HEADER_RE.match(line)
        if m_cat:
            current_category = m_cat.group(1)
            current_category_desc = m_cat.group(2).strip()
            i += 1
            continue

        m_item = _ITEM_ID_RE.match(line)
        if m_item:
            item_id = m_item.group(1)
            title = m_item.group(2).strip()

            # Gather body until next item or category header or EOF
            body_lines: list[str] = []
            j = i + 1
            while j < len(lines):
                nxt = lines[j]
                if _ITEM_ID_RE.match(nxt) or _CAT_HEADER_RE.match(nxt):
                    break
                body_lines.append(nxt)
                j += 1
            body = "\n".join(body_lines).strip()

            # Parse the meta line (Priority / Traces to / Verify) if present
            meta_extra: dict[str, str] = {}
            traces_to: list[str] = []
            for bl in body_lines:
                if bl.strip().startswith("*Priority:*") or bl.strip().startswith("*"):
                    # match `*Priority:* High · *Traces to:* SAD-STOR-0001 · *Verify:* UT-...`
                    for tok in bl.split("·"):
                        tok = tok.strip()
                        m = re.match(r"\*([A-Za-z ]+):\*\s*(.+)", tok)
                        if m:
                            key = m.group(1).strip().lower().replace(" ", "_")
                            val = m.group(2).strip()
                            meta_extra[key] = val
                            if key == "traces_to":
                                traces_to = [t.strip() for t in re.split(r"[,;]", val) if t.strip()]

            chunk_text = f"[{item_id}] {title}\n\n{body}"

            chunks.append(Chunk(
                id=f"{doc_stem}::{item_id}",
                text=chunk_text,
                metadata={
                    "source": path.name,
                    "kind": kind,               # 'requirement' | 'design' | 'implementation' | 'architecture'
                    "item_id": item_id,
                    "title": title,
                    "category": current_category,
                    "category_desc": current_category_desc,
                    "traces_to": ",".join(traces_to) if traces_to else "",
                    **{f"meta_{k}": v for k, v in meta_extra.items() if k != "traces_to"},
                },
            ))
            i = j
            continue

        i += 1

    return chunks


# ---------------------------------------------------------------------------
# 2. Vulnerability plan — one Chunk per VULN-NN row


_VULN_ROW_RE = re.compile(
    r"^\|\s*\*\*(VULN-\d+)\*\*\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|"
)


def chunk_vulnerability_plan(path: Path) -> list[Chunk]:
    """Parse the vulnerability_plan.md table rows into per-VULN chunks."""
    text = path.read_text(encoding="utf-8")
    chunks: list[Chunk] = []
    current_domain = ""

    for line in text.splitlines():
        # `## Domain 1 — OTA update integrity (5)` -> current_domain
        m_dom = re.match(r"^##\s+Domain\s+\d+\s+—\s+(.+?)\s*\(", line)
        if m_dom:
            current_domain = m_dom.group(1).strip()
            continue

        m = _VULN_ROW_RE.match(line)
        if m:
            vuln_id = m.group(1)
            cwe = _clean(m.group(2))
            target = _clean(m.group(3)).replace("`", "")
            severity = _clean(m.group(4))
            description = _clean(m.group(5))
            semgrep = _clean(m.group(6)).rstrip("|").strip()

            # Split target into file :: function if possible
            target_file = ""
            target_symbol = ""
            if "::" in target:
                target_file, target_symbol = [x.strip() for x in target.split("::", 1)]
            else:
                target_file = target

            chunk_text = (
                f"[{vuln_id}] {cwe}\n"
                f"Target: {target}\n"
                f"Severity: {severity}\n"
                f"Domain: {current_domain}\n\n"
                f"{description}"
            )
            chunks.append(Chunk(
                id=f"VULN::{vuln_id}",
                text=chunk_text,
                metadata={
                    "source": path.name,
                    "kind": "vulnerability",
                    "item_id": vuln_id,
                    "cwe": cwe,
                    "target_file": target_file,
                    "target_symbol": target_symbol,
                    "severity": severity,
                    "domain": current_domain,
                    "semgrep": semgrep,
                },
            ))
    return chunks


# ---------------------------------------------------------------------------
# 3. Threat catalog — Markdown tables with E-*, P-*, DF-*, DS-*, TB-*, T-* ids


_THREAT_ROW_RE = re.compile(
    r"^\|\s*([EPDT][A-Z0-9]*(?:-[A-Z0-9]+)+)\s*\|\s*([^|]+)\|\s*([^|]+)\|\s*([^|]+)\|"
)
_THREAT_SECTION_RE = re.compile(r"^###\s+10\.(\d+)\s+(.+)$")


def chunk_threat_catalog(path: Path) -> list[Chunk]:
    """Parse threat_catalog_exhaustive.md into per-threat chunks."""
    text = path.read_text(encoding="utf-8")
    chunks: list[Chunk] = []
    current_section = ""

    for line in text.splitlines():
        m_sec = _THREAT_SECTION_RE.match(line)
        if m_sec:
            current_section = m_sec.group(2).strip()
            continue

        m = _THREAT_ROW_RE.match(line)
        if m:
            threat_id = m.group(1)
            stride = _clean(m.group(2))
            title = _clean(m.group(3))
            description = _clean(m.group(4))
            # The row may also have priority / current_mitigation / state after col 4;
            # we grab them best-effort
            cols = [c.strip() for c in line.strip().strip("|").split("|")]
            priority = cols[4] if len(cols) > 4 else ""
            current_mitigation = cols[5] if len(cols) > 5 else ""
            state = cols[6] if len(cols) > 6 else ""

            # Derive STRIDE letter (S/T/R/I/D/E) from suffix of id or category cell
            stride_letter = ""
            m_stride = re.search(r"-([STRIDE])\d*$", threat_id)
            if m_stride:
                stride_letter = m_stride.group(1)

            chunk_text = (
                f"[{threat_id}] {title}\n"
                f"STRIDE category: {stride}\n"
                f"Section: {current_section}\n"
                f"Priority: {priority}\n"
                f"Current mitigation (legacy): {current_mitigation}\n"
                f"State: {state}\n\n"
                f"{description}"
            )
            chunks.append(Chunk(
                id=f"THREAT::{threat_id}",
                text=chunk_text,
                metadata={
                    "source": path.name,
                    "kind": "threat",
                    "item_id": threat_id,
                    "title": title,
                    "stride_category": stride,
                    "stride": stride_letter,
                    "section": current_section,
                    "priority": priority,
                    "current_mitigation": current_mitigation,
                    "state": state,
                },
            ))
    return chunks


# ---------------------------------------------------------------------------
# 4. Long-form narrative markdown — chunk by section (## / ###)


def chunk_narrative_md(path: Path, kind: str, target_chars: int = 1500) -> list[Chunk]:
    """Split a narrative markdown doc into section-sized chunks.

    Uses `##` and `###` headers as split points, then further splits any
    section longer than target_chars into overlapping windows.
    """
    doc_stem = path.stem
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()

    sections: list[tuple[str, list[str]]] = []  # (heading, lines)
    current_heading = "preamble"
    current_lines: list[str] = []

    for line in lines:
        if line.startswith(("## ", "### ")):
            if current_lines:
                sections.append((current_heading, current_lines))
            current_heading = line.lstrip("#").strip()
            current_lines = [line]
        else:
            current_lines.append(line)
    if current_lines:
        sections.append((current_heading, current_lines))

    chunks: list[Chunk] = []
    for heading, sec_lines in sections:
        body = "\n".join(sec_lines).strip()
        if not body:
            continue
        slug = _slugify(heading)

        if len(body) <= target_chars * 1.4:
            chunks.append(Chunk(
                id=f"{doc_stem}::{slug}",
                text=body,
                metadata={
                    "source": path.name,
                    "kind": kind,               # 'narrative'
                    "section": heading,
                    "item_id": "",
                },
            ))
        else:
            # Split into ~target_chars windows with 150-char overlap
            step = target_chars - 150
            for k, start in enumerate(range(0, len(body), step)):
                piece = body[start:start + target_chars]
                if not piece.strip():
                    continue
                chunks.append(Chunk(
                    id=f"{doc_stem}::{slug}::{k:02d}",
                    text=piece,
                    metadata={
                        "source": path.name,
                        "kind": kind,
                        "section": heading,
                        "chunk_ix": k,
                        "item_id": "",
                    },
                ))
    return chunks


# ---------------------------------------------------------------------------
# 5. C/C++ source — chunk by top-level function definition


# Match top-level function definitions: return_type name(args) { ... }
# This is deliberately loose — good enough for chunking, not for parsing.
_FUNC_DEF_RE = re.compile(
    r"^(?P<sig>(?:static\s+|inline\s+|extern\s+|const\s+|unsigned\s+|signed\s+)*"
    r"[A-Za-z_][A-Za-z0-9_\s\*]*?\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\([^;]*?\))\s*\{",
    re.MULTILINE,
)


def chunk_c_file(path: Path, corpus_root: Path) -> list[Chunk]:
    """Chunk a .c / .h file by top-level function definitions.

    Falls back to whole-file chunk if no functions are detected (headers, tiny files).
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    rel = path.relative_to(corpus_root).as_posix()
    subsystem = _subsystem_of(rel)

    matches = list(_FUNC_DEF_RE.finditer(text))
    if not matches:
        # Whole-file chunk — capped at 8000 chars to keep embed cost sane
        capped = text[:8000]
        return [Chunk(
            id=f"CODE::{rel}",
            text=f"// File: {rel}\n\n{capped}",
            metadata={
                "source": rel,
                "kind": "code",
                "subsystem": subsystem,
                "path": rel,
                "function": "",
                "item_id": "",
            },
        )]

    chunks: list[Chunk] = []
    for k, m in enumerate(matches):
        name = m.group("name")
        start = m.start()
        # Find matching closing brace by naive brace counting
        depth = 0
        end = start
        for i, ch in enumerate(text[m.end() - 1:], start=m.end() - 1):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        body = text[start:end][:6000]  # cap per function
        line_start = text[:start].count("\n") + 1
        line_end = text[:end].count("\n") + 1
        chunks.append(Chunk(
            id=f"CODE::{rel}::{name}",
            text=f"// File: {rel}\n// Function: {name}   Lines {line_start}-{line_end}\n\n{body}",
            metadata={
                "source": rel,
                "kind": "code",
                "subsystem": subsystem,
                "path": rel,
                "function": name,
                "line_start": line_start,
                "line_end": line_end,
                "item_id": "",
            },
        ))
    return chunks


def _subsystem_of(rel_path: str) -> str:
    """Extract a subsystem tag from a firmware relative path.

    firmware/app_mcu/ota/install_handler.c  -> 'app_mcu/ota'
    firmware/safety_mcu/alarm_engine.c      -> 'safety_mcu'
    firmware/shared/crc.c                   -> 'shared'
    """
    parts = rel_path.split("/")
    if parts and parts[0] == "firmware":
        parts = parts[1:]
    if len(parts) >= 2:
        return "/".join(parts[:2] if parts[0] in {"app_mcu"} else parts[:1])
    return parts[0] if parts else ""


# ---------------------------------------------------------------------------
# 6. Top-level: walk a device corpus and produce all chunks


def walk_corpus(corpus_root: Path) -> Iterable[Chunk]:
    """Walk input/<device>/ and yield all chunks from every recognised file.

    corpus_root is the path to input/<device>/ (i.e. contains corpus/, firmware/).
    """
    docs_dir = corpus_root / "corpus" / _first_device_dir(corpus_root)
    firmware_dir = corpus_root / "firmware"

    # --- Structured requirement docs ---
    for name, kind in (
        ("SRS.md", "requirement"),
        ("SDD.md", "design"),
        ("SDS.md", "implementation"),
        ("SAD.md", "architecture"),
    ):
        p = docs_dir / name
        if p.exists():
            yield from chunk_srs_like(p, kind)

    # --- Vulnerability plan ---
    vp = docs_dir / "vulnerability_plan.md"
    if vp.exists():
        yield from chunk_vulnerability_plan(vp)

    # --- Threat catalog ---
    tc = docs_dir / "threat_catalog_exhaustive.md"
    if tc.exists():
        yield from chunk_threat_catalog(tc)

    # --- Narrative markdown ---
    for name, kind in (
        ("concept_spec.md", "narrative"),
        ("threat_model.md", "narrative"),
        ("technical_reference_manual.md", "narrative"),
        ("service_manual.md", "narrative"),
        ("operator_manual.md", "narrative"),
        ("use_case_document.md", "narrative"),
        ("vertical_slice_ota.md", "narrative"),
    ):
        p = docs_dir / name
        if p.exists():
            yield from chunk_narrative_md(p, kind)

    # --- Firmware code ---
    if firmware_dir.exists():
        for path in sorted(firmware_dir.rglob("*")):
            if path.is_file() and path.suffix in {".c", ".h", ".cpp", ".hpp"}:
                yield from chunk_c_file(path, corpus_root)


def _first_device_dir(corpus_root: Path) -> str:
    """input/<device>/corpus/ contains one dir named after the device."""
    corpus_dir = corpus_root / "corpus"
    if not corpus_dir.exists():
        return ""
    for p in corpus_dir.iterdir():
        if p.is_dir():
            return p.name
    return ""
