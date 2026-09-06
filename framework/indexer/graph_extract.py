"""Graph extractor — parses input/<device>/ into 7 JSON files under
stores/extracts/<device>/, one per node/edge topic.

Each JSON has the shape {"nodes": [...], "edges": [...]}. Every node has a
globally-unique `id`; every edge references two ids and names its type.
The Step 4 Kuzu loader will bulk-load these files in dependency order.

Node id conventions:
    Requirement           SRS-<CAT>-NNNN         (from SRS.md)
    DesignItem            SDD-<CAT>-NNNN         (from SDD.md)
    ImplementationItem    SDS-<CAT>-NNNN         (from SDS.md)
    ArchitectureItem      SAD-<CAT>-NNNN         (from SAD.md)
    Threat                <threat_id from catalog>
    Vulnerability         VULN-NN
    CodeArtifact          CODE:<rel_path>[:<function>]
    Control               CTRL:<slug of mitigation text>
    UseCase               UC-<CAT>-NN
    Actor                 ACTOR:<slug>
    DFDElement            DFD:<element_id>       (E-*, P-*, DS-*, DF-*, TB-*)

Edge conventions (all uppercase, drawn from the graph schema in docs/roadmap):
    TRACES_TO         Requirement          -> ArchitectureItem
    IMPLEMENTS        DesignItem           -> Requirement
    REALIZES          ImplementationItem   -> DesignItem
    REALIZED_BY       ImplementationItem   -> CodeArtifact
    LOCATED_IN        Vulnerability        -> CodeArtifact
    MITIGATES         Control              -> Threat        (legacy state)
    APPLIES_TO        Threat               -> DFDElement    (element the threat targets)
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from framework.config import EXTRACTS_DIR, device_input_dir
from framework.indexer.chunker import Chunk, walk_corpus

console = Console()


# ---------------------------------------------------------------------------
# Helpers


def _slugify(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:80] or "unknown"


def _split_list(raw: str) -> list[str]:
    return [t.strip() for t in re.split(r"[,;]", raw or "") if t.strip()]


def _write_json(path: Path, nodes: list[dict], edges: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"nodes": nodes, "edges": edges}
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False))


@dataclass
class ExtractStats:
    device: str
    files: dict[str, dict[str, int]] = field(default_factory=dict)   # {filename: {"nodes": n, "edges": m}}
    total_nodes: int = 0
    total_edges: int = 0


# ---------------------------------------------------------------------------
# 1. Requirements / design / implementation / architecture


def extract_requirements(chunks: list[Chunk]) -> tuple[list[dict], list[dict]]:
    nodes: list[dict] = []
    edges: list[dict] = []
    seen_ids: set[str] = set()

    for c in chunks:
        kind = c.metadata.get("kind")
        item_id = c.metadata.get("item_id")
        if kind not in {"requirement", "design", "implementation", "architecture"} or not item_id:
            continue
        if item_id in seen_ids:
            continue
        seen_ids.add(item_id)

        label = {
            "requirement": "Requirement",
            "design": "DesignItem",
            "implementation": "ImplementationItem",
            "architecture": "ArchitectureItem",
        }[kind]

        nodes.append({
            "label": label,
            "id": item_id,
            "title": c.metadata.get("title", ""),
            "body": c.text.split("\n\n", 1)[-1][:2000],
            "category": c.metadata.get("category", ""),
            "priority": c.metadata.get("meta_priority", ""),
            "verify": c.metadata.get("meta_verify", ""),
            "location": c.metadata.get("meta_location", ""),
            "source": c.metadata.get("source", ""),
        })

        # Edges — direction: from this item to what it references
        if kind == "requirement":
            for tgt in _split_list(c.metadata.get("traces_to", "")):
                edges.append({"type": "TRACES_TO", "from": item_id, "to": tgt})
        elif kind == "design":
            for tgt in _split_list(c.metadata.get("meta_implements", "")):
                edges.append({"type": "IMPLEMENTS", "from": item_id, "to": tgt})
        elif kind == "implementation":
            for tgt in _split_list(c.metadata.get("meta_realizes", "")):
                edges.append({"type": "REALIZES", "from": item_id, "to": tgt})
            loc = c.metadata.get("meta_location", "").strip().strip("`")
            if loc:
                edges.append({
                    "type": "REALIZED_BY",
                    "from": item_id,
                    "to": f"CODE:{loc}",
                })
    return nodes, edges


# ---------------------------------------------------------------------------
# 2. Threats + DFD elements + legacy controls (all from threat catalog)


def extract_threats(chunks: list[Chunk]) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    """Returns (threat_nodes, threat_edges, dfd_nodes, control_nodes+edges).

    control_nodes carries both nodes and edges of the Control -> Threat
    MITIGATES kind — legacy state per catalog.
    """
    threat_nodes: list[dict] = []
    threat_edges: list[dict] = []
    dfd_nodes: list[dict] = []
    control_out: list[dict] = []  # returned as mixed list; split by caller

    dfd_seen: set[str] = set()
    control_seen: dict[str, str] = {}   # slug -> canonical text

    for c in chunks:
        if c.metadata.get("kind") != "threat":
            continue
        threat_id = c.metadata.get("item_id", "")
        if not threat_id:
            continue

        threat_nodes.append({
            "label": "Threat",
            "id": threat_id,
            "title": c.metadata.get("title", ""),
            "description": c.text.split("\n\n", 1)[-1][:2000],
            "stride": c.metadata.get("stride", ""),
            "stride_category": c.metadata.get("stride_category", ""),
            "section": c.metadata.get("section", ""),
            "priority": c.metadata.get("priority", ""),
            "state": c.metadata.get("state", ""),
            "source": c.metadata.get("source", ""),
        })

        # DFD element inferred from threat id prefix.
        #   E-BIOMED-S    -> E-BIOMED       (External Entity)
        #   P-UI-S01      -> P-UI           (Process)
        #   DS-FWA-T      -> DS-FWA         (Data Store)
        #   DF-VITALS-I   -> DF-VITALS      (Data Flow)
        #   TB-INT-*      -> TB-INT         (Trust Boundary)
        #   T-OTA-P01-T   -> T-OTA-P01      (cross-cutting scenario)
        m = re.match(
            r"^((?:DS|DF|TB|E|P|T)-[A-Z0-9]+(?:-[A-Z0-9]+)*?)(-[STRIDE]\d*)?$",
            threat_id,
        )
        if m:
            elem_id = m.group(1)
            elem_kind_map = {
                "E": "ExternalEntity",
                "P": "Process",
                "DS": "DataStore",
                "DF": "DataFlow",
                "TB": "TrustBoundary",
                "T": "CrossCutting",
            }
            first = elem_id.split("-")[0]
            elem_kind = elem_kind_map.get(first, "Unknown")
            if elem_id not in dfd_seen:
                dfd_seen.add(elem_id)
                dfd_nodes.append({
                    "label": "DFDElement",
                    "id": f"DFD:{elem_id}",
                    "element_id": elem_id,
                    "kind": elem_kind,
                })
            threat_edges.append({
                "type": "APPLIES_TO",
                "from": threat_id,
                "to": f"DFD:{elem_id}",
            })

        # Legacy control mined from "Current mitigation (legacy)" text
        mit = (c.metadata.get("current_mitigation") or "").strip()
        if mit and mit.lower() not in {"none", "n/a", ""}:
            slug = _slugify(mit)
            control_id = f"CTRL:{slug}"
            if slug not in control_seen:
                control_seen[slug] = mit
                control_out.append({
                    "label": "Control",
                    "id": control_id,
                    "description": mit,
                    "kind": "legacy",
                })
            control_out.append({
                "type": "MITIGATES",
                "from": control_id,
                "to": threat_id,
                "state": c.metadata.get("state", ""),
            })
    return threat_nodes, threat_edges, dfd_nodes, control_out


# ---------------------------------------------------------------------------
# 3. Vulnerabilities + their code targets


def extract_vulnerabilities(chunks: list[Chunk]) -> tuple[list[dict], list[dict]]:
    """Returns (vuln_nodes, edges) where edges include LOCATED_IN to CodeArtifact."""
    vuln_nodes: list[dict] = []
    edges: list[dict] = []

    for c in chunks:
        if c.metadata.get("kind") != "vulnerability":
            continue
        vuln_id = c.metadata.get("item_id", "")
        if not vuln_id:
            continue

        target_file = c.metadata.get("target_file", "").strip()
        target_symbol = c.metadata.get("target_symbol", "").strip().rstrip("()")

        # Vuln plan uses paths relative to `firmware/`. Normalize to a repo-relative path.
        code_id = ""
        if target_file:
            norm = target_file
            if not norm.startswith("firmware/"):
                norm = f"firmware/{norm}"
            if target_symbol:
                code_id = f"CODE:{norm}:{target_symbol}"
            else:
                code_id = f"CODE:{norm}"

        vuln_nodes.append({
            "label": "Vulnerability",
            "id": vuln_id,
            "cwe": c.metadata.get("cwe", ""),
            "severity": c.metadata.get("severity", ""),
            "domain": c.metadata.get("domain", ""),
            "semgrep": c.metadata.get("semgrep", ""),
            "target_file": target_file,
            "target_symbol": target_symbol,
            "description": c.text.split("\n\n", 1)[-1][:2000],
            "source": c.metadata.get("source", ""),
        })
        if code_id:
            edges.append({"type": "LOCATED_IN", "from": vuln_id, "to": code_id})
    return vuln_nodes, edges


# ---------------------------------------------------------------------------
# 4. Code artifacts — one per code chunk from the chunker


def extract_code_artifacts(chunks: list[Chunk]) -> tuple[list[dict], list[dict]]:
    nodes: list[dict] = []
    seen: set[str] = set()

    for c in chunks:
        if c.metadata.get("kind") != "code":
            continue
        path = c.metadata.get("path", "")
        function = c.metadata.get("function", "")
        if function:
            code_id = f"CODE:{path}:{function}"
        else:
            code_id = f"CODE:{path}"
        if code_id in seen:
            continue
        seen.add(code_id)
        nodes.append({
            "label": "CodeArtifact",
            "id": code_id,
            "path": path,
            "function": function,
            "subsystem": c.metadata.get("subsystem", ""),
            "line_start": c.metadata.get("line_start", 0),
            "line_end": c.metadata.get("line_end", 0),
        })
    return nodes, []


# ---------------------------------------------------------------------------
# 5. Use cases + actors (parsed from use_case_document.md)


_UC_HEADING_RE = re.compile(r"^####?\s+(UC-[A-Z]+-\d+)\s*[·—-]\s*(.+)$")
_UC_ACTOR_RE = re.compile(r"^\*\*(?:Primary\s+)?Actor:?\*\*\s*(.+)$", re.IGNORECASE)


def extract_use_cases(corpus_root: Path) -> tuple[list[dict], list[dict]]:
    """Parse use_case_document.md for UC-* headings and their Actor line."""
    device_dir = corpus_root / "corpus"
    if not device_dir.exists():
        return [], []
    doc = next(iter(device_dir.iterdir()), None)
    if doc is None:
        return [], []
    uc_path = doc / "use_case_document.md"
    if not uc_path.exists():
        return [], []

    uc_nodes: list[dict] = []
    actor_nodes: list[dict] = []
    edges: list[dict] = []
    seen_actors: dict[str, str] = {}

    text = uc_path.read_text(encoding="utf-8")
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = _UC_HEADING_RE.match(line)
        if not m:
            continue
        uc_id = m.group(1)
        title = m.group(2).strip()
        # Scan ahead ~30 lines for an Actor: field
        actor_name = ""
        for look in lines[i + 1: i + 30]:
            am = _UC_ACTOR_RE.match(look.strip())
            if am:
                actor_name = am.group(1).strip().rstrip(".")
                break
        uc_nodes.append({
            "label": "UseCase",
            "id": uc_id,
            "title": title,
            "actor": actor_name,
        })
        if actor_name:
            slug = _slugify(actor_name)
            actor_id = f"ACTOR:{slug}"
            if slug not in seen_actors:
                seen_actors[slug] = actor_name
                actor_nodes.append({
                    "label": "Actor",
                    "id": actor_id,
                    "name": actor_name,
                })
            edges.append({"type": "INTERACTS_VIA", "from": actor_id, "to": uc_id})
    return uc_nodes + actor_nodes, edges


# ---------------------------------------------------------------------------
# Orchestrator


def build_extracts(device: str) -> ExtractStats:
    corpus_root = device_input_dir(device)
    if not corpus_root.exists():
        raise FileNotFoundError(
            f"input/{device}/ not found. Run: sra init --repo <URL> --device {device}"
        )

    console.print(f"[bold]Parsing[/] {corpus_root} for graph extraction …")
    chunks = list(walk_corpus(corpus_root))
    out_dir = EXTRACTS_DIR / device
    stats = ExtractStats(device=device)

    # 1. requirements.json
    req_nodes, req_edges = extract_requirements(chunks)
    _write_json(out_dir / "requirements.json", req_nodes, req_edges)
    stats.files["requirements.json"] = {"nodes": len(req_nodes), "edges": len(req_edges)}

    # 2, 6, 7. threats + dfd elements + legacy controls
    t_nodes, t_edges, dfd_nodes, control_out = extract_threats(chunks)
    _write_json(out_dir / "threats.json", t_nodes, t_edges)
    stats.files["threats.json"] = {"nodes": len(t_nodes), "edges": len(t_edges)}
    _write_json(out_dir / "dfd_elements.json", dfd_nodes, [])
    stats.files["dfd_elements.json"] = {"nodes": len(dfd_nodes), "edges": 0}
    ctrl_nodes = [x for x in control_out if "label" in x]
    ctrl_edges = [x for x in control_out if "type" in x]
    _write_json(out_dir / "controls.json", ctrl_nodes, ctrl_edges)
    stats.files["controls.json"] = {"nodes": len(ctrl_nodes), "edges": len(ctrl_edges)}

    # 3. vulnerabilities.json
    v_nodes, v_edges = extract_vulnerabilities(chunks)
    _write_json(out_dir / "vulnerabilities.json", v_nodes, v_edges)
    stats.files["vulnerabilities.json"] = {"nodes": len(v_nodes), "edges": len(v_edges)}

    # 4. code_artifacts.json
    code_nodes, _ = extract_code_artifacts(chunks)
    _write_json(out_dir / "code_artifacts.json", code_nodes, [])
    stats.files["code_artifacts.json"] = {"nodes": len(code_nodes), "edges": 0}

    # 5. use_cases.json (nodes = UseCase + Actor, edges = INTERACTS_VIA)
    uc_all, uc_edges = extract_use_cases(corpus_root)
    _write_json(out_dir / "use_cases.json", uc_all, uc_edges)
    stats.files["use_cases.json"] = {"nodes": len(uc_all), "edges": len(uc_edges)}

    stats.total_nodes = sum(f["nodes"] for f in stats.files.values())
    stats.total_edges = sum(f["edges"] for f in stats.files.values())

    # Report edges whose target id does not exist as a node in any extract file.
    # These are real data-quality issues in the corpus (typo references, drift
    # between docs and actual code layout, etc.), not extraction bugs. Surfacing
    # them here is useful — the SRA workflow flags them as documentation gaps.
    all_ids: set[str] = set()
    all_edges: list[dict[str, Any]] = []
    for name in stats.files:
        payload = json.loads((out_dir / name).read_text())
        all_ids.update(n["id"] for n in payload["nodes"])
        all_edges.extend(payload["edges"])
    dangling = [e for e in all_edges if e["to"] not in all_ids]
    dangling_by_type = Counter(e["type"] for e in dangling)
    if dangling:
        console.print(
            f"\n[yellow]Dangling edges (target id not present as a node): "
            f"{len(dangling)} / {len(all_edges)}[/]"
        )
        for t, n in dangling_by_type.most_common():
            console.print(f"  {t:15s} {n:5d}")
        console.print(
            "[dim]These are real traceability gaps in the corpus — the graph loader "
            "will skip them, and the Compliance Mapper agent will flag them.[/]"
        )
        # Write for later review
        (out_dir / "_dangling_edges.json").write_text(
            json.dumps(dangling, indent=2, ensure_ascii=False)
        )

    _print_summary(stats, out_dir)
    return stats


def _print_summary(stats: ExtractStats, out_dir: Path) -> None:
    table = Table(title=f"Graph extracts — {stats.device}")
    table.add_column("File")
    table.add_column("Nodes", justify="right")
    table.add_column("Edges", justify="right")
    for name, counts in stats.files.items():
        table.add_row(name, str(counts["nodes"]), str(counts["edges"]))
    table.add_row("[bold]TOTAL[/]", f"[bold]{stats.total_nodes}[/]", f"[bold]{stats.total_edges}[/]")
    console.print(table)
    console.print(f"Written to [green]{out_dir}[/]")
