"""Kuzu graph loader — bulk-load the 7 JSON extracts into stores/kuzu/.

Schema is fixed at load time. Node tables carry all the properties present
on the JSON node payloads. Relationship tables are declared with FROM/TO
node tables, matching the graph schema in docs/roadmap.md.

Every JSON edge whose target id does not appear as a node is skipped and
counted — the graph must be internally consistent for Cypher to work.
"""

from __future__ import annotations

import json
import shutil
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

import kuzu
from rich.console import Console
from rich.table import Table

from framework.config import EXTRACTS_DIR, KUZU_DIR

console = Console()


# ---------------------------------------------------------------------------
# Schema — node tables and relationship tables

# Each entry lists (label, primary-key column, additional columns as (name, type))
NODE_TABLES: list[tuple[str, str, list[tuple[str, str]]]] = [
    ("Requirement", "id", [
        ("title", "STRING"), ("body", "STRING"), ("category", "STRING"),
        ("priority", "STRING"), ("verify", "STRING"), ("source", "STRING"),
    ]),
    ("DesignItem", "id", [
        ("title", "STRING"), ("body", "STRING"), ("category", "STRING"),
        ("source", "STRING"),
    ]),
    ("ImplementationItem", "id", [
        ("title", "STRING"), ("body", "STRING"), ("category", "STRING"),
        ("location", "STRING"), ("source", "STRING"),
    ]),
    ("ArchitectureItem", "id", [
        ("title", "STRING"), ("body", "STRING"), ("category", "STRING"),
        ("source", "STRING"),
    ]),
    ("Threat", "id", [
        ("title", "STRING"), ("description", "STRING"),
        ("stride", "STRING"), ("stride_category", "STRING"),
        ("section", "STRING"), ("priority", "STRING"), ("state", "STRING"),
        ("source", "STRING"),
    ]),
    ("Vulnerability", "id", [
        ("cwe", "STRING"), ("severity", "STRING"), ("domain", "STRING"),
        ("semgrep", "STRING"), ("target_file", "STRING"), ("target_symbol", "STRING"),
        ("description", "STRING"), ("source", "STRING"),
    ]),
    ("CodeArtifact", "id", [
        ("path", "STRING"), ("function", "STRING"), ("subsystem", "STRING"),
        ("line_start", "INT64"), ("line_end", "INT64"),
    ]),
    ("Control", "id", [
        ("description", "STRING"), ("kind", "STRING"),
    ]),
    ("UseCase", "id", [
        ("title", "STRING"), ("actor", "STRING"),
    ]),
    ("Actor", "id", [
        ("name", "STRING"),
    ]),
    ("DFDElement", "id", [
        ("element_id", "STRING"), ("kind", "STRING"),
    ]),
]

# Each entry lists (rel_name, from_table, to_table, [extra columns])
REL_TABLES: list[tuple[str, str, str, list[tuple[str, str]]]] = [
    ("TRACES_TO",     "Requirement",        "ArchitectureItem",   []),
    ("IMPLEMENTS",    "DesignItem",         "Requirement",        []),
    ("REALIZES",      "ImplementationItem", "DesignItem",         []),
    ("REALIZED_BY",   "ImplementationItem", "CodeArtifact",       []),
    ("LOCATED_IN",    "Vulnerability",      "CodeArtifact",       []),
    ("MITIGATES",     "Control",            "Threat",             [("state", "STRING")]),
    ("APPLIES_TO",    "Threat",             "DFDElement",         []),
    ("INTERACTS_VIA", "Actor",              "UseCase",            []),
]


# Which JSON file feeds which node table(s) and rel table(s).
# Format: filename -> ({label: extra_props_to_extract}, {rel_type: (from_label, to_label, extra_props)})
FILE_TO_NODE_LABELS: dict[str, set[str]] = {
    "requirements.json":    {"Requirement", "DesignItem", "ImplementationItem", "ArchitectureItem"},
    "threats.json":         {"Threat"},
    "vulnerabilities.json": {"Vulnerability"},
    "code_artifacts.json":  {"CodeArtifact"},
    "controls.json":        {"Control"},
    "use_cases.json":       {"UseCase", "Actor"},
    "dfd_elements.json":    {"DFDElement"},
}


@dataclass
class LoadStats:
    device: str
    nodes_by_label: Counter = field(default_factory=Counter)
    edges_by_type: Counter = field(default_factory=Counter)
    edges_skipped_by_type: Counter = field(default_factory=Counter)
    total_nodes: int = 0
    total_edges: int = 0
    total_skipped: int = 0


# ---------------------------------------------------------------------------
# Kuzu helpers


def _create_schema(conn: kuzu.Connection) -> None:
    for label, pk, cols in NODE_TABLES:
        col_defs = [f"{pk} STRING PRIMARY KEY"] + [f"{c} {t}" for c, t in cols]
        stmt = f"CREATE NODE TABLE {label}({', '.join(col_defs)});"
        conn.execute(stmt)
    for rel, src, dst, extras in REL_TABLES:
        extra = ", " + ", ".join(f"{c} {t}" for c, t in extras) if extras else ""
        stmt = f"CREATE REL TABLE {rel}(FROM {src} TO {dst}{extra});"
        conn.execute(stmt)


def _coerce(v: Any, target_type: str) -> Any:
    if v is None:
        return "" if target_type == "STRING" else 0
    if target_type == "STRING":
        return str(v)
    if target_type == "INT64":
        try:
            return int(v)
        except (TypeError, ValueError):
            return 0
    return v


def _insert_nodes(
    conn: kuzu.Connection,
    label: str,
    pk: str,
    cols: list[tuple[str, str]],
    rows: list[dict],
) -> int:
    if not rows:
        return 0
    col_names = [pk] + [c for c, _ in cols]
    types = {pk: "STRING", **dict(cols)}
    placeholders = ", ".join(f"${c}" for c in col_names)
    stmt = f"CREATE (:{label} {{{', '.join(f'{c}: {ph}' for c, ph in zip(col_names, [f'${c}' for c in col_names]))}}});"
    n = 0
    for r in rows:
        params = {c: _coerce(r.get(c), types[c]) for c in col_names}
        conn.execute(stmt, parameters=params)
        n += 1
    return n


def _insert_edges(
    conn: kuzu.Connection,
    rel: str,
    src_label: str,
    dst_label: str,
    extras: list[tuple[str, str]],
    edges: list[dict],
    valid_ids: dict[str, set[str]],
) -> tuple[int, int]:
    if not edges:
        return 0, 0
    src_ids = valid_ids.get(src_label, set())
    dst_ids = valid_ids.get(dst_label, set())

    extra_names = [c for c, _ in extras]
    extra_types = dict(extras)

    set_clause = ""
    if extra_names:
        set_clause = " SET " + ", ".join(f"r.{c} = ${c}" for c in extra_names)

    stmt = (
        f"MATCH (a:{src_label} {{id: $from_id}}), (b:{dst_label} {{id: $to_id}}) "
        f"CREATE (a)-[r:{rel}]->(b){set_clause};"
    )

    inserted = 0
    skipped = 0
    for e in edges:
        f_id = e["from"]
        t_id = e["to"]
        if f_id not in src_ids or t_id not in dst_ids:
            skipped += 1
            continue
        params = {"from_id": f_id, "to_id": t_id}
        for c in extra_names:
            params[c] = _coerce(e.get(c), extra_types[c])
        conn.execute(stmt, parameters=params)
        inserted += 1
    return inserted, skipped


# ---------------------------------------------------------------------------
# Orchestrator


def build_graph_index(device: str, wipe: bool = True) -> LoadStats:
    extracts_dir = EXTRACTS_DIR / device
    if not extracts_dir.exists():
        raise FileNotFoundError(
            f"{extracts_dir} not found. Run: sra extract --device {device}"
        )

    db_path = KUZU_DIR / f"{device}.kuzu"
    if wipe:
        for p in (db_path, db_path.with_suffix(".kuzu.wal")):
            if p.exists():
                if p.is_dir():
                    shutil.rmtree(p)
                else:
                    p.unlink()
    KUZU_DIR.mkdir(parents=True, exist_ok=True)

    console.print(f"[bold]Creating Kuzu database[/] at [cyan]{db_path}[/] …")
    db = kuzu.Database(str(db_path))
    conn = kuzu.Connection(db)
    _create_schema(conn)

    stats = LoadStats(device=device)

    # 1. Load all node files first — group by label so we can insert per-table.
    nodes_by_label: dict[str, list[dict]] = {label: [] for label, _, _ in NODE_TABLES}
    all_edges: list[dict] = []
    for filename in FILE_TO_NODE_LABELS:
        path = extracts_dir / filename
        if not path.exists():
            continue
        payload = json.loads(path.read_text())
        for n in payload["nodes"]:
            label = n.get("label")
            if label in nodes_by_label:
                nodes_by_label[label].append(n)
        all_edges.extend(payload["edges"])

    console.print("[bold]Inserting nodes[/] …")
    for label, pk, cols in NODE_TABLES:
        n = _insert_nodes(conn, label, pk, cols, nodes_by_label[label])
        if n:
            stats.nodes_by_label[label] = n
        stats.total_nodes += n

    # 2. Build a set of ids per label so edge loader can validate targets.
    valid_ids: dict[str, set[str]] = {
        label: {r["id"] for r in rows}
        for label, rows in nodes_by_label.items()
    }

    console.print("[bold]Inserting edges[/] …")
    # Group edges by type so we can pick the right (src_label, dst_label).
    edges_by_type: dict[str, list[dict]] = {}
    for e in all_edges:
        edges_by_type.setdefault(e["type"], []).append(e)

    for rel, src, dst, extras in REL_TABLES:
        rows = edges_by_type.get(rel, [])
        inserted, skipped = _insert_edges(conn, rel, src, dst, extras, rows, valid_ids)
        if inserted:
            stats.edges_by_type[rel] = inserted
        if skipped:
            stats.edges_skipped_by_type[rel] = skipped
        stats.total_edges += inserted
        stats.total_skipped += skipped

    _print_summary(stats)
    _run_sanity_queries(conn)
    return stats


def _print_summary(stats: LoadStats) -> None:
    table = Table(title=f"Graph load — {stats.device}")
    table.add_column("Table")
    table.add_column("Loaded", justify="right")
    table.add_column("Skipped", justify="right")
    for label in [n for n, _, _ in NODE_TABLES]:
        table.add_row(f"(:{label})", str(stats.nodes_by_label.get(label, 0)), "-")
    for rel, _, _, _ in REL_TABLES:
        table.add_row(f"[:{rel}]", str(stats.edges_by_type.get(rel, 0)),
                      str(stats.edges_skipped_by_type.get(rel, 0)))
    table.add_row("[bold]TOTAL[/]",
                  f"[bold]{stats.total_nodes} nodes  {stats.total_edges} edges[/]",
                  f"[bold]{stats.total_skipped}[/]")
    console.print(table)
    console.print(f"Kuzu database: [green]{KUZU_DIR}[/]")


def _run_sanity_queries(conn: kuzu.Connection) -> None:
    """Two small demonstration queries so we know Cypher actually works."""
    console.print("\n[bold]Sanity queries[/]")

    # 1. Count all node labels
    q1 = "MATCH (n) RETURN LABEL(n) AS label, count(*) AS n ORDER BY n DESC;"
    res = conn.execute(q1)
    console.print("  Nodes by label:")
    while res.has_next():
        row = res.get_next()
        console.print(f"    {row[0]:20s} {row[1]}")

    # 2. Walk VULN-01 -> code -> ? and the reverse (any control mitigating anything related?)
    q2 = (
        "MATCH (v:Vulnerability {id: 'VULN-01'})-[:LOCATED_IN]->(c:CodeArtifact) "
        "RETURN v.id, v.severity, c.path, c.function;"
    )
    res = conn.execute(q2)
    console.print("  VULN-01 chain:")
    while res.has_next():
        row = res.get_next()
        console.print(f"    {row[0]}  [{row[1]}]  ->  {row[2]}::{row[3]}")

    # 3. Threats applying to E-BIOMED (external entity)
    q3 = (
        "MATCH (t:Threat)-[:APPLIES_TO]->(d:DFDElement {id: 'DFD:E-BIOMED'}) "
        "RETURN t.id, t.stride, t.title;"
    )
    res = conn.execute(q3)
    console.print("  Threats on DFD:E-BIOMED:")
    while res.has_next():
        row = res.get_next()
        console.print(f"    {row[0]}  [{row[1]}]  {row[2]}")
