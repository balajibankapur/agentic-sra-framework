"""MCP server — corpus graph store (Kuzu).

Wraps stores/kuzu/<device>.kuzu (built by Step 4) as tools:
  - cypher(query, params)       arbitrary read-only Cypher
  - neighbors(node_id, ...)     walk from a node one hop
  - path(from_id, to_id, ...)   shortest path
  - list_schema()               node + rel tables

The cypher tool refuses any write (CREATE/MERGE/DELETE/SET/DROP/ALTER).
"""

from __future__ import annotations

import os
import re
from typing import Any

import kuzu
from mcp.server.mcpserver import MCPServer

from framework.config import KUZU_DIR

_conn: kuzu.Connection | None = None


def _get_conn() -> kuzu.Connection:
    global _conn
    if _conn is None:
        device = os.getenv("SRA_DEVICE", "pmx100")
        db_path = KUZU_DIR / f"{device}.kuzu"
        if not db_path.exists():
            raise FileNotFoundError(
                f"Kuzu database not found at {db_path}. "
                f"Run: sra index --device {device}"
            )
        _conn = kuzu.Connection(kuzu.Database(str(db_path)))
    return _conn


mcp = MCPServer(
    name="corpus-graph",
    instructions=(
        "Cypher-queryable property graph of the device's requirements, threats, "
        "vulnerabilities, code artifacts, controls, DFD elements, use cases and "
        "actors. Node labels: Requirement, DesignItem, ImplementationItem, "
        "ArchitectureItem, Threat, Vulnerability, CodeArtifact, Control, UseCase, "
        "Actor, DFDElement. Relationships: TRACES_TO, IMPLEMENTS, REALIZES, "
        "REALIZED_BY, LOCATED_IN, MITIGATES, APPLIES_TO, INTERACTS_VIA. Use this "
        "for structural queries — 'walk from a threat to its mitigating controls "
        "and the clauses they satisfy' — where the answer is a graph shape, not a "
        "text passage."
    ),
)


_WRITE_RE = re.compile(
    r"\b(CREATE|MERGE|DELETE|SET|DROP|ALTER|COPY|INSERT|REMOVE|LOAD)\b",
    re.IGNORECASE,
)


def _rows_to_dicts(result: kuzu.QueryResult) -> list[dict[str, Any]]:
    cols = result.get_column_names()
    out: list[dict[str, Any]] = []
    while result.has_next():
        row = result.get_next()
        out.append({cols[i]: _sanitize(v) for i, v in enumerate(row)})
    return out


def _sanitize(v: Any) -> Any:
    """Kuzu returns Python-native types already for scalars, but nodes/rels
    come back as dicts with an `_ID`/`_LABEL` — pass those through."""
    if hasattr(v, "isoformat"):
        return v.isoformat()
    return v


@mcp.tool()
def cypher(query: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Run a read-only Cypher query.

    Args:
        query: any MATCH / RETURN Cypher. Writes are refused.
        params: parameter dict for `$name` placeholders in the query.

    Returns:
        List of row dicts (column name -> value). Empty list if no rows.

    Examples:
        cypher("MATCH (v:Vulnerability) RETURN v.id, v.severity ORDER BY v.id LIMIT 5")
        cypher("MATCH (t:Threat {stride: 'S'})-[:APPLIES_TO]->(d:DFDElement) "
               "RETURN t.id, t.title, d.id")
    """
    if _WRITE_RE.search(query):
        raise ValueError(
            "This tool is read-only. Refusing query containing "
            "CREATE/MERGE/DELETE/SET/DROP/ALTER/COPY/INSERT/REMOVE/LOAD."
        )
    conn = _get_conn()
    res = conn.execute(query, parameters=params or {})
    return _rows_to_dicts(res)


@mcp.tool()
def neighbors(
    node_id: str,
    edge_type: str | None = None,
    direction: str = "out",
    depth: int = 1,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Walk from a node one or more hops and return the reachable neighbors.

    Args:
        node_id: e.g. "VULN-01", "SRS-OTA-0014", "T-OTA-P01-T"
        edge_type: filter to a single relationship type, e.g. "LOCATED_IN"
                   (None = all types)
        direction: "out" | "in" | "both"
        depth: 1-3 hops
        limit: max neighbors to return

    Returns:
        List of {edge_type, direction, hops, node_label, node_id, ...properties}
    """
    depth = max(1, min(depth, 3))
    limit = max(1, min(limit, 200))
    edge_pattern = f":{edge_type}" if edge_type else ""
    if direction == "out":
        arrow_l, arrow_r = "-", "->"
    elif direction == "in":
        arrow_l, arrow_r = "<-", "-"
    else:  # both
        arrow_l, arrow_r = "-", "-"
    hop_range = "" if depth == 1 else f"*1..{depth}"

    q = (
        f"MATCH (start {{id: $id}}) {arrow_l}[r{edge_pattern}{hop_range}]{arrow_r} (n) "
        f"RETURN LABEL(n) AS label, n.id AS id, n LIMIT {limit};"
    )
    conn = _get_conn()
    res = conn.execute(q, parameters={"id": node_id})
    out: list[dict[str, Any]] = []
    while res.has_next():
        row = res.get_next()
        label, nid, node = row[0], row[1], row[2]
        entry = {"label": label, "id": nid}
        if isinstance(node, dict):
            for k, v in node.items():
                if k.startswith("_") or k == "id":
                    continue
                entry[k] = _sanitize(v)
        out.append(entry)
    return out


@mcp.tool()
def path(from_id: str, to_id: str, max_depth: int = 4) -> list[dict[str, Any]] | None:
    """Shortest path between two nodes (by any relationship).

    Args:
        from_id: source node id
        to_id: destination node id
        max_depth: max path length (default 4)

    Returns:
        List of hops [{from_id, edge, to_id}] or None if no path.
    """
    max_depth = max(1, min(max_depth, 8))
    q = (
        f"MATCH p = (a {{id: $from_id}})-[*1..{max_depth}]-(b {{id: $to_id}}) "
        f"RETURN p LIMIT 1;"
    )
    conn = _get_conn()
    res = conn.execute(q, parameters={"from_id": from_id, "to_id": to_id})
    if not res.has_next():
        return None
    row = res.get_next()
    p = row[0]
    hops: list[dict[str, Any]] = []
    nodes = p.get("_NODES", []) if isinstance(p, dict) else []
    rels = p.get("_RELS", []) if isinstance(p, dict) else []
    for i, rel in enumerate(rels):
        hops.append({
            "from_id": nodes[i].get("id") if i < len(nodes) else None,
            "edge": rel.get("_LABEL") if isinstance(rel, dict) else str(rel),
            "to_id": nodes[i + 1].get("id") if i + 1 < len(nodes) else None,
        })
    return hops


@mcp.tool()
def list_schema() -> dict[str, list[str]]:
    """Return the graph schema — node table names + rel table names."""
    conn = _get_conn()
    tables = _rows_to_dicts(conn.execute("CALL show_tables() RETURN *;"))
    nodes: list[str] = []
    rels: list[str] = []
    for t in tables:
        name = t.get("name") or t.get("TABLE_NAME") or ""
        ttype = (t.get("type") or t.get("TABLE_TYPE") or "").upper()
        if ttype.startswith("NODE"):
            nodes.append(name)
        elif ttype.startswith("REL"):
            rels.append(name)
    return {"node_tables": sorted(nodes), "rel_tables": sorted(rels)}


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
