"""Ingestion agent — SDD §2.1.

Pure Cypher query in v1 (no LLM). Loads the ordered threat queue from the
Kuzu graph, respecting the CLI filters (--limit / --category / --threat)
carried on SRAState.
"""

from __future__ import annotations

import kuzu

from framework.agents.state import SRAState
from framework.config import KUZU_DIR


def run_ingestion(state: SRAState, *, category: str | None = None, threat: str | None = None, limit: int | None = None) -> dict:
    """Populate state.threat_queue via Cypher. Returns partial state update."""
    db_path = KUZU_DIR / f"{state.device}.kuzu"
    conn = kuzu.Connection(kuzu.Database(str(db_path)))

    where_clauses = []
    params: dict[str, object] = {}
    if threat:
        where_clauses.append("t.id = $threat")
        params["threat"] = threat
    if category:
        # threat ids like T-OTA-P01-T; category filter uses substring match on id
        where_clauses.append("t.id CONTAINS $category")
        params["category"] = f"-{category}-"

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    limit_sql = f"LIMIT {int(limit)}" if limit else ""

    query = f"""
        MATCH (t:Threat) {where_sql}
        RETURN t.id AS id
        ORDER BY
            CASE t.priority
                WHEN 'Critical' THEN 0
                WHEN 'High'     THEN 1
                WHEN 'Medium'   THEN 2
                WHEN 'Low'      THEN 3
                ELSE 4
            END,
            t.id ASC
        {limit_sql};
    """
    res = conn.execute(query, parameters=params)
    ids: list[str] = []
    while res.has_next():
        ids.append(res.get_next()[0])
    return {"threat_queue": ids}
