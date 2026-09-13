"""Ingestion agent — SDD §2.1.

Pure Cypher query in v1 (no LLM). Loads the ordered threat queue from the
Kuzu graph, respecting the CLI filters (--limit / --category / --threat)
carried on SRAState.
"""

from __future__ import annotations

import kuzu

from framework.agents.state import SRAState
from framework.config import KUZU_DIR


def run_ingestion(
    state: SRAState,
    *,
    category: str | None = None,
    threat: str | None = None,
    limit: int | None = None,
    strategy: str = "priority",
) -> dict:
    """Populate state.threat_queue via Cypher.

    Strategies:
      priority     order by priority band then id (default; matches SDD §2.1)
      code-linked  prioritise threats reachable to seeded VULN CodeArtifacts
                   (better for a small pilot targeting the code-side eval)
    """
    db_path = KUZU_DIR / f"{state.device}.kuzu"
    conn = kuzu.Connection(kuzu.Database(str(db_path)))

    where_clauses = []
    params: dict[str, object] = {}
    if threat:
        where_clauses.append("t.id = $threat")
        params["threat"] = threat
    if category:
        where_clauses.append("t.id CONTAINS $category")
        params["category"] = f"-{category}-"

    where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
    limit_sql = f"LIMIT {int(limit)}" if limit else ""

    if strategy == "code-linked":
        # Two-phase rank: post-process in Python because Kuzu can't easily
        # do the fuzzy subsystem match we need.
        # Phase 1: extract the distinct subsystem tokens where seeded VULNs
        # actually live (ota, storage, network, ble, emr, boot, ...).
        # Phase 2: pull all threats + priority, then score each threat by
        # whether its id contains any of those tokens (case-insensitive).
        # Highest-scoring threats first, then by priority band.

        vuln_sub_res = conn.execute(
            "MATCH (v:Vulnerability)-[:LOCATED_IN]->(c:CodeArtifact) "
            "RETURN DISTINCT c.subsystem AS sub;"
        )
        subsystems: set[str] = set()
        while vuln_sub_res.has_next():
            sub = (vuln_sub_res.get_next()[0] or "").lower()
            for token in sub.split("/"):
                if token and token != "app_mcu":  # too generic
                    subsystems.add(token)

        base_query = f"""
            MATCH (t:Threat) {where_sql}
            RETURN t.id AS id, t.priority AS priority
            ORDER BY t.id ASC;
        """
        all_res = conn.execute(base_query, parameters=params)
        rows: list[tuple[str, str]] = []
        while all_res.has_next():
            r = all_res.get_next()
            rows.append((r[0], r[1] or "Medium"))

        prio_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

        # Bucket each threat under EACH subsystem token it matches. A threat
        # like DF-BLEPAIR-I matches only 'ble'; T-OTA-P01-T matches 'ota'.
        # Threats matching no VULN subsystem token go into the '_unmatched' bucket.
        from collections import defaultdict
        buckets: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for tid, prio in rows:
            idl = tid.lower()
            matches = [s for s in subsystems if s in idl]
            if matches:
                for s in matches:
                    buckets[s].append((tid, prio))
            else:
                buckets["_unmatched"].append((tid, prio))
        # Sort each bucket by priority band then id
        for s in buckets:
            buckets[s].sort(key=lambda r: (prio_rank.get(r[1], 4), r[0]))

        # Round-robin across VULN-linked subsystems first (skip _unmatched
        # until every subsystem has been sampled). Deduplicates ids that
        # matched multiple tokens.
        seen: set[str] = set()
        result: list[str] = []
        active_subs = sorted(s for s in buckets if s != "_unmatched")
        # Round-robin the VULN-linked buckets
        while active_subs and (not limit or len(result) < int(limit)):
            for s in list(active_subs):
                if not buckets[s]:
                    active_subs.remove(s)
                    continue
                tid, _ = buckets[s].pop(0)
                if tid in seen:
                    continue
                seen.add(tid)
                result.append(tid)
                if limit and len(result) >= int(limit):
                    break
        # If we still have budget, fall through to unmatched threats
        if not limit or len(result) < int(limit):
            for tid, _ in buckets.get("_unmatched", []):
                if tid in seen:
                    continue
                seen.add(tid)
                result.append(tid)
                if limit and len(result) >= int(limit):
                    break

        return {"threat_queue": result}
    else:  # priority (default)
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
