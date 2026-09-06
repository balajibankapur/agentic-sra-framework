"""MCP server — corpus vector store.

Wraps stores/chroma/ (built by Step 2) as tools the agents can call:
  - search(query, k, filters, collection)   semantic retrieval
  - get_chunk(chunk_id, collection)         fetch a chunk by id
  - list_collections()                      enumerate collections

Launch standalone for smoke testing:
    sra mcp vector

Or from an agent framework, spawn as a stdio subprocess.
"""

from __future__ import annotations

import json
from typing import Any

import chromadb
from chromadb.config import Settings
from mcp.server.mcpserver import MCPServer

from framework.config import CHROMA_DIR
from framework.indexer.embed import Embedder

_client: chromadb.PersistentClient | None = None
_embedder: Embedder | None = None


def _get_client() -> chromadb.PersistentClient:
    global _client
    if _client is None:
        _client = chromadb.PersistentClient(
            path=str(CHROMA_DIR),
            settings=Settings(anonymized_telemetry=False),
        )
    return _client


def _get_embedder() -> Embedder:
    global _embedder
    if _embedder is None:
        _embedder = Embedder()
    return _embedder


mcp = MCPServer(
    name="corpus-vector",
    instructions=(
        "Semantic-search + retrieval over the device's docs and code. "
        "Collections: device_docs (SRS/SDD/SDS/SAD/threats/vulns/narrative), "
        "device_code (firmware functions), regulatory (FDA/IEC/AAMI/NIST, empty "
        "until Step 13). Use filters like {'kind': 'threat'} or {'category': 'OTA'} "
        "to narrow results. Prefer this over grep for meaning-based lookups."
    ),
)


@mcp.tool()
def search(
    query: str,
    k: int = 6,
    filters: dict[str, Any] | None = None,
    collection: str = "device_docs",
) -> list[dict[str, Any]]:
    """Semantic search over a Chroma collection.

    Args:
        query: natural-language query, e.g. "firmware update signature verification"
        k: how many results to return (default 6, max 30)
        filters: metadata equality filters, e.g. {"kind": "threat"} or
                 {"category": "OTA", "kind": "requirement"}
        collection: "device_docs" | "device_code" | "regulatory"

    Returns:
        List of {id, score, text, metadata} dicts, best first.
    """
    k = max(1, min(k, 30))
    col = _get_client().get_collection(collection)
    qv = _get_embedder().embed([query])[0]

    where = None
    if filters:
        # Chroma expects {"$and": [{"k": {"$eq": v}}, ...]} for multi-key filters,
        # but a single-key filter can be passed as {"k": {"$eq": v}} directly.
        clauses = [{k_: {"$eq": v_}} for k_, v_ in filters.items()]
        where = clauses[0] if len(clauses) == 1 else {"$and": clauses}

    res = col.query(query_embeddings=[qv], n_results=k, where=where)
    out: list[dict[str, Any]] = []
    for id_, doc, md, dist in zip(
        res["ids"][0], res["documents"][0], res["metadatas"][0], res["distances"][0]
    ):
        out.append({
            "id": id_,
            "score": 1.0 - float(dist),   # cosine distance -> similarity
            "text": doc,
            "metadata": md,
        })
    return out


@mcp.tool()
def get_chunk(chunk_id: str, collection: str = "device_docs") -> dict[str, Any] | None:
    """Fetch a single chunk by id.

    Args:
        chunk_id: e.g. "SRS::SRS-OTA-0014" or "VULN::VULN-01" or
                  "CODE::firmware/app_mcu/ota/install_handler.c::install_image"
        collection: which collection to search
    """
    col = _get_client().get_collection(collection)
    res = col.get(ids=[chunk_id], include=["documents", "metadatas"])
    if not res["ids"]:
        return None
    return {
        "id": res["ids"][0],
        "text": res["documents"][0],
        "metadata": res["metadatas"][0],
    }


@mcp.tool()
def list_collections() -> list[dict[str, Any]]:
    """List every Chroma collection with its count and embed model."""
    client = _get_client()
    out: list[dict[str, Any]] = []
    for c in client.list_collections():
        col = client.get_collection(c.name)
        out.append({
            "name": c.name,
            "count": col.count(),
            "metadata": c.metadata or {},
        })
    return out


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
