"""Regulatory corpus indexer.

Reads framework/regulatory/*.json (FDA, IEC, AAMI, NIST) and writes each
clause as one chunk into the Chroma `regulatory` collection with
metadata suitable for filter-based retrieval by the Compliance Mapper.
"""

from __future__ import annotations

import json
from pathlib import Path

import chromadb
from chromadb.config import Settings
from rich.console import Console

from framework.config import CHROMA_DIR, REPO_ROOT
from framework.indexer.embed import EMBED_DIMS, EMBED_MODEL, Embedder

console = Console()

REGULATORY_DIR = REPO_ROOT / "framework" / "regulatory"
REGULATORY_COLLECTION = "regulatory"


def load_regulatory_clauses() -> list[dict]:
    """Read every JSON in framework/regulatory/ and return a flat clause list."""
    clauses: list[dict] = []
    if not REGULATORY_DIR.exists():
        return clauses
    for path in sorted(REGULATORY_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        for c in data.get("clauses", []):
            c["_source_file"] = path.name
            clauses.append(c)
    return clauses


def build_regulatory_index() -> int:
    """Chunk + embed + write the regulatory clauses into Chroma. Returns count."""
    clauses = load_regulatory_clauses()
    if not clauses:
        console.print("[yellow]No regulatory clauses found under framework/regulatory/[/]")
        return 0
    console.print(f"[bold]Regulatory[/] · {len(clauses)} clauses across "
                  f"{len({c['_source_file'] for c in clauses})} standards")

    client = chromadb.PersistentClient(
        path=str(CHROMA_DIR),
        settings=Settings(anonymized_telemetry=False),
    )
    try:
        client.delete_collection(REGULATORY_COLLECTION)
    except Exception:
        pass
    col = client.create_collection(
        name=REGULATORY_COLLECTION,
        metadata={"embed_model": EMBED_MODEL, "embed_dims": EMBED_DIMS},
    )

    embedder = Embedder()
    ids: list[str] = []
    texts: list[str] = []
    metas: list[dict] = []
    for c in clauses:
        ids.append(c["id"])
        # Chunk text is the clause body verbatim so LLM quotes are clean.
        # Standard/section/title/id all travel in metadata.
        texts.append(c["body"])
        metas.append({
            "clause_id": c["id"],
            "standard": c["standard"],
            "section": c["section"],
            "title": c["title"],
            "source_file": c["_source_file"],
            "keywords": ",".join(c.get("keywords", [])),
        })
    vectors = embedder.embed(texts)
    col.add(ids=ids, documents=texts, embeddings=vectors, metadatas=metas)
    console.print(f"  embedded {len(ids)} clauses · "
                  f"cost ~${embedder.stats.est_cost_usd:.4f}")
    return len(ids)
