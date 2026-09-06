"""Vector indexer — walk the cloned corpus, chunk, embed, write to Chroma.

Three Chroma collections live at stores/chroma/:
  - device_docs    (SRS/SDD/SDS/SAD/threats/vulns/narrative/vertical slice)
  - device_code    (firmware .c/.h function-level chunks)
  - regulatory     (created in Step 13; empty for now)

Everything is deterministic — chunk ids are stable across runs, so re-running
overwrites the same rows rather than creating duplicates.
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import chromadb
from chromadb.config import Settings
from rich.console import Console
from rich.table import Table

from framework.config import CHROMA_DIR, device_input_dir
from framework.indexer.chunker import Chunk, walk_corpus
from framework.indexer.embed import EMBED_DIMS, EMBED_MODEL, Embedder, EmbedStats

console = Console()

DOCS_COLLECTION = "device_docs"
CODE_COLLECTION = "device_code"
REGULATORY_COLLECTION = "regulatory"


@dataclass
class IndexStats:
    device: str
    total_chunks: int = 0
    docs_chunks: int = 0
    code_chunks: int = 0
    by_kind: dict[str, int] = field(default_factory=dict)
    by_source: dict[str, int] = field(default_factory=dict)
    embed: EmbedStats | None = None
    seconds: float = 0.0


def _get_client() -> chromadb.PersistentClient:
    CHROMA_DIR.mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(
        path=str(CHROMA_DIR),
        settings=Settings(anonymized_telemetry=False),
    )


def _reset_collection(client: chromadb.PersistentClient, name: str) -> chromadb.Collection:
    """Drop + recreate a collection so this run is authoritative."""
    try:
        client.delete_collection(name)
    except Exception:
        pass
    return client.create_collection(
        name=name,
        metadata={"embed_model": EMBED_MODEL, "embed_dims": EMBED_DIMS},
    )


def _sanitize_metadata(md: dict) -> dict:
    """Chroma metadata values must be primitive (str/int/float/bool). Coerce."""
    out: dict[str, str | int | float | bool] = {}
    for k, v in md.items():
        if v is None:
            continue
        if isinstance(v, (str, int, float, bool)):
            out[k] = v
        else:
            out[k] = str(v)
    return out


def _dedup_ids(chunks: list[Chunk]) -> list[Chunk]:
    """Append `#2`, `#3` etc. to any chunk id that collides with an earlier one.

    Preserves every chunk — nothing is dropped. Duplicates arise when two markdown
    sections resolve to the same slug (e.g. identical `### Overview` headings in
    different top-level sections).
    """
    seen: dict[str, int] = {}
    for c in chunks:
        n = seen.get(c.id, 0)
        if n:
            c.id = f"{c.id}#{n + 1}"
        seen[c.id.split('#')[0]] = n + 1
    return chunks


def _add_batch(collection: chromadb.Collection, chunks: list[Chunk], vectors: list[list[float]]) -> None:
    collection.add(
        ids=[c.id for c in chunks],
        documents=[c.text for c in chunks],
        embeddings=vectors,
        metadatas=[_sanitize_metadata(c.metadata) for c in chunks],
    )


def build_vector_index(device: str, dry_run: bool = False) -> IndexStats:
    """Chunk the cloned corpus for `device` and write vectors to Chroma."""
    corpus_root = device_input_dir(device)
    if not corpus_root.exists():
        raise FileNotFoundError(
            f"input/{device}/ not found. Run: sra init --repo <URL> --device {device}"
        )

    t0 = time.perf_counter()
    stats = IndexStats(device=device)

    # 1. Collect all chunks
    console.print(f"[bold]Chunking[/] {corpus_root} …")
    all_chunks: list[Chunk] = list(walk_corpus(corpus_root))
    all_chunks = _dedup_ids(all_chunks)
    stats.total_chunks = len(all_chunks)
    stats.by_kind = dict(Counter(c.metadata.get("kind", "?") for c in all_chunks))
    stats.by_source = dict(Counter(c.metadata.get("source", "?") for c in all_chunks))

    docs_chunks = [c for c in all_chunks if c.metadata.get("kind") != "code"]
    code_chunks = [c for c in all_chunks if c.metadata.get("kind") == "code"]
    stats.docs_chunks = len(docs_chunks)
    stats.code_chunks = len(code_chunks)

    console.print(
        f"  {stats.total_chunks} chunks total   "
        f"[cyan]{stats.docs_chunks}[/] docs   [magenta]{stats.code_chunks}[/] code"
    )
    for kind, n in sorted(stats.by_kind.items(), key=lambda x: -x[1]):
        console.print(f"    {kind:15s} {n:5d}")

    if dry_run:
        console.print("[yellow]--dry-run: skipping embedding + write[/]")
        stats.seconds = time.perf_counter() - t0
        return stats

    # 2. Embed + write per collection
    embedder = Embedder()
    stats.embed = embedder.stats
    client = _get_client()

    for collection_name, chunks in (
        (DOCS_COLLECTION, docs_chunks),
        (CODE_COLLECTION, code_chunks),
    ):
        if not chunks:
            continue
        console.print(f"\n[bold]Embedding[/] into [green]{collection_name}[/] ({len(chunks)} chunks) …")
        col = _reset_collection(client, collection_name)

        BATCH = 96
        for start in range(0, len(chunks), BATCH):
            batch = chunks[start:start + BATCH]
            vectors = embedder.embed([c.text for c in batch])
            _add_batch(col, batch, vectors)
            done = start + len(batch)
            console.print(f"  {done}/{len(chunks)}  (calls={embedder.stats.calls}, "
                          f"~${embedder.stats.est_cost_usd:.3f})")

    # Ensure regulatory collection exists (empty for now)
    try:
        client.get_collection(REGULATORY_COLLECTION)
    except Exception:
        client.create_collection(
            name=REGULATORY_COLLECTION,
            metadata={"embed_model": EMBED_MODEL, "embed_dims": EMBED_DIMS},
        )

    stats.seconds = time.perf_counter() - t0
    _print_summary(stats)
    return stats


def _print_summary(stats: IndexStats) -> None:
    table = Table(title=f"Vector index summary — {stats.device}", show_header=False)
    table.add_row("total chunks", str(stats.total_chunks))
    table.add_row("  docs collection", str(stats.docs_chunks))
    table.add_row("  code collection", str(stats.code_chunks))
    if stats.embed:
        table.add_row("embedding calls", str(stats.embed.calls))
        table.add_row("embedded tokens", f"{stats.embed.est_tokens:,}")
        table.add_row("est. cost (USD)", f"${stats.embed.est_cost_usd:.4f}")
    table.add_row("elapsed", f"{stats.seconds:.1f} s")
    table.add_row("chroma dir", str(CHROMA_DIR))
    console.print(table)
