"""Top-level CLI. Real subcommands land in later steps."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from framework.clone import clone_corpus, read_manifest

app = typer.Typer(
    name="sra",
    help="Agentic SRA Framework — draft an FDA cybersecurity SRA for a connected medical device.",
    no_args_is_help=True,
)
console = Console()


def _human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


@app.command()
def init(
    repo: str = typer.Option(..., "--repo", help="GitHub URL of the legacy corpus repo."),
    device: str = typer.Option(..., "--device", help="Short device name, e.g. pmx100."),
    force: bool = typer.Option(False, "--force", help="Replace input/<device>/ if it exists."),
) -> None:
    """Clone the legacy corpus into input/<device>/ and record its commit SHA."""
    try:
        m = clone_corpus(repo_url=repo, device=device, force=force)
    except FileExistsError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(code=2)

    table = Table(title=f"Cloned {device}", show_header=False)
    table.add_row("repo", m.repo_url)
    table.add_row("commit", f"{m.commit_sha[:12]}  {m.commit_subject}")
    table.add_row("files", str(m.file_count))
    table.add_row("size", _human_bytes(m.total_bytes))
    table.add_row("cloned_at", m.cloned_at_utc)
    console.print(table)
    console.print(f"\nNext: [bold]sra index[/] to build vector + graph stores.")


@app.command()
def status(
    device: str = typer.Option(..., "--device", help="Device to inspect."),
) -> None:
    """Show what has been cloned and indexed for a device."""
    m = read_manifest(device)
    if m is None:
        console.print(f"[yellow]No manifest for '{device}'. Run: sra init --repo <URL> --device {device}[/]")
        raise typer.Exit(code=1)
    table = Table(title=f"{device} status", show_header=False)
    table.add_row("repo", m.repo_url)
    table.add_row("commit", f"{m.commit_sha[:12]}  {m.commit_subject}")
    table.add_row("files", str(m.file_count))
    table.add_row("size", _human_bytes(m.total_bytes))
    table.add_row("cloned_at", m.cloned_at_utc)
    console.print(table)


@app.command()
def extract(
    device: str = typer.Option(..., "--device", help="Device to extract graph JSON for."),
) -> None:
    """Parse the corpus into 7 JSON extract files under stores/extracts/<device>/."""
    from framework.indexer.graph_extract import build_extracts
    build_extracts(device)


@app.command()
def index(
    device: str = typer.Option(..., "--device", help="Device to index."),
    vectors: bool = typer.Option(True, "--vectors/--no-vectors", help="Build the Chroma vector index."),
    extract_json: bool = typer.Option(True, "--extract/--no-extract", help="Build the graph JSON extracts."),
    graph: bool = typer.Option(True, "--graph/--no-graph", help="Build the Kuzu graph index (Step 4)."),
    regulatory: bool = typer.Option(True, "--regulatory/--no-regulatory",
                                    help="Also (re)build the regulatory collection."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Chunk and count only; skip embedding + writes."),
) -> None:
    """Build vector + graph indices from input/<device>/."""
    if vectors:
        from framework.indexer.vector import build_vector_index
        build_vector_index(device, dry_run=dry_run)
    if extract_json:
        from framework.indexer.graph_extract import build_extracts
        build_extracts(device)
    if graph:
        from framework.indexer.graph_load import build_graph_index
        build_graph_index(device)
    if regulatory and not dry_run:
        from framework.indexer.regulatory import build_regulatory_index
        build_regulatory_index()


@app.command()
def mcp(
    server: str = typer.Argument(..., help="One of: vector, graph, files"),
    device: str = typer.Option("pmx100", "--device", help="Device the server reads from."),
) -> None:
    """Launch an MCP server on stdio (for debugging or connecting a client)."""
    import os
    os.environ.setdefault("SRA_DEVICE", device)
    if server == "vector":
        from framework.mcp_servers.corpus_vector_server import main
    elif server == "graph":
        from framework.mcp_servers.corpus_graph_server import main
    elif server == "files":
        from framework.mcp_servers.corpus_files_server import main
    else:
        console.print(f"[red]Unknown server '{server}'. Choose: vector | graph | files[/]")
        raise typer.Exit(code=2)
    main()


@app.command("mcp-test")
def mcp_test(
    device: str = typer.Option("pmx100", "--device", help="Device to test against."),
) -> None:
    """In-process smoke test — calls each server's tool functions directly."""
    import os
    os.environ.setdefault("SRA_DEVICE", device)
    from framework.mcp_servers import corpus_vector_server as v
    from framework.mcp_servers import corpus_graph_server as g
    from framework.mcp_servers import corpus_files_server as f

    console.rule("[bold]corpus-vector[/]")
    cols = v.list_collections()
    for c in cols:
        console.print(f"  collection {c['name']:15s} count={c['count']}")
    hits = v.search("firmware update signature verification", k=3)
    console.print(f"\n  search top-3:")
    for h in hits:
        console.print(f"    {h['score']:.3f}  [{h['id']}]  {h['text'][:80]}...")

    console.rule("[bold]corpus-graph[/]")
    schema = g.list_schema()
    console.print(f"  node tables: {schema['node_tables']}")
    console.print(f"  rel tables:  {schema['rel_tables']}")
    rows = g.cypher(
        "MATCH (v:Vulnerability {id: 'VULN-01'})-[:LOCATED_IN]->(c:CodeArtifact) "
        "RETURN v.severity AS sev, c.path AS path, c.function AS fn;"
    )
    console.print(f"\n  VULN-01 -[:LOCATED_IN]-> {rows}")
    nbrs = g.neighbors("VULN-01", edge_type="LOCATED_IN")
    console.print(f"  neighbors(VULN-01, LOCATED_IN): {nbrs}")

    console.rule("[bold]corpus-files[/]")
    top = f.list_dir("")
    console.print(f"  root entries: {[e['name'] for e in top]}")
    hits = f.grep(r"verify_signature", glob="firmware/**/*.c", max_hits=5)
    console.print(f"\n  grep 'verify_signature' in firmware/*.c: {len(hits)} hits")
    for h in hits[:5]:
        console.print(f"    {h['path']}:{h['line']}  {h['match'][:70]}")


@app.command()
def draft(
    device: str = typer.Option(..., "--device", help="Device to draft SRA for."),
    profile: str = typer.Option("hybrid", "--profile", help="free | hybrid | openai (SRS-CLI-0016)."),
    category: str | None = typer.Option(None, "--category", help="Filter threats to one category (e.g. OTA)."),
    threat: str | None = typer.Option(None, "--threat", help="Draft a single threat id."),
    limit: int | None = typer.Option(None, "--limit", help="Cap total threats processed."),
) -> None:
    """Run the LangGraph pipeline over each threat and write output/<device>_sra_draft.{md,json}."""
    from framework.agents.runner import run_draft
    if profile not in {"free", "hybrid", "openai"}:
        console.print(f"[red]--profile must be one of free|hybrid|openai (got {profile!r})[/]")
        raise typer.Exit(code=2)
    run_draft(device=device, profile=profile, category=category, threat=threat, limit=limit)


@app.command()
def review() -> None:
    """Launch the Streamlit review UI. Wired up in Step 12."""
    console.print("[yellow]review not yet implemented (Step 12)[/]")


if __name__ == "__main__":
    app()
