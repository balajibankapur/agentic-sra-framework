"""Top-level CLI. Real subcommands land in later steps."""

from __future__ import annotations

from pathlib import Path

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
    """Show the full pipeline state: input, indices, draft, review, final."""
    from framework.config import CHROMA_DIR, KUZU_DIR, OUTPUT_DIR, device_input_dir
    import json as _json

    table = Table(title=f"{device} status", show_header=True)
    table.add_column("Stage")
    table.add_column("Detail")
    table.add_column("Status", justify="right")

    # -- Input corpus --------------------------------------------------------
    m = read_manifest(device)
    if m is None:
        table.add_row("input", "not cloned", "[red]missing[/]")
    else:
        table.add_row(
            "input",
            f"{m.commit_sha[:12]} · {m.file_count} files · {_human_bytes(m.total_bytes)}",
            "[green]ok[/]",
        )

    # -- Vector store --------------------------------------------------------
    try:
        import chromadb
        from chromadb.config import Settings as _CS
        client = chromadb.PersistentClient(path=str(CHROMA_DIR),
                                           settings=_CS(anonymized_telemetry=False))
        cols = client.list_collections()
        by_name = {c.name: client.get_collection(c.name).count() for c in cols}
        docs = by_name.get("device_docs", 0)
        code = by_name.get("device_code", 0)
        reg = by_name.get("regulatory", 0)
        table.add_row("vector store (Chroma)",
                      f"docs={docs}  code={code}  regulatory={reg}",
                      "[green]ok[/]" if (docs and code) else "[yellow]incomplete[/]")
    except Exception as e:
        table.add_row("vector store (Chroma)", f"error: {e}", "[red]missing[/]")

    # -- Kuzu graph ----------------------------------------------------------
    kuzu_path = KUZU_DIR / f"{device}.kuzu"
    if not kuzu_path.exists():
        table.add_row("graph store (Kuzu)", "not built", "[red]missing[/]")
    else:
        try:
            import kuzu
            conn = kuzu.Connection(kuzu.Database(str(kuzu_path)))
            res = conn.execute("MATCH (n) RETURN COUNT(*) AS n;")
            total_nodes = res.get_next()[0]
            table.add_row("graph store (Kuzu)",
                          f"{total_nodes} nodes across 11 tables",
                          "[green]ok[/]" if total_nodes else "[yellow]empty[/]")
        except Exception as e:
            table.add_row("graph store (Kuzu)", f"error: {e}", "[red]error[/]")

    # -- Draft ---------------------------------------------------------------
    draft_json = OUTPUT_DIR / f"{device}_sra_draft.json"
    if draft_json.exists():
        try:
            draft = _json.loads(draft_json.read_text())
            errs = sum(1 for e in draft if e.get("parse_error"))
            table.add_row("draft", f"{len(draft)} entries ({errs} parse_error)",
                          "[green]ok[/]" if len(draft) else "[yellow]empty[/]")
        except Exception as e:
            table.add_row("draft", f"error: {e}", "[red]error[/]")
    else:
        table.add_row("draft", "not drafted yet", "[dim]—[/]")

    # -- Prompts log ---------------------------------------------------------
    plog = OUTPUT_DIR / f"{device}_prompts.jsonl"
    if plog.exists():
        n = sum(1 for _ in plog.open())
        table.add_row("prompts log", f"{n} LLM turns", "[green]ok[/]")
    else:
        table.add_row("prompts log", "—", "[dim]—[/]")

    # -- Review state --------------------------------------------------------
    rev = OUTPUT_DIR / f"{device}_review_state.json"
    if rev.exists():
        try:
            state = _json.loads(rev.read_text())
            decisions = state.get("decisions", {}) or {}
            from collections import Counter as _C
            c = _C(d.get("action", "?") for d in decisions.values())
            summary = f"{len(decisions)} decisions ({dict(c)})  reviewer='{state.get('reviewer_name','')}'"
            table.add_row("review state", summary, "[green]ok[/]")
        except Exception as e:
            table.add_row("review state", f"error: {e}", "[red]error[/]")
    else:
        table.add_row("review state", "no decisions yet", "[dim]—[/]")

    # -- Final artifacts -----------------------------------------------------
    finals = [f"{device}_sra_final.md", f"{device}_sra_final.pdf",
              f"{device}_sra_final.docx", f"{device}_sra_final.json",
              f"{device}_provenance.json"]
    present = [f for f in finals if (OUTPUT_DIR / f).exists()]
    if present:
        total = sum((OUTPUT_DIR / f).stat().st_size for f in present)
        table.add_row("final artifacts", f"{len(present)}/{len(finals)} files · {_human_bytes(total)}",
                      "[green]ok[/]" if len(present) == len(finals) else "[yellow]partial[/]")
    else:
        table.add_row("final artifacts", "not exported yet", "[dim]—[/]")

    console.print(table)


@app.command()
def reset(
    device: str = typer.Option(..., "--device", help="Device to reset."),
    draft: bool = typer.Option(True, "--draft/--no-draft",
                               help="Wipe draft + prompts + review_state + final artifacts."),
    indices: bool = typer.Option(False, "--indices",
                                 help="Also wipe Chroma vector store, Kuzu graph, JSON extracts."),
    corpus: bool = typer.Option(False, "--corpus",
                                help="Also wipe input/<device>/ (requires re-running `sra init`)."),
    yes: bool = typer.Option(False, "-y", "--yes",
                             help="Skip the confirmation prompt."),
) -> None:
    """Clean slate for a new run — wipe stale draft / review / index / corpus state."""
    from framework.config import CHROMA_DIR, EXTRACTS_DIR, KUZU_DIR, OUTPUT_DIR, device_input_dir
    import shutil

    to_delete: list[Path] = []
    if draft:
        for name in (f"{device}_sra_draft.md", f"{device}_sra_draft.json",
                     f"{device}_prompts.jsonl", f"{device}_review_state.json",
                     f"{device}_sra_final.md", f"{device}_sra_final.pdf",
                     f"{device}_sra_final.docx", f"{device}_sra_final.json",
                     f"{device}_provenance.json"):
            p = OUTPUT_DIR / name
            if p.exists():
                to_delete.append(p)
    if indices:
        kuzu_p = KUZU_DIR / f"{device}.kuzu"
        if kuzu_p.exists():
            to_delete.append(kuzu_p)
        wal_p = KUZU_DIR / f"{device}.kuzu.wal"
        if wal_p.exists():
            to_delete.append(wal_p)
        ex = EXTRACTS_DIR / device
        if ex.exists():
            to_delete.append(ex)
        # Chroma stores are shared across devices; only wipe if user really wants
        if CHROMA_DIR.exists():
            to_delete.append(CHROMA_DIR)
    if corpus:
        cin = device_input_dir(device)
        if cin.exists():
            to_delete.append(cin)

    if not to_delete:
        console.print(f"[yellow]Nothing to reset for '{device}'.[/]")
        raise typer.Exit(code=0)

    console.print(f"[bold]sra reset[/] · [cyan]{device}[/]  will delete:")
    for p in to_delete:
        kind = "dir" if p.is_dir() else "file"
        console.print(f"  {kind:4s}  [red]{p}[/]")
    if not yes:
        confirm = typer.confirm("\nProceed?", default=False)
        if not confirm:
            console.print("[yellow]Aborted.[/]")
            raise typer.Exit(code=1)

    for p in to_delete:
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
        else:
            try:
                p.unlink()
            except OSError:
                pass
    console.print(f"[green]✓[/] Deleted {len(to_delete)} items.")
    console.print(f"\nRebuild:")
    if corpus:
        console.print(f"  sra init --repo <URL> --device {device}")
    if indices or corpus:
        console.print(f"  sra index --device {device}")
    if draft or indices or corpus:
        console.print(f"  sra draft --device {device}")


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
def eval(
    device: str = typer.Option(..., "--device", help="Device to evaluate."),
) -> None:
    """Score the current SRA draft against the seeded VULN ground truth."""
    from framework.eval.vuln_recall import evaluate, print_report, write_report_json
    from framework.config import OUTPUT_DIR
    report = evaluate(device)
    print_report(report)
    out = OUTPUT_DIR / f"{device}_eval.json"
    write_report_json(report, out)
    console.print(f"\nWritten: [green]{out}[/]  ({out.stat().st_size:,} bytes)")


@app.command()
def export(
    device: str = typer.Option(..., "--device", help="Device to export SRA for."),
    profile: str = typer.Option("hybrid", "--profile",
                                help="Profile the draft was produced under (for provenance)."),
) -> None:
    """Assemble final SRA artifacts: MD + PDF + DOCX + JSON + provenance."""
    from framework.sra.export import run_export
    run_export(device=device, profile=profile)


@app.command()
def review(
    device: str = typer.Option(..., "--device", help="Device to review."),
    port: int = typer.Option(8501, "--port", help="Streamlit port (default 8501)."),
) -> None:
    """Launch the Streamlit review UI on http://localhost:<port>."""
    import os
    import subprocess
    import sys
    env = os.environ.copy()
    env["SRA_DEVICE"] = device
    app_path = Path(__file__).parent.parent / "review_ui" / "app.py"
    console.print(f"Launching review UI for [cyan]{device}[/] on "
                  f"[green]http://localhost:{port}[/] …")
    console.print("[dim](one reviewer at a time; press Ctrl+C to stop)[/]\n")
    subprocess.run(
        [sys.executable, "-m", "streamlit", "run", str(app_path),
         "--server.port", str(port),
         "--server.headless", "false",
         "--browser.gatherUsageStats", "false"],
        env=env,
    )


if __name__ == "__main__":
    app()
