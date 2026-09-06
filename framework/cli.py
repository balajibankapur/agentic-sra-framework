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
def index() -> None:
    """Build vector + graph indices from input/. Wired up in Steps 2-4."""
    console.print("[yellow]index not yet implemented (Steps 2-4)[/]")


@app.command()
def draft(
    device: str = typer.Option(..., "--device", help="Device to draft SRA for."),
) -> None:
    """Run the agents to produce output/<device>_sra_draft.md. Wired up in Steps 6-11."""
    console.print(f"[yellow]draft not yet implemented — will produce output/{device}_sra_draft.md[/]")


@app.command()
def review() -> None:
    """Launch the Streamlit review UI. Wired up in Step 12."""
    console.print("[yellow]review not yet implemented (Step 12)[/]")


if __name__ == "__main__":
    app()
