"""Top-level CLI. Real subcommands land in later steps."""

from __future__ import annotations

import typer
from rich.console import Console

app = typer.Typer(
    name="sra",
    help="Agentic SRA Framework — draft an FDA cybersecurity SRA for a connected medical device.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def init(
    repo: str = typer.Option(..., "--repo", help="GitHub URL of the legacy corpus repo."),
    device: str = typer.Option(..., "--device", help="Short device name, e.g. pmx100."),
) -> None:
    """Clone the legacy corpus into input/<device>/. Wired up in Step 1."""
    console.print(f"[yellow]init not yet implemented — will clone {repo} into input/{device}/[/]")


@app.command()
def index() -> None:
    """Build vector + graph indices from input/. Wired up in Steps 2-4."""
    console.print("[yellow]index not yet implemented[/]")


@app.command()
def draft(
    device: str = typer.Option(..., "--device", help="Device to draft SRA for."),
) -> None:
    """Run the agents to produce output/<device>_sra_draft.md. Wired up in Steps 6-11."""
    console.print(f"[yellow]draft not yet implemented — will produce output/{device}_sra_draft.md[/]")


@app.command()
def review() -> None:
    """Launch the Streamlit review UI. Wired up in Step 12."""
    console.print("[yellow]review not yet implemented[/]")


if __name__ == "__main__":
    app()
