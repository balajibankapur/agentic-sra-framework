"""Clone the legacy corpus repo into input/<device>/ and record its provenance."""

from __future__ import annotations

import json
import shutil
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from git import Repo
from rich.console import Console

from framework.config import device_input_dir, device_manifest_path, ensure_dirs

console = Console()


@dataclass
class Manifest:
    device: str
    repo_url: str
    commit_sha: str
    commit_subject: str
    cloned_at_utc: str
    file_count: int
    total_bytes: int

    def write(self, path: Path) -> None:
        path.write_text(json.dumps(asdict(self), indent=2))


def _walk_size(root: Path) -> tuple[int, int]:
    """Return (file_count, total_bytes) excluding the .git dir."""
    count = 0
    size = 0
    for p in root.rglob("*"):
        if ".git" in p.parts:
            continue
        if p.is_file():
            count += 1
            size += p.stat().st_size
    return count, size


def clone_corpus(repo_url: str, device: str, force: bool = False) -> Manifest:
    """Git-clone repo_url into input/<device>/. Writes .manifest.json.

    Returns the Manifest that was written.
    """
    ensure_dirs()
    target = device_input_dir(device)

    if target.exists() and any(target.iterdir()):
        if not force:
            raise FileExistsError(
                f"{target} is not empty. Re-run with --force to replace, "
                f"or pick a different --device name."
            )
        console.print(f"[yellow]--force set: removing existing {target}[/]")
        shutil.rmtree(target)

    target.parent.mkdir(parents=True, exist_ok=True)
    console.print(f"Cloning [cyan]{repo_url}[/] → [green]{target}[/] …")
    repo = Repo.clone_from(repo_url, str(target))
    head = repo.head.commit

    file_count, total_bytes = _walk_size(target)
    manifest = Manifest(
        device=device,
        repo_url=repo_url,
        commit_sha=head.hexsha,
        commit_subject=head.message.strip().splitlines()[0][:120],
        cloned_at_utc=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        file_count=file_count,
        total_bytes=total_bytes,
    )
    manifest.write(device_manifest_path(device))
    return manifest


def read_manifest(device: str) -> Manifest | None:
    path = device_manifest_path(device)
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    return Manifest(**data)
