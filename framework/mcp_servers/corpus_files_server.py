"""MCP server — corpus files (read-only, rooted at input/<device>/).

Wraps the cloned corpus filesystem as tools:
  - read(path)            file content, capped at 200 KB
  - list(directory)       directory listing
  - grep(pattern, glob)   pattern search across files

All paths are resolved relative to input/<device>/ and refuse any resolved
path that escapes that root — no `..` traversal, no absolute paths outside
the input tree.
"""

from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from framework.config import device_input_dir

MAX_READ_BYTES = 200_000
MAX_GREP_HITS = 200


def _get_root() -> Path:
    device = os.getenv("SRA_DEVICE", "pmx100")
    root = device_input_dir(device)
    if not root.exists():
        raise FileNotFoundError(
            f"input/{device}/ not found. Run: sra init --repo <URL> --device {device}"
        )
    return root.resolve()


def _resolve_safe(rel: str) -> Path:
    """Resolve rel under the device root, refuse traversal outside."""
    root = _get_root()
    p = (root / rel).resolve()
    try:
        p.relative_to(root)
    except ValueError:
        raise ValueError(f"Path escapes device root: {rel}")
    return p


mcp = MCPServer(
    name="corpus-files",
    instructions=(
        "Read-only filesystem access to the cloned device corpus at "
        "input/<device>/. Use this when you need raw file content or grep "
        "for symbols the vector search would miss (short identifiers, "
        "function names, exact regex matches). Paths are always relative "
        "to the device root; absolute or `..` paths are refused."
    ),
)


@mcp.tool()
def read(path: str) -> dict:
    """Read a file from the device corpus.

    Args:
        path: relative to input/<device>/, e.g. "firmware/app_mcu/ota/install_handler.c"
              or "corpus/pmx100/SRS.md"

    Returns:
        {path, bytes, truncated, content}. Content is capped at 200 KB.
    """
    p = _resolve_safe(path)
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(f"Not a file: {path}")
    data = p.read_bytes()
    total = len(data)
    truncated = total > MAX_READ_BYTES
    text = data[:MAX_READ_BYTES].decode("utf-8", errors="replace")
    return {
        "path": path,
        "bytes": total,
        "truncated": truncated,
        "content": text,
    }


@mcp.tool()
def list_dir(directory: str = "") -> list[dict]:
    """List entries under a directory (non-recursive).

    Args:
        directory: relative path; empty string = device root
    """
    p = _resolve_safe(directory)
    if not p.exists() or not p.is_dir():
        raise NotADirectoryError(f"Not a directory: {directory}")
    entries: list[dict] = []
    for child in sorted(p.iterdir()):
        try:
            rel = child.relative_to(_get_root()).as_posix()
        except ValueError:
            continue
        entries.append({
            "name": child.name,
            "path": rel,
            "type": "dir" if child.is_dir() else "file",
            "bytes": child.stat().st_size if child.is_file() else 0,
        })
    return entries


@mcp.tool()
def grep(
    pattern: str,
    glob: str = "**/*",
    max_hits: int = 100,
    case_insensitive: bool = False,
    context: int = 0,
) -> list[dict]:
    """Regex search across files matching a glob.

    Args:
        pattern: Python regex
        glob: filename pattern, e.g. "**/*.c" or "corpus/**/*.md"
        max_hits: cap on hits returned (default 100, max 200)
        case_insensitive: pass True for a case-insensitive match
        context: extra lines around each match (0-3)

    Returns:
        List of {path, line, match, before, after} entries.
    """
    max_hits = max(1, min(max_hits, MAX_GREP_HITS))
    context = max(0, min(context, 3))
    root = _get_root()
    flags = re.IGNORECASE if case_insensitive else 0
    try:
        rx = re.compile(pattern, flags)
    except re.error as e:
        raise ValueError(f"Bad regex: {e}")

    hits: list[dict] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            continue
        if not fnmatch.fnmatch(rel, glob):
            continue
        # Skip obvious binaries
        if path.suffix in {".pdf", ".png", ".jpg", ".svg", ".zip", ".bin"}:
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines):
            m = rx.search(line)
            if not m:
                continue
            before = lines[max(0, i - context): i] if context else []
            after = lines[i + 1: i + 1 + context] if context else []
            hits.append({
                "path": rel,
                "line": i + 1,
                "match": line[:400],
                "before": before,
                "after": after,
            })
            if len(hits) >= max_hits:
                return hits
    return hits


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
