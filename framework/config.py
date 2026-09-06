"""Framework-wide paths + defaults. Reads .env if present."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Load .env from the framework repo root (parent of this file's parent).
REPO_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(REPO_ROOT / ".env")


def _dir_from_env(env_var: str, default_rel: str) -> Path:
    return Path(os.getenv(env_var, str(REPO_ROOT / default_rel))).resolve()


INPUT_DIR = _dir_from_env("SRA_INPUT_DIR", "input")
STORES_DIR = _dir_from_env("SRA_STORES_DIR", "stores")
OUTPUT_DIR = _dir_from_env("SRA_OUTPUT_DIR", "output")

CHROMA_DIR = _dir_from_env("SRA_CHROMA_DIR", "stores/chroma")
KUZU_DIR = _dir_from_env("SRA_KUZU_DIR", "stores/kuzu")
EXTRACTS_DIR = _dir_from_env("SRA_EXTRACTS_DIR", "stores/extracts")


def device_input_dir(device: str) -> Path:
    """Where the cloned legacy corpus lives for a given device."""
    return INPUT_DIR / device


def device_manifest_path(device: str) -> Path:
    return device_input_dir(device) / ".manifest.json"


def ensure_dirs() -> None:
    """Make sure the top-level runtime dirs exist. Safe to call repeatedly."""
    for d in (INPUT_DIR, STORES_DIR, OUTPUT_DIR):
        d.mkdir(parents=True, exist_ok=True)
