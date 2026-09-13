"""Job manager — spawn / stop / status of `sra draft` from the UI.

Streamlit is a request-response loop, so long-running analyses have to
run as separate processes. This module wraps subprocess.Popen with a
tiny PID+log control file so the UI can poll for progress and stop a
run cleanly.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from framework.config import (
    CHROMA_DIR,
    EXTRACTS_DIR,
    KUZU_DIR,
    OUTPUT_DIR,
    device_input_dir,
)


def control_path(device: str) -> Path:
    return OUTPUT_DIR / f"{device}_job.json"


def log_path(device: str) -> Path:
    return OUTPUT_DIR / f"{device}_job.log"


@dataclass
class JobStatus:
    device: str
    pid: int | None = None
    alive: bool = False
    started_at_utc: str = ""
    profile: str = ""
    limit: int | None = None
    entries_done: int = 0
    llm_turns: int = 0
    cost_usd_est: float = 0.0
    last_activity_utc: str = ""
    exit_code: int | None = None

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


# ---------------------------------------------------------------------------
# Start / stop


def is_running(device: str) -> bool:
    """Cheap check: control file exists AND its PID is a live process."""
    cp = control_path(device)
    if not cp.exists():
        return False
    try:
        pid = json.loads(cp.read_text()).get("pid")
    except (json.JSONDecodeError, OSError):
        return False
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)  # signal 0 = existence check
        return True
    except (OSError, ProcessLookupError, ValueError):
        return False


def start_draft(
    device: str,
    profile: str = "hybrid",
    limit: int | None = None,
    category: str | None = None,
) -> JobStatus:
    """Spawn `sra draft` as a detached background subprocess.

    Refuses if a job is already running for this device.
    """
    if is_running(device):
        raise RuntimeError(f"A draft job is already running for '{device}'. Stop it first.")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    log_p = log_path(device)
    # Truncate old log
    log_p.write_text("")

    sra_bin = shutil.which("sra") or f"{Path(sys.executable).parent}/sra"
    cmd = [sra_bin, "draft", "--device", device, "--profile", profile]
    if limit is not None:
        cmd += ["--limit", str(int(limit))]
    if category:
        cmd += ["--category", category]

    log_fh = log_p.open("ab", buffering=0)
    # start_new_session so the child survives if the Streamlit process reloads
    proc = subprocess.Popen(
        cmd,
        stdout=log_fh,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    ctl = {
        "device": device,
        "pid": proc.pid,
        "started_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "profile": profile,
        "limit": limit,
        "category": category,
        "cmd": cmd,
    }
    control_path(device).write_text(json.dumps(ctl, indent=2))
    return status(device)


def stop_draft(device: str) -> bool:
    """Send SIGTERM to the running draft job. Returns True if a process was signalled."""
    cp = control_path(device)
    if not cp.exists():
        return False
    try:
        pid = int(json.loads(cp.read_text())["pid"])
    except Exception:
        return False
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except (OSError, ProcessLookupError):
        pass
    # Also drop the control file so status shows idle
    try:
        cp.unlink()
    except OSError:
        pass
    return True


def status(device: str) -> JobStatus:
    st = JobStatus(device=device)
    cp = control_path(device)
    if cp.exists():
        try:
            ctl = json.loads(cp.read_text())
            st.pid = int(ctl.get("pid", 0)) or None
            st.started_at_utc = ctl.get("started_at_utc", "")
            st.profile = ctl.get("profile", "")
            st.limit = ctl.get("limit")
        except Exception:
            pass
    st.alive = is_running(device)

    # Read draft + prompts for progress metrics
    draft_json = OUTPUT_DIR / f"{device}_sra_draft.json"
    if draft_json.exists():
        try:
            entries = json.loads(draft_json.read_text())
            st.entries_done = len(entries)
        except Exception:
            pass
        st.last_activity_utc = datetime.fromtimestamp(
            draft_json.stat().st_mtime, tz=timezone.utc
        ).isoformat(timespec="seconds")

    prompts = OUTPUT_DIR / f"{device}_prompts.jsonl"
    if prompts.exists():
        total_cost = 0.0
        turns = 0
        for line in prompts.open("r", encoding="utf-8", errors="ignore"):
            try:
                r = json.loads(line)
                total_cost += float(r.get("cost_usd_est", 0.0))
                turns += 1
            except Exception:
                continue
        st.llm_turns = turns
        st.cost_usd_est = round(total_cost, 5)

    # If the control file says a job started but the PID is dead, drop the file
    # so subsequent starts aren't blocked.
    if cp.exists() and not st.alive:
        try:
            cp.unlink()
        except OSError:
            pass

    return st


# ---------------------------------------------------------------------------
# Reset


def reset(
    device: str,
    include_indices: bool = False,
    include_corpus: bool = False,
) -> list[Path]:
    """Wipe draft + final + review artifacts. Optionally indices and cloned corpus.

    Refuses if a job is running for this device.
    """
    if is_running(device):
        raise RuntimeError(f"A draft job is running for '{device}'. Stop it first.")

    to_delete: list[Path] = []
    for name in (f"{device}_sra_draft.md", f"{device}_sra_draft.json",
                 f"{device}_prompts.jsonl", f"{device}_review_state.json",
                 f"{device}_sra_final.md", f"{device}_sra_final.pdf",
                 f"{device}_sra_final.docx", f"{device}_sra_final.json",
                 f"{device}_provenance.json", f"{device}_eval.json",
                 f"{device}_job.json", f"{device}_job.log"):
        p = OUTPUT_DIR / name
        if p.exists():
            to_delete.append(p)

    if include_indices:
        for p in (KUZU_DIR / f"{device}.kuzu", KUZU_DIR / f"{device}.kuzu.wal"):
            if p.exists():
                to_delete.append(p)
        ex = EXTRACTS_DIR / device
        if ex.exists():
            to_delete.append(ex)
        if CHROMA_DIR.exists():
            to_delete.append(CHROMA_DIR)

    if include_corpus:
        cin = device_input_dir(device)
        if cin.exists():
            to_delete.append(cin)

    for p in to_delete:
        try:
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
            else:
                p.unlink()
        except OSError:
            pass
    return to_delete
