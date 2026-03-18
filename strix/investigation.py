"""Investigation memory — persistent storage for long-running escalation analyses.

Each investigation gets its own directory with:
- notes.md     — running investigation notes (model writes to this)
- evidence/    — saved tool results and artifacts
- ruling.json  — final ruling when complete
- meta.json    — investigation metadata (process, timestamps, tool budget)

The model can read/write its own investigation files, allowing it to
persist findings across context compaction. Each new investigation starts
with a clean context — previous investigation files are archived, not loaded.
"""

import json
import time
import hashlib
import shutil
import logging
from pathlib import Path
from config import STRIX_DIR

log = logging.getLogger("strix.investigation")

INVESTIGATIONS_DIR = STRIX_DIR / "investigations"


def start_investigation(event: dict, classification: dict) -> dict:
    """Create a new investigation directory. Returns investigation context.

    Each investigation is identified by a short hash of (path, pid, timestamp).
    Previous investigations are NOT loaded — clean context every time.
    """
    # Generate investigation ID
    key = f"{event.get('path', '')}-{event.get('pid', '')}-{time.time()}"
    inv_id = hashlib.sha256(key.encode()).hexdigest()[:12]

    inv_dir = INVESTIGATIONS_DIR / inv_id
    inv_dir.mkdir(parents=True, exist_ok=True)
    (inv_dir / "evidence").mkdir(exist_ok=True)

    meta = {
        "id": inv_id,
        "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "process": event.get("process"),
        "path": event.get("path"),
        "pid": event.get("pid"),
        "initial_risk": classification.get("risk_score"),
        "initial_verdict": classification.get("verdict"),
        "status": "active",
        "tool_calls": 0,
        "rounds": 0,
    }

    (inv_dir / "meta.json").write_text(json.dumps(meta, indent=2))

    # Initialize empty notes
    (inv_dir / "notes.md").write_text(
        f"# Investigation {inv_id}\n"
        f"**Process**: {event.get('process')} ({event.get('path')})\n"
        f"**PID**: {event.get('pid')} | **Started**: {meta['started']}\n"
        f"**Initial risk**: {classification.get('risk_score', '?')}\n\n"
        f"---\n\n"
    )

    log.info("Investigation %s started for %s (PID %s)",
             inv_id, event.get("process"), event.get("pid"))

    return {"id": inv_id, "dir": str(inv_dir)}


def write_notes(inv_id: str, content: str) -> str:
    """Append to investigation notes. Model uses this to persist findings."""
    inv_dir = INVESTIGATIONS_DIR / inv_id
    if not inv_dir.exists():
        return f"ERROR: investigation {inv_id} not found"

    notes_path = inv_dir / "notes.md"
    with open(notes_path, "a") as f:
        f.write(f"\n{content}\n")

    return f"Notes updated ({len(content)} chars written)"


def read_notes(inv_id: str) -> str:
    """Read investigation notes. Model uses this to recall findings after context compaction."""
    inv_dir = INVESTIGATIONS_DIR / inv_id
    notes_path = inv_dir / "notes.md"
    if not notes_path.exists():
        return f"ERROR: no notes for investigation {inv_id}"
    return notes_path.read_text()


def save_evidence(inv_id: str, label: str, content: str) -> str:
    """Save a tool result or artifact as evidence."""
    inv_dir = INVESTIGATIONS_DIR / inv_id / "evidence"
    if not inv_dir.exists():
        return f"ERROR: investigation {inv_id} not found"

    # Sanitize label for filename
    safe_label = "".join(c if c.isalnum() or c in "-_" else "_" for c in label)
    evidence_path = inv_dir / f"{safe_label}.txt"
    evidence_path.write_text(content)

    return f"Evidence saved: {safe_label} ({len(content)} chars)"


def list_evidence(inv_id: str) -> str:
    """List all saved evidence files for an investigation."""
    inv_dir = INVESTIGATIONS_DIR / inv_id / "evidence"
    if not inv_dir.exists():
        return f"ERROR: investigation {inv_id} not found"

    files = sorted(inv_dir.iterdir())
    if not files:
        return "No evidence saved yet"

    return "\n".join(f"- {f.name} ({f.stat().st_size} bytes)" for f in files)


def read_evidence(inv_id: str, label: str) -> str:
    """Read a specific evidence file."""
    safe_label = "".join(c if c.isalnum() or c in "-_" else "_" for c in label)
    evidence_path = INVESTIGATIONS_DIR / inv_id / "evidence" / f"{safe_label}.txt"
    if not evidence_path.exists():
        return f"ERROR: evidence '{label}' not found"
    return evidence_path.read_text()


def close_investigation(inv_id: str, ruling: dict) -> str:
    """Finalize an investigation with a ruling."""
    inv_dir = INVESTIGATIONS_DIR / inv_id
    if not inv_dir.exists():
        return f"ERROR: investigation {inv_id} not found"

    # Save ruling
    ruling["closed"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    (inv_dir / "ruling.json").write_text(json.dumps(ruling, indent=2))

    # Update meta
    meta_path = inv_dir / "meta.json"
    meta = json.loads(meta_path.read_text())
    meta["status"] = "closed"
    meta["closed"] = ruling["closed"]
    meta["final_verdict"] = ruling.get("verdict")
    meta_path.write_text(json.dumps(meta, indent=2))

    log.info("Investigation %s closed: %s", inv_id, ruling.get("verdict"))
    return f"Investigation {inv_id} closed with ruling: {ruling.get('verdict')}"


def get_active_investigations() -> list[dict]:
    """List all active (unclosed) investigations."""
    if not INVESTIGATIONS_DIR.exists():
        return []

    active = []
    for inv_dir in sorted(INVESTIGATIONS_DIR.iterdir()):
        meta_path = inv_dir / "meta.json"
        if not meta_path.exists():
            continue
        meta = json.loads(meta_path.read_text())
        if meta.get("status") == "active":
            active.append(meta)

    return active


def get_investigation_summary(inv_id: str) -> str:
    """Get a summary of an investigation for re-loading after context compaction."""
    inv_dir = INVESTIGATIONS_DIR / inv_id
    if not inv_dir.exists():
        return f"ERROR: investigation {inv_id} not found"

    meta = json.loads((inv_dir / "meta.json").read_text())
    notes = (inv_dir / "notes.md").read_text() if (inv_dir / "notes.md").exists() else ""
    evidence_files = list((inv_dir / "evidence").iterdir()) if (inv_dir / "evidence").exists() else []

    return json.dumps({
        "meta": meta,
        "notes_preview": notes[:2000] + ("..." if len(notes) > 2000 else ""),
        "evidence_files": [f.name for f in evidence_files],
    }, indent=2)
