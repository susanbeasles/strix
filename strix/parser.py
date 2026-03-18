"""Parse osquery results log into structured process events.

Reads /var/log/osquery/osqueryd.results.log (JSONL) and extracts
process_events entries. Tracks file position for incremental reads.
"""

import json
import logging
import os
from config import OSQUERY_RESULTS_LOG, MAX_LINES_PER_POLL

log = logging.getLogger("watchdog.parser")

# Track file position for incremental reads
_last_pos: int = 0
_last_inode: int = 0


def poll_process_events() -> list[dict]:
    """Read new process events from osquery results log.

    Tails the log from the last read position. Handles log rotation
    by detecting inode changes.
    """
    global _last_pos, _last_inode

    log_path = str(OSQUERY_RESULTS_LOG)

    if not os.path.exists(log_path):
        log.debug("osquery results log not found: %s", log_path)
        return []

    # Detect log rotation (inode changed)
    try:
        stat = os.stat(log_path)
    except OSError:
        return []

    if stat.st_ino != _last_inode:
        # New file (rotated) — start from beginning
        _last_pos = 0
        _last_inode = stat.st_ino

    # Nothing new
    if stat.st_size <= _last_pos:
        return []

    events = []
    try:
        with open(log_path, "r") as f:
            f.seek(_last_pos)
            lines_read = 0

            while lines_read < MAX_LINES_PER_POLL:
                line = f.readline()
                if not line:
                    break
                lines_read += 1

                line = line.strip()
                if not line:
                    continue

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                event = _parse_osquery_entry(entry)
                if event:
                    events.append(event)

            _last_pos = f.tell()

    except (OSError, PermissionError) as e:
        log.error("Failed to read osquery log: %s", e)
        return []

    return events


def _parse_osquery_entry(entry: dict) -> dict | None:
    """Parse a single osquery results log entry into a watchdog event.

    Only processes es_process_events entries (exec/fork/exit).
    """
    name = entry.get("name", "")

    # Only care about process events
    if "process_events" not in name:
        return None

    cols = entry.get("columns", {})
    if not cols:
        return None

    event_type = cols.get("event_type", "")
    path = cols.get("path", "")

    # Skip exit events for now — focus on exec and fork
    if event_type == "exit":
        return None

    if not path:
        return None

    pid = _int(cols.get("pid"))
    parent = _int(cols.get("parent"))
    uid = _int(cols.get("uid"))
    euid = _int(cols.get("euid"))

    # Extract process basename
    basename = path.rsplit("/", 1)[-1] if "/" in path else path

    # Build context
    return {
        "timestamp": entry.get("calendarTime", ""),
        "unix_time": _int(cols.get("time")),
        "event_type": event_type,
        "path": path,
        "process": basename,
        "pid": pid,
        "parent_pid": parent,
        "original_parent": _int(cols.get("original_parent")),
        "responsible_pid": _int(cols.get("responsible_pid")),
        "uid": uid,
        "euid": euid,
        "username": cols.get("username", ""),
        "cmdline": cols.get("cmdline", ""),
        "cwd": cols.get("cwd", ""),
        "signing_id": cols.get("signing_id", ""),
        "team_id": cols.get("team_id", ""),
        "cdhash": cols.get("cdhash", ""),
        "platform_binary": cols.get("platform_binary", "") == "1",
        "codesigning_flags": cols.get("codesigning_flags", ""),
        "exit_code": _int(cols.get("exit_code")),
    }


def _int(val) -> int | None:
    """Safe int conversion."""
    if val is None or val == "":
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None
