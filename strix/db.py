"""SQLite storage for process events, baselines, and verdicts."""

import sqlite3
import time
from pathlib import Path
from config import DB_PATH, WATCHDOG_DIR


def _ensure_dirs():
    WATCHDOG_DIR.mkdir(parents=True, exist_ok=True)


def get_conn() -> sqlite3.Connection:
    _ensure_dirs()
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    _migrate(conn)
    return conn


def _migrate(conn: sqlite3.Connection):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS process_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            unix_time INTEGER,
            event_type TEXT,
            path TEXT NOT NULL,
            process TEXT NOT NULL,
            pid INTEGER,
            parent_pid INTEGER,
            uid INTEGER,
            euid INTEGER,
            username TEXT,
            cmdline TEXT,
            cwd TEXT,
            signing_id TEXT,
            team_id TEXT,
            platform_binary INTEGER DEFAULT 0,
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS baselines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL,
            process TEXT NOT NULL,
            signing_id TEXT,
            team_id TEXT,
            platform_binary INTEGER DEFAULT 0,
            typical_parent TEXT,
            typical_uid INTEGER,
            seen_count INTEGER DEFAULT 1,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            verdict TEXT DEFAULT 'unknown',
            UNIQUE(path, signing_id)
        );

        CREATE TABLE IF NOT EXISTS verdicts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT NOT NULL,
            process TEXT NOT NULL,
            signing_id TEXT,
            source TEXT NOT NULL,  -- 'ollama', 'claude', 'fast-cache', 'baseline'
            verdict TEXT NOT NULL,  -- 'normal', 'suspicious', 'alert'
            confidence REAL,
            risk_score REAL,
            reasoning TEXT,
            category TEXT,
            created_at REAL NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_baselines_path
            ON baselines(path, signing_id);
        CREATE INDEX IF NOT EXISTS idx_events_ts
            ON process_events(created_at);
        CREATE INDEX IF NOT EXISTS idx_verdicts_path
            ON verdicts(path, created_at);
    """)
    conn.commit()


def record_event(conn: sqlite3.Connection, event: dict):
    conn.execute("""
        INSERT INTO process_events (timestamp, unix_time, event_type, path, process,
                                     pid, parent_pid, uid, euid, username, cmdline,
                                     cwd, signing_id, team_id, platform_binary, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event.get("timestamp"),
        event.get("unix_time"),
        event.get("event_type"),
        event["path"],
        event["process"],
        event.get("pid"),
        event.get("parent_pid"),
        event.get("uid"),
        event.get("euid"),
        event.get("username"),
        event.get("cmdline"),
        event.get("cwd"),
        event.get("signing_id"),
        event.get("team_id"),
        1 if event.get("platform_binary") else 0,
        time.time(),
    ))
    conn.commit()


def update_baseline(conn: sqlite3.Connection, event: dict):
    """Update or insert a baseline entry for this binary."""
    now = time.time()
    path = event["path"]
    signing_id = event.get("signing_id", "")
    parent = event.get("process", "")

    existing = conn.execute(
        "SELECT id, typical_parent FROM baselines WHERE path = ? AND signing_id = ?",
        (path, signing_id)
    ).fetchone()

    if existing:
        conn.execute("""
            UPDATE baselines SET seen_count = seen_count + 1, last_seen = ? WHERE id = ?
        """, (now, existing["id"]))
    else:
        conn.execute("""
            INSERT INTO baselines (path, process, signing_id, team_id, platform_binary,
                                    typical_parent, typical_uid, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            path,
            event.get("process", ""),
            signing_id,
            event.get("team_id", ""),
            1 if event.get("platform_binary") else 0,
            parent,
            event.get("uid"),
            now, now,
        ))
    conn.commit()


def get_baseline_context(conn: sqlite3.Connection, path: str) -> str:
    """Get baseline context string for a binary path."""
    row = conn.execute(
        "SELECT * FROM baselines WHERE path = ? ORDER BY seen_count DESC LIMIT 1",
        (path,)
    ).fetchone()
    if not row:
        return "NEVER SEEN BEFORE — first execution of this binary"

    return (
        f"Seen {row['seen_count']}x since {time.strftime('%Y-%m-%d', time.localtime(row['first_seen']))}. "
        f"Typical parent: {row['typical_parent'] or 'unknown'}. "
        f"Typical UID: {row['typical_uid']}. "
        f"Platform binary: {'yes' if row['platform_binary'] else 'no'}. "
        f"Previous verdict: {row['verdict']}."
    )


def record_verdict(conn: sqlite3.Connection, event: dict, source: str,
                   result: dict):
    conn.execute("""
        INSERT INTO verdicts (path, process, signing_id, source, verdict,
                              confidence, risk_score, reasoning, category, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event["path"],
        event["process"],
        event.get("signing_id", ""),
        source,
        result["verdict"],
        result.get("confidence"),
        result.get("risk_score"),
        result.get("reasoning"),
        result.get("category"),
        time.time(),
    ))

    # Update baseline verdict if confidence is high enough
    if result.get("confidence", 0) >= 0.7:
        conn.execute("""
            UPDATE baselines SET verdict = ?
            WHERE path = ? AND signing_id = ?
        """, (result["verdict"], event["path"], event.get("signing_id", "")))

    conn.commit()
