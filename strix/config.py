"""Watchdog configuration — paths, thresholds, model settings."""

from pathlib import Path

# --- Paths ---
HOME = Path.home()
WATCHDOG_DIR = HOME / ".local" / "share" / "watchdog"
DB_PATH = WATCHDOG_DIR / "process_events.db"
LOG_PATH = HOME / ".local" / "log" / "watchdog" / "watchdog.log"
ESCALATION_LOG = WATCHDOG_DIR / "escalations.jsonl"

# --- osquery event source ---
# User-readable copy maintained by LaunchDaemon (see launch/LaunchDaemons/)
# Falls back to raw osquery log (requires root)
OSQUERY_RESULTS_LOG = Path("/var/run/watchdog/results.log")

# --- Ollama ---
OLLAMA_MODEL = "watchdog"
OLLAMA_URL = "http://localhost:11434"

# --- Thresholds ---
SKETCHY_THRESHOLD = 0.7

# Poll interval: how often to tail the osquery results log (seconds)
POLL_INTERVAL_SECONDS = 15

# How many lines to read per poll cycle (backpressure limit)
MAX_LINES_PER_POLL = 500

# --- Claude escalation ---
CLAUDE_BIN = HOME / ".local" / "bin" / "claude"
