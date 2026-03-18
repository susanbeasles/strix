"""Strix configuration — paths, thresholds, model settings."""

import os
from pathlib import Path

# --- Paths ---
HOME = Path.home()
STRIX_DIR = Path(os.environ.get("STRIX_DIR", str(HOME / ".local" / "share" / "strix")))
DB_PATH = STRIX_DIR / "process_events.db"
LOG_PATH = Path(os.environ.get("STRIX_LOG", str(HOME / ".local" / "log" / "strix" / "strix.log")))
ESCALATION_LOG = STRIX_DIR / "escalations.jsonl"

# --- osquery event source ---
OSQUERY_RESULTS_LOG = Path(os.environ.get(
    "STRIX_OSQUERY_LOG", "/var/run/strix/results.log"
))

# --- Ollama ---
OLLAMA_MODEL = os.environ.get("STRIX_MODEL", "watchdog")
OLLAMA_URL = os.environ.get("STRIX_OLLAMA_URL", "http://localhost:11434")

# --- Thresholds ---
SKETCHY_THRESHOLD = float(os.environ.get("STRIX_SKETCHY_THRESHOLD", "0.7"))

# Poll interval: how often to tail the osquery results log (seconds)
POLL_INTERVAL_SECONDS = int(os.environ.get("STRIX_POLL_INTERVAL", "15"))

# How many lines to read per poll cycle (backpressure limit)
MAX_LINES_PER_POLL = int(os.environ.get("STRIX_MAX_LINES", "500"))
