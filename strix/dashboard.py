"""Watchdog live pipeline dashboard.

Shows events flowing through the pipeline in real time:
  classify queue → 4B classifier → escalation queue → 30B investigators
                                         ↑
                    scrubber queue ← ─ ─ ┘
                         ↑
                    log monitor (Scout)

Usage:
    python -m watchdog dashboard     (or: python dashboard.py)

Reads from the daemon's log file and watchdog state directory.
Refreshes every 2 seconds.
"""

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from config import LOG_PATH, WATCHDOG_DIR, ESCALATION_LOG


# ANSI escape codes
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
WHITE = "\033[97m"
RESET = "\033[0m"
CLEAR = "\033[2J\033[H"

# Box drawing
H = "─"
V = "│"
TL = "┌"
TR = "┐"
BL = "└"
BR = "┘"
T = "┬"
B = "┴"
ARROW_R = "→"
ARROW_D = "↓"


def box(title: str, lines: list[str], width: int = 50, color: str = WHITE) -> list[str]:
    """Draw a box with a title and content lines."""
    out = []
    title_str = f" {title} "
    pad = width - len(title_str) - 2
    out.append(f"{color}{TL}{H}{title_str}{H * max(0, pad)}{TR}{RESET}")
    for line in lines:
        text = line[:width - 4]
        padding = " " * max(0, width - len(text) - 4)
        out.append(f"{color}{V}{RESET} {text}{padding} {color}{V}{RESET}")
    if not lines:
        out.append(f"{color}{V}{RESET}{' ' * (width - 2)}{color}{V}{RESET}")
    out.append(f"{color}{BL}{H * (width - 2)}{BR}{RESET}")
    return out


def read_tail(path: Path, n: int = 20) -> list[str]:
    """Read the last N lines of a file."""
    if not path.exists():
        return []
    try:
        with open(path) as f:
            lines = f.readlines()
            return [l.rstrip() for l in lines[-n:]]
    except (OSError, PermissionError):
        return []


def parse_log_stats(lines: list[str]) -> dict:
    """Extract stats from recent log lines."""
    stats = {
        "last_ingest": "",
        "classify_q": "?",
        "cache_size": "?",
        "escalate_q": "?",
        "escalate_high": "?",
        "recent_verdicts": [],
        "recent_escalations": [],
        "recent_alerts": [],
        "chains": [],
        "anomalies": [],
        "log_monitor": [],
    }

    for line in reversed(lines):
        # Ingestion line
        if "Ingested" in line and "classify_q=" in line:
            if not stats["last_ingest"]:
                stats["last_ingest"] = line.split("]")[-1].strip() if "]" in line else line
                # Parse queue depths
                for part in line.split("|"):
                    part = part.strip()
                    if "classify_q=" in part:
                        for kv in part.split():
                            if kv.startswith("classify_q="):
                                stats["classify_q"] = kv.split("=")[1]
                            elif kv.startswith("cache="):
                                stats["cache_size"] = kv.split("=")[1]
                    if "escalate_q=" in part:
                        for kv in part.split():
                            if kv.startswith("escalate_q="):
                                stats["escalate_q"] = kv.split("=")[1]
                            elif kv.startswith("(HIGH="):
                                stats["escalate_high"] = kv.strip("()").split("=")[1]

        # Verdict lines
        if "verdict=" in line and "PID=" in line and len(stats["recent_verdicts"]) < 5:
            ts = line[:19] if len(line) > 19 else ""
            # Extract process name and verdict
            parts = line.split("|")
            proc = parts[0].split("]")[-1].strip() if "]" in parts[0] else ""
            verdict_part = parts[1].strip() if len(parts) > 1 else ""
            stats["recent_verdicts"].append(f"{ts}  {proc[:30]}  {verdict_part[:40]}")

        # 30B rulings
        if "30b ruling:" in line and len(stats["recent_escalations"]) < 5:
            ts = line[:19]
            ruling = line.split("30b ruling:")[-1].strip()
            stats["recent_escalations"].append(f"{ts}  {ruling[:50]}")

        # Chain alerts
        if "CHAIN:" in line and len(stats["chains"]) < 3:
            ts = line[:19]
            chain = line.split("CHAIN:")[-1].strip()
            stats["chains"].append(f"{RED}{ts}  {chain[:45]}{RESET}")

        # Anomaly alerts
        if "ANOMALY:" in line and len(stats["anomalies"]) < 3:
            ts = line[:19]
            anom = line.split("ANOMALY:")[-1].strip()
            stats["anomalies"].append(f"{YELLOW}{ts}  {anom[:45]}{RESET}")

        # Log monitor
        if "log-monitor" in line and "4B flagged" in line and len(stats["log_monitor"]) < 3:
            ts = line[:19]
            detail = line.split("4B flagged:")[-1].strip()
            stats["log_monitor"].append(f"{ts}  {detail[:45]}")

    return stats


def parse_escalation_log() -> list[str]:
    """Read recent escalation entries."""
    lines = read_tail(ESCALATION_LOG, 5)
    entries = []
    for line in reversed(lines):
        try:
            entry = json.loads(line)
            ts = entry.get("timestamp", "?")[:19]
            proc = entry.get("process", "?")
            status = entry.get("status", "?")
            risk = entry.get("risk_score", "?")

            color = RED if "alert" in str(status) else YELLOW if "suspicious" in str(status) else GREEN
            entries.append(f"{ts}  {color}{proc:<20}{RESET} {status} (risk={risk})")
        except json.JSONDecodeError:
            continue
    return entries


def parse_investigation_state() -> list[str]:
    """Check for active investigations."""
    inv_dir = WATCHDOG_DIR / "investigations"
    if not inv_dir.exists():
        return [f"{DIM}No investigations directory{RESET}"]

    active = []
    for d in sorted(inv_dir.iterdir(), reverse=True):
        meta_path = d / "meta.json"
        if not meta_path.exists():
            continue
        try:
            meta = json.loads(meta_path.read_text())
            if meta.get("status") == "active":
                proc = meta.get("process", "?")
                started = meta.get("started", "?")[:19]
                active.append(f"{CYAN}{proc:<25}{RESET} since {started}")
        except (json.JSONDecodeError, OSError):
            continue

        if len(active) >= 3:
            break

    return active if active else [f"{DIM}(idle){RESET}"]


def render(stats: dict, escalations: list[str], investigations: list[str]):
    """Render the full dashboard."""
    w = 56

    print(CLEAR, end="")
    print(f"{BOLD}{CYAN}  WATCHDOG PIPELINE DASHBOARD{RESET}  {DIM}{time.strftime('%H:%M:%S')}{RESET}")
    print()

    # Row 1: Pipeline flow
    classify_lines = [
        f"Queue depth:  {stats['classify_q']}",
        f"Cache size:   {stats['cache_size']}",
    ]
    for v in stats["recent_verdicts"][:3]:
        classify_lines.append(f"{DIM}{v}{RESET}")

    escalate_lines = [
        f"Queue depth:  {stats['escalate_q']}  {RED}HIGH: {stats['escalate_high']}{RESET}",
    ]
    for e in stats["recent_escalations"][:3]:
        escalate_lines.append(f"{DIM}{e}{RESET}")

    # Draw the pipeline boxes
    b1 = box("4B CLASSIFIER", classify_lines, w, BLUE)
    b2 = box("ESCALATION QUEUE", escalate_lines, w, YELLOW)

    print(f"  {BOLD}osquery{RESET} {ARROW_R} ", end="")
    for line in b1:
        print(f"  {line}")
    print(f"  {'':>10}{ARROW_D}")
    for line in b2:
        print(f"  {line}")

    print()

    # Row 2: Investigators + Scrubber side by side
    inv_box = box("30B INVESTIGATORS", investigations, w, MAGENTA)
    scout_lines = stats["log_monitor"][:3] if stats["log_monitor"] else [f"{DIM}(quiet){RESET}"]
    scout_box = box("LOG SCOUT (4B)", scout_lines, w, GREEN)

    for i in range(max(len(inv_box), len(scout_box))):
        left = inv_box[i] if i < len(inv_box) else " " * w
        right = scout_box[i] if i < len(scout_box) else ""
        print(f"  {left}  {right}")

    print()

    # Row 3: Alerts
    alert_lines = stats["chains"] + stats["anomalies"]
    if not alert_lines:
        alert_lines = [f"{GREEN}No active chains or anomalies{RESET}"]
    alert_box = box("ALERTS", alert_lines, w * 2 + 2, RED)
    for line in alert_box:
        print(f"  {line}")

    print()

    # Row 4: Recent escalation log
    if escalations:
        esc_box = box("ESCALATION LOG (last 5)", escalations, w * 2 + 2, YELLOW)
        for line in esc_box:
            print(f"  {line}")
    else:
        print(f"  {DIM}No escalation log entries yet{RESET}")

    # Footer
    print()
    print(f"  {DIM}Last ingest: {stats['last_ingest'][:70]}{RESET}")
    print(f"  {DIM}Ctrl+C to exit{RESET}")


def main():
    print(f"{BOLD}Starting watchdog dashboard...{RESET}")
    print(f"Reading from: {LOG_PATH}")
    print()

    try:
        while True:
            log_lines = read_tail(LOG_PATH, 200)
            stats = parse_log_stats(log_lines)
            escalations = parse_escalation_log()
            investigations = parse_investigation_state()
            render(stats, escalations, investigations)
            time.sleep(2)
    except KeyboardInterrupt:
        print(f"\n{DIM}Dashboard stopped.{RESET}")


if __name__ == "__main__":
    main()
