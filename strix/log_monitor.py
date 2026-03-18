"""Log monitor — 4B model tails macOS unified logs for security events.

Runs as its own thread, polling `log show` for recent entries matching
security-relevant subsystems. Suspicious entries are triaged by the 4B
and submitted directly to the escalation queue as HIGH or LOW priority.

This is a separate event source from the osquery process monitor.
The 30b doesn't see raw log noise — only events the 4B flags as worth
investigating.

Subsystems watched:
  - com.apple.securityd           (keychain, code signing, cert validation)
  - com.apple.authd               (authorization, privilege escalation)
  - com.apple.opendirectoryd      (directory services, user auth)
  - com.apple.TCC                 (privacy/permissions — camera, mic, disk)
  - com.apple.alf                 (application-level firewall)
  - com.apple.xpc                 (XPC service issues, sandbox violations)
  - com.apple.launchd             (service lifecycle, unexpected launches)
  - com.apple.endpointsecurity    (ES framework events)
  - com.apple.sandbox             (sandbox violations)
"""

import json
import logging
import subprocess
import time
import threading
import urllib.request
import urllib.error
from config import OLLAMA_URL, WATCHDOG_DIR
from scrubber import scrub

log = logging.getLogger("watchdog.log_monitor")

# --- Config ---
POLL_INTERVAL = 30       # Seconds between log polls
LOOKBACK_MINUTES = 1     # How far back each poll looks (slight overlap is fine)
MAX_LOG_LINES = 100      # Cap lines per poll to protect 4B context
TRIAGE_MODEL = "watchdog" # Same 4B as classifier
TRIAGE_TIMEOUT = 20

# Subsystems and predicates to watch
# Each entry: (human label, log predicate)
_WATCH_LIST = [
    ("auth_failures",
     'subsystem == "com.apple.opendirectoryd" AND messageType == error'),
    ("tcc_access",
     'subsystem == "com.apple.TCC"'),
    ("firewall_blocks",
     'subsystem == "com.apple.alf" AND messageType == error'),
    ("sandbox_violations",
     'subsystem == "com.apple.sandbox" AND messageType == error'),
    ("privilege_escalation",
     'subsystem == "com.apple.authd" AND eventMessage CONTAINS "authentication"'),
    ("security_events",
     'subsystem == "com.apple.securityd" AND messageType == error'),
    ("xpc_anomalies",
     'subsystem == "com.apple.xpc" AND messageType == error'),
    ("launchd_events",
     'subsystem == "com.apple.launchd" AND messageType >= default'),
    ("endpoint_security",
     'subsystem == "com.apple.endpointsecurity"'),
]

# Track what we've already seen to avoid re-processing
_seen_hashes: set[str] = set()
_MAX_SEEN = 5000  # Rolling window


def start_log_monitor(eq) -> threading.Thread:
    """Start the log monitor thread. Returns the thread handle."""
    t = threading.Thread(target=_monitor_loop, args=(eq,),
                         name="log-monitor-4b", daemon=True)
    t.start()
    log.info("Log monitor started (poll=%ds, lookback=%dm, subsystems=%d)",
             POLL_INTERVAL, LOOKBACK_MINUTES, len(_WATCH_LIST))
    return t


def _monitor_loop(eq):
    """Main loop: poll system logs, triage with 4B, submit to escalation queue."""
    # Let the system settle on startup before reading logs
    time.sleep(10)

    while True:
        try:
            for label, predicate in _WATCH_LIST:
                entries = _poll_log(predicate)
                if not entries:
                    continue

                # Dedup against what we've already processed
                new_entries = _dedup(entries)
                if not new_entries:
                    continue

                log.info("[%s] %d new log entries (of %d raw)",
                         label, len(new_entries), len(entries))

                # Triage with 4B — she decides what's worth escalating
                alerts = _triage_with_4b(label, new_entries)

                for alert in alerts:
                    eq.submit(
                        alert["event"],
                        alert["classification"],
                        source=f"log-monitor-{label}",
                    )

        except Exception as e:
            log.error("Log monitor error: %s", e, exc_info=True)

        time.sleep(POLL_INTERVAL)


def _poll_log(predicate: str) -> list[str]:
    """Run `log show` with a predicate, return lines."""
    cmd = [
        "log", "show",
        "--last", f"{LOOKBACK_MINUTES}m",
        "--predicate", predicate,
        "--style", "compact",
        "--info",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0:
            return []

        lines = result.stdout.strip().split("\n")
        # First line is usually a header — skip it
        if lines and lines[0].startswith("Filtering"):
            lines = lines[1:]

        # Cap output
        return lines[:MAX_LOG_LINES]

    except (subprocess.TimeoutExpired, OSError) as e:
        log.warning("log show failed: %s", e)
        return []


def _dedup(entries: list[str]) -> list[str]:
    """Filter out entries we've already processed."""
    global _seen_hashes

    # Prune if too large
    if len(_seen_hashes) > _MAX_SEEN:
        _seen_hashes = set(list(_seen_hashes)[-(_MAX_SEEN // 2):])

    new = []
    for entry in entries:
        if not entry.strip():
            continue
        h = hash(entry)
        if h not in _seen_hashes:
            _seen_hashes.add(h)
            new.append(entry)
    return new


def _triage_with_4b(label: str, entries: list[str]) -> list[dict]:
    """Run log entries through the 4B to triage what's worth escalating.

    The 4B sees the raw log entries and decides:
    - ESCALATE (HIGH): active threat, auth breach, sandbox escape
    - ESCALATE (LOW): suspicious but not urgent
    - IGNORE: normal system noise

    Returns a list of alert dicts ready for eq.submit().
    """
    log_block = "\n".join(entries)

    prompt = f"""You are a macOS security log triage agent. You monitor system logs for threats.

LOG CATEGORY: {label}
ENTRIES ({len(entries)} lines):
{log_block}

For each entry that looks suspicious or security-relevant, output a JSON object on its own line:
{{"priority": "HIGH" or "LOW", "process": "process name or subsystem", "path": "binary path if visible, else empty", "summary": "one-line description of what happened", "category": "auth_failure|sandbox_violation|privilege_escalation|firewall_block|tcc_bypass|persistence|suspicious_launch|other"}}

Rules:
- IGNORE normal system operations (routine auth checks, expected TCC prompts, standard service lifecycle)
- HIGH: failed auth attempts from unusual sources, sandbox escapes, unexpected privilege escalation, TCC bypass attempts
- LOW: unusual but not immediately threatening (new LaunchAgent loaded, unfamiliar process hitting firewall)
- Output NOTHING for entries that are clearly normal
- Do NOT wrap in markdown. One JSON object per line, nothing else.
- If everything is normal, output the single word: CLEAR"""

    payload = {
        "model": TRIAGE_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "keep_alive": "30m",
    }

    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{OLLAMA_URL}/api/chat",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=TRIAGE_TIMEOUT) as resp:
            result = json.loads(resp.read())
            content = result.get("message", {}).get("content", "").strip()
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        log.warning("4B triage failed for %s: %s", label, e)
        return []

    if not content or content.upper() == "CLEAR":
        return []

    # Parse 4B output — one JSON per line
    alerts = []
    for line in content.split("\n"):
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue

        priority = parsed.get("priority", "LOW").upper()
        process = parsed.get("process", "unknown")
        path = parsed.get("path", "")
        summary = parsed.get("summary", "")
        category = parsed.get("category", "other")

        # Build an event dict compatible with the process event format
        event = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "event_type": "log_alert",
            "path": path or f"/system/log/{label}",
            "process": process,
            "pid": None,
            "parent_pid": None,
            "uid": None,
            "euid": None,
            "signing_id": "",
            "team_id": "",
            "platform_binary": False,
            "cmdline": summary,
            "cwd": "",
            "source": f"log-monitor-{label}",
        }

        risk = 0.85 if priority == "HIGH" else 0.6
        classification = {
            "risk_score": risk,
            "verdict": "alert" if priority == "HIGH" else "suspicious",
            "reasoning": f"[log-monitor/{label}] {summary}",
            "category": category,
            "confidence": 0.7,
        }

        # Grab surrounding log context — 1 minute before and after the event
        # so the 30b sees the full timeline, not just a single line
        log_context = _grab_surrounding_logs(label, parsed)

        event["log_context"] = log_context
        classification["reasoning"] += f" | {len(log_context.splitlines())} lines of surrounding context attached"

        alerts.append({"event": event, "classification": classification})
        log.warning("[%s] 4B flagged: %s — %s (%s)", label, process, summary, priority)

    return alerts


def _grab_surrounding_logs(label: str, parsed_alert: dict) -> str:
    """Grab a 2-minute window of logs around an alert, filtered by the 4B.

    Raw 2 minutes of logs can be 10,000+ entries. The 4B filters it down
    to just the timeline entries relevant to the investigation — what led
    up to the event, the event itself, and what happened after.
    """
    category = parsed_alert.get("category", "")
    process = parsed_alert.get("process", "")
    summary = parsed_alert.get("summary", "")

    # Build a predicate that captures related activity
    predicates = []

    if process and process != "unknown":
        predicates.append(f'process == "{process}"')

    _category_subsystems = {
        "auth_failure": "com.apple.opendirectoryd",
        "privilege_escalation": "com.apple.authd",
        "sandbox_violation": "com.apple.sandbox",
        "tcc_bypass": "com.apple.TCC",
        "firewall_block": "com.apple.alf",
        "persistence": "com.apple.launchd",
        "suspicious_launch": "com.apple.launchd",
    }
    subsystem = _category_subsystems.get(category)
    if subsystem:
        predicates.append(f'subsystem == "{subsystem}"')

    if not predicates:
        predicates.append(
            'subsystem IN {"com.apple.securityd","com.apple.authd",'
            '"com.apple.TCC","com.apple.sandbox","com.apple.alf"}'
        )

    predicate = " OR ".join(predicates)

    cmd = [
        "log", "show",
        "--last", "2m",
        "--predicate", predicate,
        "--style", "compact",
        "--info",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0:
            return "(failed to grab surrounding logs)"

        raw = result.stdout.strip()
        lines = raw.split("\n")

        # Skip header
        if lines and lines[0].startswith("Filtering"):
            lines = lines[1:]

        if not lines:
            return "(no surrounding log entries)"

        raw_count = len(lines)

        # If it's small enough, no filter needed
        if raw_count <= 30:
            return f"[{raw_count} entries in 2-min window]\n" + "\n".join(lines)

        # Too many entries — run through 4B to extract the relevant timeline
        return _filter_log_context(process, category, summary, lines, raw_count)

    except (subprocess.TimeoutExpired, OSError) as e:
        return f"(failed to grab surrounding logs: {e})"


def _filter_log_context(process: str, category: str, summary: str,
                        lines: list[str], raw_count: int) -> str:
    """Run raw surrounding logs through the 4B scrubber to extract relevant timeline."""
    # Feed the 4B a manageable chunk — first 500 + last 500 if huge
    if len(lines) > 1000:
        sample = lines[:500] + ["", f"... [{len(lines) - 1000} lines omitted] ...", ""] + lines[-500:]
    else:
        sample = lines

    log_block = "\n".join(sample)

    prompt = f"""You are filtering system logs for a security investigation. Extract ONLY the relevant timeline.

THE ALERT:
  Process: {process}
  Category: {category}
  What happened: {summary}

RAW SYSTEM LOGS ({raw_count} entries from a 2-minute window):
{log_block}

INSTRUCTIONS:
- Extract entries that show the TIMELINE of this event:
  1. What led up to it (auth attempts, process launches, permission checks)
  2. The event itself
  3. What happened immediately after (follow-up actions, errors, related spawns)
- Remove routine noise (heartbeats, periodic checks, unrelated subsystem chatter)
- Preserve EXACT original format — do not rewrite or summarize entries
- Keep chronological order
- Include timestamps
- Maximum 50 entries. If more are relevant, keep the ones closest to the event.
- If nothing is relevant, say "NO RELEVANT TIMELINE ENTRIES" """

    result = scrub(log_block, prompt, fallback_chars=0)

    # If scrubber returned the raw (fallback_chars=0 means no truncation fallback),
    # build our own head+tail fallback
    if not result.startswith("[4B"):
        head = "\n".join(lines[:25])
        tail = "\n".join(lines[-25:])
        return (f"[4B filter unavailable — showing first/last 25 of {raw_count} entries]\n"
                f"--- FIRST 25 ---\n{head}\n\n--- LAST 25 ---\n{tail}")

    return result
