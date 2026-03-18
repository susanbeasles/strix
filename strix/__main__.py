"""Watchdog — ML-powered process anomaly detector.

Reads osquery EndpointSecurity events, classifies process executions
via Ollama, escalates suspicious activity to Claude.

Usage:
    python -m watchdog daemon      Run the continuous polling daemon
    python -m watchdog scan        One-shot scan of recent events
    python -m watchdog baseline    Show learned process baselines
    python -m watchdog verdicts    Show recent verdicts
    python -m watchdog status      Daemon health + stats
    python -m watchdog dashboard   Live pipeline dashboard
"""

import os
import sys
import time
import json
import logging
import signal
import threading
from pathlib import Path

# Add our directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from config import (
    POLL_INTERVAL_SECONDS, SKETCHY_THRESHOLD,
    LOG_PATH, WATCHDOG_DIR
)
import db
import parser
import classifier
import escalate
import correlator
from queue import ClassificationQueue
from escalation_queue import EscalationQueue
from log_monitor import start_log_monitor
from tools import set_escalation_queue
from scrubber import stop_scrubber

# --- Logging ---
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(str(LOG_PATH)),
        logging.StreamHandler(),
    ]
)
log = logging.getLogger("watchdog")

_running = True


def signal_handler(sig, frame):
    global _running
    log.info("Received signal %s, shutting down", sig)
    _running = False


signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


def daemon_loop():
    """Main daemon loop — ingestion, classification, and escalation.

    Threads:
      - Main thread: polls osquery, ingests events, runs correlation
      - Classifier thread: pulls from classification queue, runs 4B
      - Escalation worker(s): pulls from escalation queue, runs 30B
        (1 worker normally, scales to 2 when HIGH queue builds up)
    """
    log.info("Watchdog daemon starting (poll=%ds, sketchy_threshold=%.2f)",
             POLL_INTERVAL_SECONDS, SKETCHY_THRESHOLD)

    q = ClassificationQueue()
    eq = EscalationQueue()
    set_escalation_queue(eq)  # So the 30b's promote_priority tool can reach it

    # Verdict callback for escalation workers
    def _record_escalation_result(event, ruling, source):
        conn = db.get_conn()
        db.record_verdict(conn, event, f"watchdog-escalate-30b-{source}", ruling)
        q.record_verdict(event, ruling)
        conn.close()

    eq.start_workers(escalate.escalate, _record_escalation_result)

    classifier_thread = threading.Thread(
        target=_classifier_worker, args=(q, eq), daemon=True
    )
    classifier_thread.start()

    # Log monitor — another 4B tails system logs, feeds alerts to escalation queue
    start_log_monitor(eq)

    # Ingestion loop (main thread)
    while _running:
        try:
            events = parser.poll_process_events()
            if events:
                conn = db.get_conn()
                queued = deduped = fast = 0
                for event in events:
                    # Always record to DB and update baseline
                    db.record_event(conn, event)
                    db.update_baseline(conn, event)

                    result = q.enqueue(event)
                    if result == "queued":
                        queued += 1
                    elif result == "deduped":
                        deduped += 1
                    elif result == "fast_path":
                        fast += 1
                        cached = q.get_cached_verdict(event)
                        if cached:
                            db.record_verdict(conn, event, "fast-cache", cached)

                conn.close()

                if queued or deduped or fast:
                    log.info(
                        "Ingested %d events: %d queued, %d deduped, %d fast-path | "
                        "classify_q=%d cache=%d | escalate_q=%d (HIGH=%d)",
                        len(events), queued, deduped, fast,
                        q.size, q.cache_size,
                        eq.size, eq.high_count,
                    )

        except Exception as e:
            log.error("Error in poll cycle: %s", e, exc_info=True)

        # --- Correlation pass: detect attack chains + anomalies ---
        try:
            conn = db.get_conn()

            # Known attack chains (rule-based)
            chains = correlator.correlate(conn)
            for chain_alert in chains:
                log.warning("CHAIN: %s (%s)", chain_alert["chain"], chain_alert["severity"])
                chain_context = correlator.format_chain_for_escalation(chain_alert)
                chain_event = chain_alert["events"][-1]["event"] if chain_alert.get("events") else {}
                chain_class = {"risk_score": 0.9, "verdict": "chain_trigger",
                               "reasoning": chain_context, "category": chain_alert["chain"]}
                eq.submit(chain_event, chain_class, source="correlator-chain")

            # Novel anomaly detection (behavioral, no signatures)
            anomalies = correlator.correlate_anomalies(conn)
            for anomaly in anomalies:
                log.warning("ANOMALY: %s (%s)", anomaly["type"], anomaly["severity"])
                if anomaly["severity"] in ("high", "critical"):
                    anom_events = anomaly.get("events", anomaly.get("unsigned", []))
                    anom_event = anom_events[-1] if anom_events else {}
                    if isinstance(anom_event, dict) and "event" in anom_event:
                        anom_event = anom_event["event"]
                    anom_class = {
                        "risk_score": 0.85,
                        "verdict": "anomaly",
                        "reasoning": anomaly["description"] + " | " + anomaly.get("why_anomalous", ""),
                        "category": anomaly["type"],
                    }
                    eq.submit(anom_event, anom_class, source="correlator-anomaly")

            conn.close()
        except Exception as e:
            log.error("Error in correlation pass: %s", e, exc_info=True)

        for _ in range(POLL_INTERVAL_SECONDS):
            if not _running:
                break
            time.sleep(1)

    eq.stop()
    stop_scrubber()
    log.info("Watchdog daemon stopped (classify: %s | escalate: %s)", q.stats, eq.stats)


def _classifier_worker(q: ClassificationQueue, eq: EscalationQueue):
    """Classification thread — pulls from queue, classifies via Ollama.

    Suspicious/alert events are submitted to the escalation queue (not
    processed inline). The escalation worker(s) handle the 30b sessions.
    """
    conn = db.get_conn()

    while _running:
        item = q.dequeue(timeout=5.0)
        if item is None:
            continue

        event = item.event
        try:
            process_name = event.get("process", "unknown")
            path = event.get("path", "unknown")
            pid = event.get("pid", "?")

            # Get baseline context for this binary
            baseline_ctx = db.get_baseline_context(conn, path)

            result = classifier.classify_process(event, baseline_ctx)
            verdict = result["verdict"]
            risk = result["risk_score"]
            confidence = result["confidence"]

            log.info(
                "%s (%s) PID=%s | verdict=%s risk=%.2f conf=%.2f hits=%d | %s",
                process_name, path, pid,
                verdict, risk, confidence, item.count, result["reasoning"]
            )

            db.record_verdict(conn, event, "ollama", result)

            # Feed verdict back to queue for fast-path learning
            q.record_verdict(event, result)

            # Submit to escalation queue — worker(s) handle the 30b sessions
            if verdict in ("alert", "suspicious") or risk >= SKETCHY_THRESHOLD:
                eq.submit(event, result, source="classifier")

        except Exception as e:
            log.error("Error classifying %s: %s",
                      event.get("process", "?"), e, exc_info=True)

    conn.close()


def cmd_scan():
    """One-shot scan of current osquery events."""
    conn = db.get_conn()
    events = parser.poll_process_events()
    log.info("Found %d process events", len(events))

    for event in events:
        db.record_event(conn, event)
        db.update_baseline(conn, event)

        baseline_ctx = db.get_baseline_context(conn, event["path"])
        result = classifier.classify_process(event, baseline_ctx)

        verdict = result["verdict"]
        risk = result["risk_score"]
        process = event.get("process", "unknown")
        path = event.get("path", "")

        log.info(
            "%s (%s) | verdict=%s risk=%.2f | %s",
            process, path, verdict, risk, result["reasoning"]
        )

        db.record_verdict(conn, event, "ollama", result)

        if verdict in ("alert", "suspicious") or risk >= SKETCHY_THRESHOLD:
            log.warning("ESCALATING to 30b: %s (risk=%.2f)", process, risk)
            ruling = escalate.escalate(event, result)
            if ruling:
                db.record_verdict(conn, event, "watchdog-escalate-30b", ruling)

    conn.close()


def cmd_baseline():
    """Show learned process baselines."""
    conn = db.get_conn()
    rows = conn.execute("""
        SELECT process, path, signing_id, platform_binary, seen_count,
               verdict, typical_parent, typical_uid,
               datetime(first_seen, 'unixepoch', 'localtime') as first,
               datetime(last_seen, 'unixepoch', 'localtime') as last
        FROM baselines ORDER BY seen_count DESC LIMIT 50
    """).fetchall()

    if not rows:
        print("No baselines recorded yet. Run 'watchdog daemon' or 'watchdog scan' first.")
    else:
        print(f"{'Count':>6}  {'Verdict':<11} {'Process':<25} {'Signing ID':<35} {'Path'}")
        print("-" * 110)
        for r in rows:
            plat = "*" if r["platform_binary"] else " "
            print(f"{r['seen_count']:>5}{plat} {r['verdict']:<11} "
                  f"{r['process']:<25} {r['signing_id'] or '(unsigned)':<35} "
                  f"{r['path']}")

    conn.close()


def cmd_verdicts():
    """Show recent verdicts."""
    conn = db.get_conn()
    rows = conn.execute("""
        SELECT process, path, source, verdict, confidence, risk_score,
               reasoning, category,
               datetime(created_at, 'unixepoch', 'localtime') as ts
        FROM verdicts ORDER BY created_at DESC LIMIT 30
    """).fetchall()

    if not rows:
        print("No verdicts recorded yet.")
    else:
        for r in rows:
            risk_bar = "#" * int(r["risk_score"] * 10) if r["risk_score"] else ""
            print(f"  [{r['ts']}] {r['verdict']:<11} {r['process']:<25} "
                  f"risk={r['risk_score']:.2f} [{risk_bar:<10}] "
                  f"({r['source']}) {r['reasoning']}")

    conn.close()


def cmd_status():
    """Show daemon status and stats."""
    conn = db.get_conn()
    stats = {}
    stats["total_events"] = conn.execute("SELECT COUNT(*) FROM process_events").fetchone()[0]
    stats["unique_binaries"] = conn.execute("SELECT COUNT(*) FROM baselines").fetchone()[0]
    stats["total_verdicts"] = conn.execute("SELECT COUNT(*) FROM verdicts").fetchone()[0]
    stats["suspicious"] = conn.execute(
        "SELECT COUNT(*) FROM verdicts WHERE verdict = 'suspicious'").fetchone()[0]
    stats["alerts"] = conn.execute(
        "SELECT COUNT(*) FROM verdicts WHERE verdict = 'alert'").fetchone()[0]
    stats["unsigned_binaries"] = conn.execute(
        "SELECT COUNT(*) FROM baselines WHERE signing_id = '' OR signing_id IS NULL"
    ).fetchone()[0]

    print("Watchdog Status")
    print("=" * 40)
    for k, v in stats.items():
        print(f"  {k.replace('_', ' ').title():<25} {v}")

    # Show escalation count
    if WATCHDOG_DIR.exists():
        esc_log = WATCHDOG_DIR / "escalations.jsonl"
        if esc_log.exists():
            with open(esc_log) as f:
                esc_count = sum(1 for _ in f)
            print(f"  {'Escalations':<25} {esc_count}")

    conn.close()


FORKGUARD = Path.home() / "bin" / "forkguard"
FORKGUARD_LIMIT = 12


def _ensure_forkguard():
    """Re-exec through forkguard if not already wrapped.

    Forkguard monitors the entire watchdog process tree. If descendants
    exceed the limit, it freezes the tree and notifies the operator.
    """
    if os.environ.get("FORKGUARD_WRAPPED"):
        return  # Already inside forkguard

    if not FORKGUARD.exists():
        log.critical("forkguard not found at %s — refusing to start unguarded", FORKGUARD)
        sys.exit(1)

    cmd = [
        str(FORKGUARD),
        "--limit", str(FORKGUARD_LIMIT),
        "--name", "watchdog",
        "--",
        sys.executable, "-m", "watchdog",
    ] + sys.argv[1:]

    env = os.environ.copy()
    env["FORKGUARD_WRAPPED"] = "1"

    log.info("Re-launching through forkguard (limit=%d)", FORKGUARD_LIMIT)
    os.execve(str(FORKGUARD), cmd, env)


def _boost_priority():
    """Renice watchdog to maximum scheduling priority (-20).

    When security events are firing, watchdog deserves CPU time over
    everything else. This requires root (via sudo) or the process to
    already be running as root.
    """
    pid = os.getpid()
    try:
        os.setpriority(os.PRIO_PROCESS, pid, -20)
        log.info("Reniced PID %d to -20 (max priority)", pid)
    except PermissionError:
        # Need sudo for negative nice values
        try:
            import subprocess
            subprocess.run(
                ["sudo", "-n", "renice", "-n", "-20", "-p", str(pid)],
                capture_output=True, timeout=5,
            )
            log.info("Reniced PID %d to -20 via sudo", pid)
        except Exception as e:
            log.warning("Could not renice to -20: %s (running at normal priority)", e)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "daemon":
        _ensure_forkguard()
        _boost_priority()
        daemon_loop()
    elif cmd == "scan":
        cmd_scan()
    elif cmd == "baseline":
        cmd_baseline()
    elif cmd == "verdicts":
        cmd_verdicts()
    elif cmd == "status":
        cmd_status()
    elif cmd == "dashboard":
        import dashboard
        dashboard.main()
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
