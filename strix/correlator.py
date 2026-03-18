"""Kill chain correlator — detect attack patterns across individually-benign events.

The 30b model analyzes events one at a time. She might rule each one "normal"
because individually they ARE normal. But a sequence of normal events can be
a known attack pattern:

  process enumeration → keychain access → new LaunchAgent → outbound curl

Each step is legitimate on its own. Together, it's persistence + exfiltration.

The correlator runs periodically (called from the daemon loop), scans recent
events and verdicts, and matches against defined attack chain patterns.
When a chain matches, it escalates to the 30b with the FULL sequence context
so she can see the big picture.

No ML. Just pattern rules over SQLite + time windows.
"""

import json
import time
import sqlite3
import logging
from dataclasses import dataclass, field
from config import DB_PATH, STRIX_DIR
from manifest import check_against_manifest, check_parent_against_manifest

log = logging.getLogger("strix.correlator")

CORRELATION_LOG = STRIX_DIR / "correlations.jsonl"


# ============================================================
# ATTACK CHAIN DEFINITIONS
# ============================================================

@dataclass
class ChainStage:
    """A single stage in an attack chain."""
    label: str                          # Human-readable name
    match: dict                         # Fields to match in events/verdicts
    mitre: str = ""                     # ATT&CK technique ID
    required: bool = True               # Must this stage be present?
    max_age_minutes: int = 60           # How far back to look for this stage


@dataclass
class AttackChain:
    """A sequence of stages that, together, indicate an attack pattern."""
    name: str                           # Chain name
    description: str                    # What this chain detects
    mitre_tactic: str                   # ATT&CK tactic (e.g., "TA0003 Persistence")
    severity: str                       # "medium", "high", "critical"
    min_stages: int                     # Minimum stages that must match to trigger
    stages: list[ChainStage]           # Ordered stages
    window_minutes: int = 60            # Total time window for the chain
    cooldown_minutes: int = 30          # Don't re-alert within this window


# --- Defined attack chains ---

CHAINS = [
    AttackChain(
        name="persistence_install",
        description="Process enumeration followed by LaunchAgent/Daemon creation — classic persistence install pattern",
        mitre_tactic="TA0003 Persistence",
        severity="high",
        min_stages=3,
        window_minutes=60,
        stages=[
            ChainStage(
                label="reconnaissance",
                match={"cmdline_contains": ["ps ", "pgrep", "launchctl list", "system_profiler"]},
                mitre="T1057",
            ),
            ChainStage(
                label="plist_write",
                match={"path_contains": ["LaunchAgents", "LaunchDaemons"], "event_type": "exec"},
                mitre="T1543.001",
            ),
            ChainStage(
                label="launchctl_load",
                match={"process": "launchctl", "cmdline_contains": ["bootstrap", "load"]},
                mitre="T1569.001",
            ),
        ],
    ),

    AttackChain(
        name="credential_harvest_exfil",
        description="Keychain or credential access followed by network exfiltration",
        mitre_tactic="TA0006 Credential Access + TA0010 Exfiltration",
        severity="critical",
        min_stages=2,
        window_minutes=30,
        stages=[
            ChainStage(
                label="credential_access",
                match={"process_any": ["security", "KeychainAccess"], "cmdline_contains": ["find-generic-password", "dump-keychain", "find-internet-password"]},
                mitre="T1555.001",
            ),
            ChainStage(
                label="exfiltration",
                match={"process_any": ["curl", "wget", "nc", "ncat"], "cmdline_contains": ["-X POST", "--upload", "-d @", "--data-binary"]},
                mitre="T1048",
            ),
        ],
    ),

    AttackChain(
        name="defense_evasion_execution",
        description="Binary dropped to /tmp, made executable, then executed — classic dropper pattern",
        mitre_tactic="TA0005 Defense Evasion + TA0002 Execution",
        severity="critical",
        min_stages=2,
        window_minutes=15,
        stages=[
            ChainStage(
                label="chmod_tmp",
                match={"process": "chmod", "cmdline_contains": ["/tmp/", "/var/tmp/", "+x"]},
                mitre="T1222.002",
            ),
            ChainStage(
                label="tmp_execution",
                match={"path_contains": ["/tmp/", "/var/tmp/"], "event_type": "exec"},
                mitre="T1036",
            ),
        ],
    ),

    AttackChain(
        name="reverse_shell",
        description="Shell spawned with network redirection — reverse shell indicators",
        mitre_tactic="TA0011 Command and Control",
        severity="critical",
        min_stages=1,
        window_minutes=5,
        stages=[
            ChainStage(
                label="reverse_shell",
                match={"cmdline_contains": ["/dev/tcp", "mkfifo", "nc -e", "bash -i >& /dev/tcp", "python -c 'import socket"]},
                mitre="T1059.004",
            ),
        ],
    ),

    AttackChain(
        name="discovery_spray",
        description="Multiple discovery commands in rapid succession — automated recon",
        mitre_tactic="TA0007 Discovery",
        severity="medium",
        min_stages=4,
        window_minutes=10,
        stages=[
            ChainStage(
                label="system_info",
                match={"process_any": ["sw_vers", "system_profiler", "uname", "sysctl"]},
                mitre="T1082",
                required=False,
            ),
            ChainStage(
                label="process_list",
                match={"process_any": ["ps", "pgrep", "top"], "cmdline_contains": ["aux", "-ef", "-A"]},
                mitre="T1057",
                required=False,
            ),
            ChainStage(
                label="network_info",
                match={"process_any": ["ifconfig", "netstat", "lsof"], "cmdline_contains": ["-i", "-an", "-tulnp"]},
                mitre="T1049",
                required=False,
            ),
            ChainStage(
                label="user_info",
                match={"process_any": ["whoami", "id", "dscl", "dscacheutil"]},
                mitre="T1033",
                required=False,
            ),
            ChainStage(
                label="file_discovery",
                match={"process_any": ["find", "mdfind", "ls"], "cmdline_contains": ["/etc/", "/var/", "passwd", ".ssh", ".aws"]},
                mitre="T1083",
                required=False,
            ),
        ],
    ),

    AttackChain(
        name="privilege_escalation_attempt",
        description="SUID binary execution or sudo with suspicious parent chain",
        mitre_tactic="TA0004 Privilege Escalation",
        severity="high",
        min_stages=2,
        window_minutes=15,
        stages=[
            ChainStage(
                label="suid_discovery",
                match={"process": "find", "cmdline_contains": ["-perm", "4000", "+4000", "-u=s"]},
                mitre="T1083",
            ),
            ChainStage(
                label="suid_execution",
                match={"uid_neq_euid": True},
                mitre="T1548.001",
            ),
        ],
    ),

    AttackChain(
        name="ssh_lateral_movement",
        description="SSH key generation or discovery followed by outbound SSH",
        mitre_tactic="TA0008 Lateral Movement",
        severity="high",
        min_stages=2,
        window_minutes=30,
        stages=[
            ChainStage(
                label="ssh_key_discovery",
                match={"process_any": ["find", "ls", "cat"], "cmdline_contains": [".ssh/", "id_rsa", "id_ed25519", "authorized_keys"]},
                mitre="T1552.004",
            ),
            ChainStage(
                label="ssh_connection",
                match={"process": "ssh"},
                mitre="T1021.004",
            ),
        ],
    ),
]


# ============================================================
# CORRELATION ENGINE
# ============================================================

def correlate(conn: sqlite3.Connection | None = None) -> list[dict]:
    """Scan recent events for attack chain matches.

    Returns list of triggered chain alerts with full event context.
    Called periodically from the daemon loop.
    """
    own_conn = conn is None
    if own_conn:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row

    triggered = []

    for chain in CHAINS:
        # Check cooldown — don't re-alert too soon
        if _in_cooldown(chain.name, chain.cooldown_minutes):
            continue

        matches = _match_chain(conn, chain)
        if matches:
            alert = {
                "chain": chain.name,
                "description": chain.description,
                "mitre_tactic": chain.mitre_tactic,
                "severity": chain.severity,
                "stages_matched": len(matches),
                "stages_required": chain.min_stages,
                "events": matches,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            }
            triggered.append(alert)
            _log_correlation(alert)
            log.warning(
                "CHAIN TRIGGERED: %s (%s) — %d/%d stages matched",
                chain.name, chain.severity, len(matches), len(chain.stages)
            )

    if own_conn:
        conn.close()

    return triggered


def _match_chain(conn: sqlite3.Connection, chain: AttackChain) -> list[dict]:
    """Try to match all stages of a chain against recent events."""
    now = time.time()
    window_start = now - (chain.window_minutes * 60)

    # Pull recent events within the chain's time window
    events = conn.execute("""
        SELECT * FROM process_events
        WHERE created_at >= ?
        ORDER BY created_at ASC
    """, (window_start,)).fetchall()

    if not events:
        return []

    matched_stages = []

    for stage in chain.stages:
        stage_match = _find_stage_match(events, stage, now)
        if stage_match:
            matched_stages.append({
                "stage": stage.label,
                "mitre": stage.mitre,
                "event": dict(stage_match),
            })
        elif stage.required:
            # Required stage missing — chain doesn't match
            return []

    # Check if we have enough stages
    if len(matched_stages) >= chain.min_stages:
        return matched_stages

    return []


def _find_stage_match(events: list, stage: ChainStage, now: float) -> dict | None:
    """Find an event that matches a stage's criteria."""
    max_age = now - (stage.max_age_minutes * 60)

    for event in events:
        if event["created_at"] < max_age:
            continue

        if _event_matches(event, stage.match):
            return event

    return None


def _event_matches(event: dict, criteria: dict) -> bool:
    """Check if an event matches stage criteria."""
    for key, value in criteria.items():
        if key == "process":
            if event.get("process") != value:
                return False

        elif key == "process_any":
            if event.get("process") not in value:
                return False

        elif key == "event_type":
            if event.get("event_type") != value:
                return False

        elif key == "cmdline_contains":
            cmdline = (event.get("cmdline") or "").lower()
            if not any(pat.lower() in cmdline for pat in value):
                return False

        elif key == "path_contains":
            path = (event.get("path") or "").lower()
            if not any(pat.lower() in path for pat in value):
                return False

        elif key == "uid_neq_euid":
            uid = event.get("uid")
            euid = event.get("euid")
            if uid is None or euid is None or uid == euid:
                return False

    return True


# ============================================================
# COOLDOWN + LOGGING
# ============================================================

_last_triggered: dict[str, float] = {}


def _in_cooldown(chain_name: str, cooldown_minutes: int) -> bool:
    """Check if a chain was triggered recently."""
    last = _last_triggered.get(chain_name, 0)
    return (time.time() - last) < (cooldown_minutes * 60)


def _log_correlation(alert: dict):
    """Log a correlation alert to disk."""
    _last_triggered[alert["chain"]] = time.time()
    STRIX_DIR.mkdir(parents=True, exist_ok=True)
    with open(CORRELATION_LOG, "a") as f:
        f.write(json.dumps(alert, default=str) + "\n")


# ============================================================
# ANOMALY CORRELATOR — detect novel attack patterns
# ============================================================
# This doesn't match known chains. It detects sequences that DEVIATE
# from your machine's normal behavior profile. The 30b gets the sequence
# and decides if it's a threat — she's the one discovering new patterns,
# not us.

def correlate_anomalies(conn: sqlite3.Connection | None = None) -> list[dict]:
    """Detect anomalous event sequences that don't match known chains.

    Looks for:
    1. Burst of never-before-seen binaries in a short window
    2. Unusual parent→child spawn relationships
    3. Events ruled "normal" individually but from unusual UIDs
    4. Process chains that cross trust boundaries (user → root → user)
    5. Temporal anomalies — things that never happen at this time of day
    """
    own_conn = conn is None
    if own_conn:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row

    now = time.time()
    window = now - 1800  # Last 30 minutes
    anomalies = []

    # --- 1. Burst of first-seen binaries ---
    # If multiple never-before-seen processes execute within 10 minutes,
    # something is deploying new tools. That's recon or staging.
    first_seen_events = conn.execute("""
        SELECT pe.*, b.seen_count, b.first_seen as baseline_first_seen
        FROM process_events pe
        LEFT JOIN baselines b ON pe.path = b.path AND pe.signing_id = b.signing_id
        WHERE pe.created_at >= ?
          AND (b.seen_count IS NULL OR b.seen_count <= 2)
          AND pe.platform_binary = 0
        ORDER BY pe.created_at ASC
    """, (window,)).fetchall()

    if len(first_seen_events) >= 3:
        # Check if they cluster within 10 minutes
        clusters = _find_temporal_clusters(first_seen_events, window_seconds=600)
        for cluster in clusters:
            if len(cluster) >= 3:
                anomalies.append({
                    "type": "novel_binary_burst",
                    "severity": "high",
                    "description": (
                        f"{len(cluster)} never-before-seen non-platform binaries executed "
                        f"within 10 minutes. Possible tool deployment or staging."
                    ),
                    "events": [dict(e) for e in cluster],
                    "why_anomalous": "Multiple first-execution events clustered together "
                                     "is abnormal — your machine has a stable baseline of "
                                     "known binaries. New tools appearing in bursts is a signal.",
                })

    # --- 2. Unusual parent→child relationships ---
    # If a process spawns something it's NEVER spawned before, that's interesting.
    recent_events = conn.execute("""
        SELECT pe.*, b.typical_parent
        FROM process_events pe
        LEFT JOIN baselines b ON pe.path = b.path
        WHERE pe.created_at >= ?
        ORDER BY pe.created_at ASC
    """, (window,)).fetchall()

    unusual_spawns = []
    for event in recent_events:
        typical_parent = event["typical_parent"]
        actual_parent_pid = event["parent_pid"]
        if not typical_parent or not actual_parent_pid:
            continue

        # Look up the actual parent's name
        parent = conn.execute(
            "SELECT process, path FROM process_events WHERE pid = ? ORDER BY created_at DESC LIMIT 1",
            (actual_parent_pid,)
        ).fetchone()

        if parent and typical_parent and parent["process"] != typical_parent:
            unusual_spawns.append({
                "child": event["process"],
                "child_path": event["path"],
                "expected_parent": typical_parent,
                "actual_parent": parent["process"],
                "actual_parent_path": parent["path"],
                "event": dict(event),
            })

    if len(unusual_spawns) >= 2:
        anomalies.append({
            "type": "unusual_parent_chain",
            "severity": "medium",
            "description": (
                f"{len(unusual_spawns)} processes spawned by unexpected parents. "
                f"Normal parent relationships have been learned from baseline — "
                f"these deviate from established patterns."
            ),
            "events": unusual_spawns[:10],  # Cap at 10
            "why_anomalous": "A process being spawned by an unusual parent suggests "
                             "either a new workflow or process injection/hijacking.",
        })

    # --- 3. Trust boundary crossings ---
    # user → root → user within a short window is suspicious
    uid_changes = []
    prev_uid = None
    for event in recent_events:
        uid = event.get("uid")
        euid = event.get("euid")
        if uid is None:
            continue

        if prev_uid is not None:
            # Detect user → root transition
            if prev_uid != 0 and (uid == 0 or euid == 0):
                uid_changes.append(("escalation", event))
            # Detect root → user transition (after escalation)
            elif prev_uid == 0 and uid != 0 and euid != 0:
                uid_changes.append(("de-escalation", event))

        prev_uid = euid if euid is not None else uid

    # Look for escalation → de-escalation pattern
    escalations = [e for t, e in uid_changes if t == "escalation"]
    deescalations = [e for t, e in uid_changes if t == "de-escalation"]
    if escalations and deescalations:
        anomalies.append({
            "type": "trust_boundary_crossing",
            "severity": "high",
            "description": (
                f"Privilege escalation→de-escalation pattern detected: "
                f"{len(escalations)} escalation(s), {len(deescalations)} de-escalation(s) "
                f"within 30 minutes."
            ),
            "escalations": [dict(e) for e in escalations[:5]],
            "deescalations": [dict(e) for e in deescalations[:5]],
            "why_anomalous": "Legitimate privilege escalation (sudo, installer) typically "
                             "stays elevated. Bouncing between user↔root suggests a tool "
                             "that escalates, does something, then drops back to hide.",
        })

    # --- 4. Unsigned + network activity combo ---
    # Unsigned binary executing AND network tools used within same window
    unsigned_events = [e for e in recent_events
                       if not e.get("signing_id") and not e.get("platform_binary")]
    network_events = [e for e in recent_events
                      if e.get("process") in ("curl", "wget", "nc", "ncat", "ssh", "scp", "sftp")
                      or "tcp" in (e.get("cmdline") or "").lower()]

    if unsigned_events and network_events:
        anomalies.append({
            "type": "unsigned_plus_network",
            "severity": "high",
            "description": (
                f"{len(unsigned_events)} unsigned binary execution(s) and "
                f"{len(network_events)} network tool usage(s) in the same 30-minute window."
            ),
            "unsigned": [{"process": e["process"], "path": e["path"]} for e in unsigned_events[:5]],
            "network": [{"process": e["process"], "cmdline": (e["cmdline"] or "")[:100]} for e in network_events[:5]],
            "why_anomalous": "Unsigned code + network activity together suggests "
                             "a dropped tool communicating with an external endpoint.",
        })

    # --- 5. Unexpected service relationships ---
    # Process A talking to/through Process B when they've never interacted before.
    # Example: NSURLSession → proxy → CUPS. Or node → cupsd. Or python → identityservicesd.
    # We detect this by finding processes that share a parent chain but have never
    # appeared together before in the baseline.
    service_events = conn.execute("""
        SELECT pe.process, pe.path, pe.parent_pid, pe.pid, pe.cmdline,
               pe.signing_id, pe.created_at
        FROM process_events pe
        WHERE pe.created_at >= ?
        ORDER BY pe.created_at ASC
    """, (window,)).fetchall()

    # Build parent→child pairs seen in this window
    current_pairs = set()
    pid_to_process = {}
    for ev in service_events:
        pid_to_process[ev["pid"]] = ev["process"]
        if ev["parent_pid"] and ev["parent_pid"] in pid_to_process:
            parent_name = pid_to_process[ev["parent_pid"]]
            current_pairs.add((parent_name, ev["process"]))

    # Check which pairs have NEVER been seen in baseline
    novel_pairs = []
    for parent_name, child_name in current_pairs:
        # Query baseline: has this child ever had this parent?
        baseline_match = conn.execute("""
            SELECT id FROM baselines
            WHERE process = ? AND typical_parent = ?
        """, (child_name, parent_name)).fetchone()

        if not baseline_match:
            # Also check if the reverse has been seen (bidirectional check)
            reverse_match = conn.execute("""
                SELECT id FROM baselines
                WHERE process = ? AND typical_parent = ?
            """, (parent_name, child_name)).fetchone()

            if not reverse_match:
                novel_pairs.append({
                    "parent": parent_name,
                    "child": child_name,
                })

    # Filter out noise: only flag if we have enough baseline data to trust
    total_baselines = conn.execute("SELECT COUNT(*) FROM baselines").fetchone()[0]
    if novel_pairs and total_baselines >= 50:
        # Group by parent to find the most suspicious spawners
        from collections import Counter
        spawner_counts = Counter(p["parent"] for p in novel_pairs)
        top_spawners = spawner_counts.most_common(3)

        if any(count >= 2 for _, count in top_spawners):
            anomalies.append({
                "type": "novel_process_relationships",
                "severity": "high",
                "description": (
                    f"{len(novel_pairs)} process relationships never seen before on this machine. "
                    f"Top novel spawners: {', '.join(f'{name} ({count} new children)' for name, count in top_spawners)}."
                ),
                "novel_pairs": novel_pairs[:10],
                "baseline_size": total_baselines,
                "why_anomalous": (
                    "These processes have never interacted in this parent→child pattern before. "
                    "With a baseline of {0} known relationships, a burst of novel interactions "
                    "suggests either a new workflow (benign) or inter-process communication "
                    "that shouldn't exist (C2 relay, service hijacking, proxy chaining). "
                    "The 30b model should evaluate whether these relationships make sense."
                ).format(total_baselines),
            })

    # --- 6. Manifest violations ---
    # Check every recent event against Apple's canonical process specs.
    # This catches things the baseline would NEVER catch because the
    # baseline might have been poisoned from day one.
    manifest_violations = []
    for event in recent_events:
        # Check the process itself (path, signing ID, UID, platform binary)
        deviation = check_against_manifest(dict(event))
        if deviation:
            manifest_violations.append(deviation)

        # Check parent→child relationship against Apple's architecture
        if event["parent_pid"] and event["parent_pid"] in pid_to_process:
            parent_name = pid_to_process[event["parent_pid"]]
            parent_dev = check_parent_against_manifest(event["process"], parent_name)
            if parent_dev:
                manifest_violations.append(parent_dev)

    if manifest_violations:
        # Group by severity
        critical = [v for v in manifest_violations if v.get("max_severity") == "critical" or v.get("severity") == "critical"]
        high = [v for v in manifest_violations if v.get("max_severity") == "high" or v.get("severity") == "high"]

        if critical:
            anomalies.append({
                "type": "manifest_violation_critical",
                "severity": "critical",
                "description": (
                    f"{len(critical)} CRITICAL manifest violations: Apple system processes "
                    f"not behaving as documented. This is NOT about your machine's baseline — "
                    f"this is about how macOS is SUPPOSED to work."
                ),
                "violations": critical[:10],
                "why_anomalous": (
                    "These processes violate Apple's documented behavior. Wrong path, "
                    "wrong signing identity, wrong UID, or wrong parent process. "
                    "This cannot be explained by 'the machine is just configured differently.' "
                    "Apple platform binaries have specific, kernel-enforced properties. "
                    "Deviations indicate tampering, replacement, or masquerading."
                ),
            })

        if high and not critical:
            anomalies.append({
                "type": "manifest_violation_high",
                "severity": "high",
                "description": (
                    f"{len(high)} manifest violations: system processes spawned by "
                    f"unexpected parents or running with wrong privileges."
                ),
                "violations": high[:10],
                "why_anomalous": (
                    "These parent→child relationships don't match Apple's architecture. "
                    "The machine baseline might show this as 'normal' because it's been "
                    "happening since before monitoring started. The manifest says otherwise."
                ),
            })

    if own_conn:
        conn.close()

    for anomaly in anomalies:
        anomaly["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        _log_correlation(anomaly)
        log.warning(
            "ANOMALY: %s (%s) — %s",
            anomaly["type"], anomaly["severity"], anomaly["description"][:120]
        )

    return anomalies


def _find_temporal_clusters(events: list, window_seconds: int = 600) -> list[list]:
    """Group events into temporal clusters within a sliding window."""
    if not events:
        return []

    clusters = []
    current_cluster = [events[0]]

    for event in events[1:]:
        if event["created_at"] - current_cluster[0]["created_at"] <= window_seconds:
            current_cluster.append(event)
        else:
            if len(current_cluster) >= 2:
                clusters.append(current_cluster)
            current_cluster = [event]

    if len(current_cluster) >= 2:
        clusters.append(current_cluster)

    return clusters


# ============================================================
# ESCALATION INTERFACE — feeds chains to the 30b model
# ============================================================

def format_chain_for_escalation(alert: dict) -> str:
    """Format a triggered chain alert as context for the 30b model.

    This gets injected into the escalation prompt so the 30b can see
    the full sequence of events that triggered the chain.
    """
    lines = [
        f"ATTACK CHAIN DETECTED: {alert['chain']}",
        f"Severity: {alert['severity'].upper()}",
        f"MITRE Tactic: {alert['mitre_tactic']}",
        f"Description: {alert['description']}",
        f"Stages matched: {alert['stages_matched']}/{alert['stages_required']} required",
        "",
        "CHAIN EVENTS (in chronological order):",
    ]

    for stage in alert.get("events", []):
        ev = stage.get("event", {})
        lines.append(
            f"  [{stage['stage']}] ({stage['mitre']}) "
            f"{ev.get('process', '?')} — {ev.get('path', '?')} "
            f"PID={ev.get('pid', '?')} cmdline={ev.get('cmdline', '')[:100]}"
        )

    lines.append("")
    lines.append(
        "These events were each individually assessed. Together they form "
        "a known attack pattern. Evaluate the SEQUENCE, not each event alone."
    )

    return "\n".join(lines)
