"""Pre-classification enrichment — gather forensic data about a process.

Before Ollama classifies a process event, we enrich it with real data
from the filesystem: code signing verification, file permissions,
setuid bits, binary hash, and Homebrew bottle verification.

This gives the ML model actual evidence instead of just metadata.
"""

import subprocess
import os
import hashlib
import logging

log = logging.getLogger("watchdog.enrich")


def enrich_event(event: dict) -> dict:
    """Add forensic context to a process event. Returns enriched copy."""
    enriched = dict(event)
    path = event.get("path", "")

    if not path or not os.path.exists(path):
        enriched["enrichment"] = {"exists": False, "note": "binary not found on disk"}
        return enriched

    ctx = {"exists": True}

    # Live process verification — if the PID is still running, get the REAL uid/euid/gid
    pid = event.get("pid")
    if pid:
        try:
            result = subprocess.run(
                ["ps", "-p", str(pid), "-o", "pid=,uid=,gid=,user=,comm="],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                parts = result.stdout.strip().split()
                if len(parts) >= 4:
                    ctx["live_pid"] = int(parts[0])
                    ctx["live_uid"] = int(parts[1])
                    ctx["live_gid"] = int(parts[2])
                    ctx["live_user"] = parts[3]
                    # Compare against what osquery reported
                    reported_euid = event.get("euid")
                    if reported_euid is not None and ctx["live_uid"] != reported_euid:
                        ctx["euid_mismatch"] = (
                            f"osquery reported euid={reported_euid}, "
                            f"but ps shows uid={ctx['live_uid']} gid={ctx['live_gid']} — "
                            f"osquery may be reporting GID in the EUID field"
                        )
            else:
                ctx["process_exited"] = True
        except (subprocess.TimeoutExpired, ValueError):
            pass

    # File permissions and ownership
    try:
        stat = os.stat(path)
        ctx["mode"] = oct(stat.st_mode)
        ctx["owner_uid"] = stat.st_uid
        ctx["owner_gid"] = stat.st_gid
        ctx["size_bytes"] = stat.st_size
        # Check for setuid/setgid bits
        ctx["setuid"] = bool(stat.st_mode & 0o4000)
        ctx["setgid"] = bool(stat.st_mode & 0o2000)
    except OSError as e:
        ctx["stat_error"] = str(e)

    # SHA256 hash for integrity verification
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        ctx["sha256"] = h.hexdigest()
    except (OSError, PermissionError) as e:
        ctx["hash_error"] = str(e)

    # Code signing verification
    try:
        result = subprocess.run(
            ["codesign", "-dvvv", path],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stderr  # codesign writes to stderr
        ctx["codesign_valid"] = result.returncode == 0
        # Extract key fields
        for line in output.splitlines():
            if line.startswith("Authority="):
                ctx.setdefault("codesign_authorities", []).append(line.split("=", 1)[1])
            elif line.startswith("TeamIdentifier="):
                ctx["codesign_team_id"] = line.split("=", 1)[1]
            elif line.startswith("Identifier="):
                ctx["codesign_identifier"] = line.split("=", 1)[1]
            elif line.startswith("Signature="):
                ctx["codesign_signature"] = line.split("=", 1)[1]
            elif "adhoc" in line.lower():
                ctx["codesign_adhoc"] = True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        ctx["codesign_error"] = "codesign command failed"

    # Check if this is a Homebrew binary
    if "/opt/homebrew/" in path or "/usr/local/Cellar/" in path:
        ctx["homebrew"] = True

    # Check if path is in a suspicious location
    if any(s in path for s in ("/tmp/", "/var/tmp/", "/private/tmp/")):
        ctx["suspicious_location"] = True
    if "/." in path:
        ctx["hidden_directory"] = True

    enriched["enrichment"] = ctx
    return enriched


def format_enrichment(enrichment: dict) -> str:
    """Format enrichment data as a string for the classifier prompt."""
    if not enrichment.get("exists", True):
        return "BINARY NOT FOUND ON DISK — possible ephemeral or deleted process"

    parts = []

    # Live process verification results
    if enrichment.get("euid_mismatch"):
        parts.append(f"EUID DISCREPANCY: {enrichment['euid_mismatch']}")
    if enrichment.get("live_uid") is not None:
        parts.append(
            f"Live process verified: uid={enrichment['live_uid']} "
            f"gid={enrichment['live_gid']} user={enrichment.get('live_user','?')}"
        )
    elif enrichment.get("process_exited"):
        parts.append("Process already exited — could not verify live UID/EUID")

    if enrichment.get("setuid"):
        parts.append("WARNING: SETUID BIT SET — privilege escalation binary")
    if enrichment.get("setgid"):
        parts.append("WARNING: SETGID BIT SET")

    if enrichment.get("codesign_valid"):
        authorities = enrichment.get("codesign_authorities", [])
        if authorities:
            parts.append(f"Code signing chain: {' -> '.join(authorities)}")
        team = enrichment.get("codesign_team_id", "")
        if team and team != "not set":
            parts.append(f"Team ID verified: {team}")
        elif enrichment.get("codesign_adhoc"):
            parts.append("Ad-hoc signed (no developer ID)")
    else:
        parts.append("CODE SIGNING INVALID or unsigned")

    if enrichment.get("homebrew"):
        parts.append("Homebrew-managed binary (expected ad-hoc signing)")

    mode = enrichment.get("mode", "")
    if mode:
        parts.append(f"File mode: {mode}, owner: {enrichment.get('owner_uid')}:{enrichment.get('owner_gid')}")

    sha = enrichment.get("sha256", "")
    if sha:
        parts.append(f"SHA256: {sha[:16]}...")

    if enrichment.get("suspicious_location"):
        parts.append("WARNING: Binary in /tmp — classic staging area")
    if enrichment.get("hidden_directory"):
        parts.append("WARNING: Binary in hidden directory")

    return "\n".join(parts) if parts else "No enrichment data available"
