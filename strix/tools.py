"""Strix tools — the 30b model's investigative toolbelt.

These tools are called by the escalation agent loop when the 30b model
requests additional context during process analysis. The model can
request any tool by name; escalate.py executes it and feeds the result back.

All web access is restricted to ALLOWED_DOMAINS. No open internet.
Rate-limited globally and per-domain to prevent abuse.
"""

import json
import re
import subprocess
import time
import hashlib
import sqlite3
import urllib.request
import urllib.error
import urllib.parse
import logging
import os
from pathlib import Path
from config import DB_PATH, STRIX_DIR
from scrubber import scrub

log = logging.getLogger("strix.tools")

# --- Domain Allowlist ---
# The 30b model can ONLY fetch from these domains. Everything else is blocked.
ALLOWED_DOMAINS = {
    # Apple
    "support.apple.com",
    "developer.apple.com",
    # Homebrew
    "formulae.brew.sh",
    # osquery
    "osquery.io",
    # GitHub (restricted to specific repos/paths below)
    "github.com",
    "raw.githubusercontent.com",
    # Security research
    "objective-see.org",
    "attack.mitre.org",
    # CVE / vulnerability databases
    "nvd.nist.gov",
    "services.nvd.nist.gov",
    # Threat intel
    "malware.news",
    "thedfirreport.com",
    # VirusTotal (API only, requires key)
    "www.virustotal.com",
}

# GitHub repos the model is allowed to access
ALLOWED_GITHUB_REPOS = {
    "osquery/osquery",
    "objective-see/LuLu",
    "objective-see/KnockKnock",
    "objective-see/BlockBlock",
    "objective-see/Netiquette",
    "objective-see/RansomWhere",
    "objective-see/OverSight",
    "Yara-Rules/rules",
    "SigmaHQ/sigma",
}

# --- Rate Limiting ---
_call_log: list[float] = []
_domain_calls: dict[str, list[float]] = {}
MAX_CALLS_PER_MINUTE = 10
MAX_CALLS_PER_DOMAIN_PER_MINUTE = 4


def _rate_check(domain: str) -> bool:
    """Returns True if the call is allowed, False if rate-limited."""
    now = time.time()
    cutoff = now - 60

    # Global rate limit
    _call_log[:] = [t for t in _call_log if t > cutoff]
    if len(_call_log) >= MAX_CALLS_PER_MINUTE:
        log.warning("Global rate limit hit (%d/min)", MAX_CALLS_PER_MINUTE)
        return False

    # Per-domain rate limit
    domain_log = _domain_calls.setdefault(domain, [])
    domain_log[:] = [t for t in domain_log if t > cutoff]
    if len(domain_log) >= MAX_CALLS_PER_DOMAIN_PER_MINUTE:
        log.warning("Domain rate limit hit for %s (%d/min)", domain, MAX_CALLS_PER_DOMAIN_PER_MINUTE)
        return False

    _call_log.append(now)
    domain_log.append(now)
    return True


# --- System Inspection ---
INSPECT_SH = Path(__file__).parent / "inspect.sh"
INSPECT_TIMEOUT = 30
INSPECT_MAX_OUTPUT = 8000

INSPECT_SUBCOMMANDS = {
    "ps", "ps-tree", "netstat", "lsof-net", "lsof-listen",
    "launchctl-list", "launchagents", "kextstat", "dns-config",
    "network-config", "arp-table", "routes", "who", "last-logins",
    "dscl-users",
    "ps-pid", "proc-fds", "lsof-pid-net", "launchctl-info",
    "plist-read", "file-info", "codesign", "codesign-verify",
    "entitlements", "sysctl", "system-profiler", "log-show",
}

# Subcommands that return bulk system-wide output — run through 4B filter
# to strip noise before it enters the 30b's context window.
_BULK_SUBCOMMANDS = {
    "ps", "ps-tree", "netstat", "lsof-net", "lsof-listen",
    "launchctl-list", "kextstat", "log-show", "dscl-users", "launchagents",
}

_SHELL_METACHARACTERS = re.compile(r'[;|&$`\\(){}\!><\n\r]')

# Event context — set by escalate.py so the 4B filter knows what to look for
_current_event: dict = {}

# Escalation queue reference — set by __main__.py so promote_priority can reach it
_escalation_queue = None


def set_event_context(event: dict):
    """Set the current event so the 4B filter knows what's under investigation."""
    global _current_event
    _current_event = event


def set_escalation_queue(eq):
    """Set the escalation queue reference so the 30b can promote priorities."""
    global _escalation_queue
    _escalation_queue = eq


def _filter_with_4b(raw_output: str, subcommand: str, focus: str) -> str:
    """Run bulk inspect output through the 4B scrubber to strip noise."""
    process = _current_event.get("process", "unknown")
    pid = _current_event.get("pid", "?")
    path = _current_event.get("path", "unknown")
    parent_pid = _current_event.get("parent_pid", "?")

    prompt = f"""You are a data filter for a security investigation. Your ONLY job is to reduce noise.

INVESTIGATION TARGET:
  Process: {process} (PID {pid})
  Path: {path}
  Parent PID: {parent_pid}

THE INVESTIGATOR ASKED FOR: {subcommand}
FOCUS INSTRUCTION: {focus if focus else "Return anything relevant to the target process."}

RAW SYSTEM OUTPUT (from inspect.sh {subcommand}):
{raw_output}

INSTRUCTIONS:
- Return ONLY lines/entries relevant to the investigation target.
- Include the target process, its parent, its children, and anything the focus instruction asks for.
- Remove obvious system noise (Apple daemons, standard Homebrew services, window server, etc.) UNLESS they relate to the target.
- Preserve the original format — do not rewrite or summarize. Just filter.
- If everything is relevant, return it all.
- If NOTHING is relevant, say "NO RELEVANT ENTRIES for [process]" and list the 3 closest matches.
- Keep output under 1500 characters."""

    return scrub(raw_output, prompt)


def system_inspect(subcommand: str, args: list[str] | None = None, focus: str = "") -> str:
    """Run a read-only system inspection via inspect.sh.

    Validated against an allowlist. Shell metacharacters in args are rejected.
    Called via sudo — requires the sudoers entry for inspect.sh.

    For bulk-output subcommands (ps, netstat, etc.), output is filtered through
    the 4B model before entering the 30b's context. Use 'focus' to tell the 4B
    what to look for.
    """
    if subcommand not in INSPECT_SUBCOMMANDS:
        return f"INVALID_SUBCOMMAND: '{subcommand}' not in allowlist. Valid: {', '.join(sorted(INSPECT_SUBCOMMANDS))}"

    args = args or []

    for arg in args:
        if _SHELL_METACHARACTERS.search(arg):
            return f"BLOCKED: argument contains shell metacharacters: {arg!r}"

    cmd = ["sudo", str(INSPECT_SH), subcommand] + args

    try:
        result = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=INSPECT_TIMEOUT,
        )
        output = result.stdout
        if result.returncode != 0 and result.stderr:
            output += f"\nSTDERR: {result.stderr}"

        if not output.strip():
            return "(no output)"

        # Bulk subcommands go through the 4B filter to strip noise
        if subcommand in _BULK_SUBCOMMANDS and len(output) > 500:
            return _filter_with_4b(output, subcommand, focus)

        # Single-target commands: just truncate if needed
        if len(output) > INSPECT_MAX_OUTPUT:
            output = output[:INSPECT_MAX_OUTPUT] + f"\n... [truncated at {INSPECT_MAX_OUTPUT} chars]"

        return output

    except subprocess.TimeoutExpired:
        return f"TIMEOUT: inspect.sh {subcommand} exceeded {INSPECT_TIMEOUT}s"
    except FileNotFoundError:
        return f"ERROR: inspect.sh not found at {INSPECT_SH}"
    except OSError as e:
        return f"ERROR: {e}"


def _is_allowed_url(url: str) -> tuple[bool, str]:
    """Check if a URL is on the allowlist. Returns (allowed, reason)."""
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return False, "invalid URL"

    if parsed.scheme not in ("https",):
        return False, "only HTTPS allowed"

    domain = parsed.hostname or ""

    if domain not in ALLOWED_DOMAINS:
        return False, f"domain {domain} not in allowlist"

    # GitHub: restrict to allowed repos
    if domain in ("github.com", "raw.githubusercontent.com"):
        path = parsed.path.lstrip("/")
        repo = "/".join(path.split("/")[:2])
        if repo not in ALLOWED_GITHUB_REPOS:
            return False, f"GitHub repo {repo} not in allowlist"

    return True, "allowed"


def _fetch(url: str, timeout: int = 15) -> str:
    """Fetch a URL (must be on allowlist). Returns text content."""
    allowed, reason = _is_allowed_url(url)
    if not allowed:
        return f"BLOCKED: {reason}"

    domain = urllib.parse.urlparse(url).hostname or ""
    if not _rate_check(domain):
        return f"RATE_LIMITED: too many requests to {domain}"

    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "strix-security-tool/1.0",
            "Accept": "text/html,application/json,text/plain",
        })
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content_type = resp.headers.get("Content-Type", "")
            raw = resp.read(500_000)  # 500KB max
            if "json" in content_type:
                return raw.decode("utf-8", errors="replace")
            # Strip HTML tags for readability
            text = raw.decode("utf-8", errors="replace")
            if "<html" in text.lower():
                return _strip_html(text)
            return text
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return f"FETCH_ERROR: {e}"


def _strip_html(html: str) -> str:
    """Crude HTML-to-text. Good enough for doc pages."""
    import re
    # Remove script/style blocks
    text = re.sub(r'<(script|style)[^>]*>.*?</\1>', '', html, flags=re.DOTALL | re.IGNORECASE)
    # Remove tags
    text = re.sub(r'<[^>]+>', ' ', text)
    # Collapse whitespace
    text = re.sub(r'\s+', ' ', text).strip()
    # Truncate to ~10KB for the model prompt
    if len(text) > 10_000:
        text = text[:10_000] + "\n... [truncated]"
    return text


# ============================================================
# TOOL DEFINITIONS — each tool is a callable the agent loop uses
# ============================================================

def web_lookup(url: str) -> str:
    """Fetch a page from an allowed domain. Use for documentation lookups.

    Allowed domains: Apple support/developer, Homebrew formulae, osquery.io,
    objective-see.org, MITRE ATT&CK, NVD/NIST, selected GitHub repos.
    """
    return _fetch(url)


def lookup_homebrew_formula(formula_name: str) -> str:
    """Look up a Homebrew formula to understand what a binary is.

    Returns: package description, homepage, dependencies.
    """
    url = f"https://formulae.brew.sh/api/formula/{urllib.parse.quote(formula_name)}.json"
    raw = _fetch(url)
    try:
        data = json.loads(raw)
        return json.dumps({
            "name": data.get("name"),
            "desc": data.get("desc"),
            "homepage": data.get("homepage"),
            "license": data.get("license"),
            "versions": data.get("versions", {}).get("stable"),
            "dependencies": data.get("dependencies", []),
            "caveats": data.get("caveats"),
        }, indent=2)
    except (json.JSONDecodeError, AttributeError):
        return raw


def lookup_osquery_table(table_name: str) -> str:
    """Look up an osquery table schema to understand event fields."""
    url = f"https://raw.githubusercontent.com/osquery/osquery/master/specs/{urllib.parse.quote(table_name)}.table"
    result = _fetch(url)
    if "FETCH_ERROR" in result or "BLOCKED" in result:
        # Try macOS-specific path
        url = f"https://raw.githubusercontent.com/osquery/osquery/master/specs/darwin/{urllib.parse.quote(table_name)}.table"
        result = _fetch(url)
    return result


def lookup_cve(cve_id: str) -> str:
    """Look up a CVE by ID from NVD/NIST.

    Returns: description, severity, affected products.
    """
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={urllib.parse.quote(cve_id)}"
    raw = _fetch(url)
    try:
        data = json.loads(raw)
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return f"CVE {cve_id} not found"
        cve = vulns[0].get("cve", {})
        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d["lang"] == "en"), "no description")
        metrics = cve.get("metrics", {})
        # Try CVSS 3.1 first, then 3.0
        cvss = None
        for version in ("cvssMetricV31", "cvssMetricV30"):
            if version in metrics:
                cvss = metrics[version][0].get("cvssData", {})
                break
        severity = cvss.get("baseSeverity", "UNKNOWN") if cvss else "UNKNOWN"
        score = cvss.get("baseScore", "?") if cvss else "?"
        return json.dumps({
            "id": cve_id,
            "description": desc,
            "severity": severity,
            "score": score,
            "published": cve.get("published"),
            "lastModified": cve.get("lastModified"),
        }, indent=2)
    except (json.JSONDecodeError, KeyError, IndexError):
        return raw


def lookup_mitre_technique(technique_id: str) -> str:
    """Look up a MITRE ATT&CK technique (e.g., T1059.004 for Unix Shell)."""
    # MITRE ATT&CK STIX data via GitHub
    url = f"https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    # This file is huge — instead, use the web page
    technique_id_clean = technique_id.upper().replace(".", "/")
    url = f"https://attack.mitre.org/techniques/{urllib.parse.quote(technique_id_clean)}/"
    return _fetch(url)


def query_baseline(binary_path: str) -> str:
    """Query the local strix baseline database for a binary.

    Returns: how many times seen, first/last seen, previous verdicts,
    typical parent process, whether it's a platform binary.
    """
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row

        baseline = conn.execute(
            "SELECT * FROM baselines WHERE path = ? ORDER BY seen_count DESC LIMIT 1",
            (binary_path,)
        ).fetchone()

        verdicts = conn.execute(
            "SELECT verdict, confidence, risk_score, reasoning, source, created_at "
            "FROM verdicts WHERE path = ? ORDER BY created_at DESC LIMIT 5",
            (binary_path,)
        ).fetchall()

        conn.close()

        result = {}
        if baseline:
            result["baseline"] = {
                "seen_count": baseline["seen_count"],
                "first_seen": time.strftime("%Y-%m-%d %H:%M", time.localtime(baseline["first_seen"])),
                "last_seen": time.strftime("%Y-%m-%d %H:%M", time.localtime(baseline["last_seen"])),
                "typical_parent": baseline["typical_parent"],
                "typical_uid": baseline["typical_uid"],
                "platform_binary": bool(baseline["platform_binary"]),
                "current_verdict": baseline["verdict"],
                "signing_id": baseline["signing_id"],
            }
        else:
            result["baseline"] = "NEVER SEEN — first execution of this binary"

        if verdicts:
            result["recent_verdicts"] = [
                {
                    "verdict": v["verdict"],
                    "confidence": v["confidence"],
                    "risk_score": v["risk_score"],
                    "source": v["source"],
                    "reasoning": v["reasoning"],
                    "when": time.strftime("%Y-%m-%d %H:%M", time.localtime(v["created_at"])),
                }
                for v in verdicts
            ]

        return json.dumps(result, indent=2)

    except sqlite3.Error as e:
        return f"DB_ERROR: {e}"


def check_known_signing_ids(signing_id: str) -> str:
    """Check a code signing ID against known-good and known-bad lists.

    Known-good: Apple platform binaries, major vendors.
    Known-bad: known macOS malware signing IDs.
    """
    # Apple platform signing ID prefixes — these are kernel-verified
    apple_prefixes = (
        "com.apple.",
        "com.apple.security.",
        "com.apple.xpc.",
    )

    # Known legitimate vendor prefixes
    vendor_prefixes = {
        "com.google.": "Google",
        "com.microsoft.": "Microsoft",
        "com.docker.": "Docker",
        "com.github.": "GitHub",
        "com.1password.": "1Password / AgileBits",
        "com.agilebits.": "1Password / AgileBits",
        "com.crowdstrike.": "CrowdStrike",
        "com.sentinelone.": "SentinelOne",
        "com.malwarebytes.": "Malwarebytes",
        "org.mozilla.": "Mozilla",
        "com.brave.": "Brave",
        "io.sentry.": "Sentry",
        "com.jetbrains.": "JetBrains",
        "com.visualstudio.": "Visual Studio / Microsoft",
        "com.electron.": "Electron app",
        "org.chromium.": "Chromium-based",
        "com.hashicorp.": "HashiCorp",
        "dev.warp.": "Warp terminal",
        "com.loom.": "Loom",
        "com.anthropic.": "Anthropic",
        "com.openai.": "OpenAI",
    }

    # Known macOS malware signing IDs (curated from Objective-See research)
    known_bad = {
        "Developer ID Application: Yinshan Beijing Technology",  # OSX.WindTail
    }

    if not signing_id:
        return json.dumps({"status": "UNSIGNED", "risk": "elevated",
                          "note": "No code signing identity — cannot verify provenance"})

    # Check Apple
    if any(signing_id.startswith(p) for p in apple_prefixes):
        return json.dumps({"status": "APPLE_PLATFORM",
                          "vendor": "Apple", "risk": "low",
                          "note": "Apple platform binary — kernel-verified signing chain"})

    # Check known vendors
    for prefix, vendor in vendor_prefixes.items():
        if signing_id.startswith(prefix):
            return json.dumps({"status": "KNOWN_VENDOR",
                              "vendor": vendor, "risk": "low",
                              "note": f"Known vendor: {vendor}"})

    # Check known-bad
    for bad in known_bad:
        if bad.lower() in signing_id.lower():
            return json.dumps({"status": "KNOWN_MALWARE",
                              "risk": "critical",
                              "note": f"Known malware signing identity: {bad}"})

    return json.dumps({"status": "UNKNOWN",
                      "risk": "medium",
                      "note": f"Signing ID '{signing_id}' not in known-good or known-bad lists. Investigate further."})


def apple_support_search(query: str) -> str:
    """Search Apple support documentation for information about a binary or behavior."""
    encoded = urllib.parse.quote(query)
    url = f"https://support.apple.com/en-us/search/{encoded}"
    return _fetch(url)


def objective_see_malware_check(binary_name: str) -> str:
    """Check Objective-See's macOS malware database for a binary name."""
    url = "https://objective-see.org/malware.html"
    content = _fetch(url)
    if "FETCH_ERROR" in content or "BLOCKED" in content:
        return content
    binary_lower = binary_name.lower()
    if binary_lower in content.lower():
        idx = content.lower().find(binary_lower)
        start = max(0, idx - 200)
        end = min(len(content), idx + 500)
        return f"MATCH FOUND in Objective-See malware catalog:\n...{content[start:end]}..."
    return f"No match for '{binary_name}' in Objective-See malware catalog"


def lookup_virustotal_hash(sha256: str) -> str:
    """Look up a SHA256 hash on VirusTotal. Requires VT_API_KEY env var.

    Free tier: 4 requests/minute. Returns detection ratio and vendor verdicts.
    If no API key is configured, returns instructions for the operator.
    """
    api_key = os.environ.get("VT_API_KEY", "")
    if not api_key:
        return (
            "VIRUSTOTAL: No API key configured. The operator can add one:\n"
            "1. Get a free key at https://www.virustotal.com/gui/join-us\n"
            "2. Store in 1Password, add to ~/.config/op/env.tpl\n"
            "3. Export as VT_API_KEY"
        )

    sha256 = sha256.strip().lower()
    if len(sha256) != 64:
        return f"ERROR: invalid SHA256 hash (expected 64 hex chars, got {len(sha256)})"

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    try:
        req = urllib.request.Request(url, headers={
            "x-apikey": api_key,
            "Accept": "application/json",
        })
        if not _rate_check("www.virustotal.com"):
            return "RATE_LIMITED: too many VirusTotal requests"

        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})

        # Get flagging vendors
        flagged = {vendor: info.get("result", "")
                   for vendor, info in results.items()
                   if info.get("category") == "malicious"}

        return json.dumps({
            "sha256": sha256,
            "detection_ratio": f"{stats.get('malicious', 0)}/{sum(stats.values())}",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "name": attrs.get("meaningful_name", ""),
            "type": attrs.get("type_description", ""),
            "first_seen": attrs.get("first_submission_date"),
            "flagged_by": flagged if flagged else "none",
        }, indent=2)

    except urllib.error.HTTPError as e:
        if e.code == 404:
            return json.dumps({"sha256": sha256, "status": "NOT_FOUND",
                              "note": "Hash not in VirusTotal database — could be benign or novel"})
        return f"VT_ERROR: HTTP {e.code}"
    except (urllib.error.URLError, TimeoutError) as e:
        return f"VT_ERROR: {e}"


def map_mitre_technique(behavior: str) -> str:
    """Map an observed behavior to MITRE ATT&CK techniques for macOS.

    This is a LOCAL lookup — no network call. Maps common process behaviors
    to ATT&CK technique IDs for the model to reference.
    """
    # macOS-relevant ATT&CK technique mappings
    technique_map = {
        # Execution
        "shell": ("T1059.004", "Command and Scripting Interpreter: Unix Shell"),
        "python": ("T1059.006", "Command and Scripting Interpreter: Python"),
        "osascript": ("T1059.002", "Command and Scripting Interpreter: AppleScript"),
        "launchctl": ("T1569.001", "System Services: Launchctl"),
        # Persistence
        "launchagent": ("T1543.001", "Create or Modify System Process: Launch Agent"),
        "launchdaemon": ("T1543.004", "Create or Modify System Process: Launch Daemon"),
        "cron": ("T1053.003", "Scheduled Task/Job: Cron"),
        "login_item": ("T1547.015", "Boot or Logon Autostart Execution: Login Items"),
        # Privilege Escalation
        "suid": ("T1548.001", "Abuse Elevation Control Mechanism: Setuid and Setgid"),
        "sudo": ("T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"),
        # Defense Evasion
        "unsigned": ("T1553.001", "Subvert Trust Controls: Gatekeeper Bypass"),
        "hidden": ("T1564.001", "Hide Artifacts: Hidden Files and Directories"),
        "tmp_execution": ("T1036", "Masquerading"),
        "process_injection": ("T1055", "Process Injection"),
        # Credential Access
        "keychain": ("T1555.001", "Credentials from Password Stores: Keychain"),
        "security_tool": ("T1555", "Credentials from Password Stores"),
        # Discovery
        "system_info": ("T1082", "System Information Discovery"),
        "process_list": ("T1057", "Process Discovery"),
        "network_scan": ("T1046", "Network Service Discovery"),
        # Collection
        "screen_capture": ("T1113", "Screen Capture"),
        "clipboard": ("T1115", "Clipboard Data"),
        "input_capture": ("T1056.001", "Input Capture: Keylogging"),
        # Exfiltration
        "curl_upload": ("T1048", "Exfiltration Over Alternative Protocol"),
        "dns_exfil": ("T1048.003", "Exfiltration Over Alternative Protocol: DNS"),
        # C2
        "reverse_shell": ("T1571", "Non-Standard Port"),
        "nc_listener": ("T1095", "Non-Application Layer Protocol"),
        "encoded_command": ("T1132.001", "Data Encoding: Standard Encoding"),
    }

    behavior_lower = behavior.lower()
    matches = []

    for key, (tech_id, tech_name) in technique_map.items():
        if key in behavior_lower:
            matches.append({"technique_id": tech_id, "name": tech_name, "matched_on": key})

    if not matches:
        return json.dumps({
            "query": behavior,
            "matches": [],
            "note": "No direct technique match. Use web_lookup on attack.mitre.org for deeper search.",
        }, indent=2)

    return json.dumps({"query": behavior, "matches": matches}, indent=2)


def request_domain_access(domain: str, reason: str) -> str:
    """Request access to a domain not on the allowlist.

    The operator will review. Provide the FULL DOMAIN (not a URL) and a
    clear reason. Good: 'virustotal.com' + 'need to check hash reputation'.
    Bad: 'https://virustotal.com/api/v3/files/abc123' + 'checking stuff'.
    """
    # This is handled specially by escalate.py — placeholder for tool registration
    return f"Domain request for '{domain}' logged. Reason: {reason}"


# --- Canonical manifest tool ---
from manifest import get_spec as _get_spec, MANIFEST as _MANIFEST

def check_manifest(process_name: str) -> str:
    """Look up Apple's canonical spec for a process."""
    spec = _get_spec(process_name)
    if spec:
        return json.dumps(spec, indent=2)

    # Not in manifest — list similar names
    similar = [name for name in _MANIFEST if process_name.lower() in name.lower()]
    if similar:
        return json.dumps({
            "status": "NOT_IN_MANIFEST",
            "process": process_name,
            "similar_entries": similar,
            "note": "Process not in canonical manifest. Similar entries listed. Use web_lookup on Apple docs for research.",
        }, indent=2)

    return json.dumps({
        "status": "NOT_IN_MANIFEST",
        "process": process_name,
        "note": "Process not in canonical manifest. Use web_lookup on developer.apple.com or apple_support_search to research.",
    }, indent=2)


# --- Investigation memory tools (wrappers for tool registry) ---
from investigation import (
    write_notes as _write_notes,
    read_notes as _read_notes,
    save_evidence as _save_evidence,
    list_evidence as _list_evidence,
    read_evidence as _read_evidence,
    INVESTIGATIONS_DIR,
)


def recall_past_investigations(query: str) -> str:
    """Search closed investigations for relevant prior knowledge.

    No model needed — plain text search over investigation notes, evidence,
    and rulings. Returns matching snippets from past investigations so the
    30b doesn't have to re-investigate binaries she's already ruled on.
    """
    if not INVESTIGATIONS_DIR.exists():
        return "No past investigations found"

    query_lower = query.lower()
    query_terms = query_lower.split()
    matches = []

    for inv_dir in sorted(INVESTIGATIONS_DIR.iterdir(), reverse=True):
        if not inv_dir.is_dir():
            continue

        # Check meta
        meta_path = inv_dir / "meta.json"
        if not meta_path.exists():
            continue

        try:
            meta = json.loads(meta_path.read_text())
        except json.JSONDecodeError:
            continue

        # Skip active investigations — don't pollute current context
        if meta.get("status") == "active":
            continue

        # Search across notes, ruling, and meta
        searchable = ""

        notes_path = inv_dir / "notes.md"
        if notes_path.exists():
            searchable += notes_path.read_text()

        ruling_path = inv_dir / "ruling.json"
        if ruling_path.exists():
            searchable += ruling_path.read_text()

        searchable += json.dumps(meta)

        searchable_lower = searchable.lower()

        # Score by how many query terms match
        score = sum(1 for term in query_terms if term in searchable_lower)
        if score == 0:
            continue

        # Extract relevant snippet around first match
        for term in query_terms:
            idx = searchable_lower.find(term)
            if idx >= 0:
                start = max(0, idx - 150)
                end = min(len(searchable), idx + 300)
                snippet = searchable[start:end].strip()
                break
        else:
            snippet = searchable[:300]

        # Lightweight summary first — just the ruling headline
        # She can use read_investigation_notes with the ID if she wants the full thing
        ruling_summary = ""
        if ruling_path.exists():
            try:
                rul = json.loads(ruling_path.read_text())
                ruling_summary = rul.get("reasoning", "")[:150]
            except json.JSONDecodeError:
                pass

        matches.append({
            "investigation_id": meta.get("id"),
            "process": meta.get("process"),
            "path": meta.get("path"),
            "verdict": meta.get("final_verdict", "unknown"),
            "date": meta.get("started", "?")[:10],
            "ruling_summary": ruling_summary,
            "relevance_score": score,
            "hint": f"Use read_evidence(inv_id='{meta.get('id')}') for full details",
        })

        # Limit results
        if len(matches) >= 5:
            break

    if not matches:
        return f"No past investigations match '{query}'"

    # Sort by relevance
    matches.sort(key=lambda m: m["relevance_score"], reverse=True)
    return json.dumps(matches, indent=2)

# These get the inv_id injected by the agent loop in escalate.py
_current_inv_id = ""

def set_investigation_context(inv_id: str):
    """Set the current investigation ID for memory tools."""
    global _current_inv_id
    _current_inv_id = inv_id

def write_investigation_notes(content: str) -> str:
    """Write findings to your investigation notes. Use this to persist key discoveries."""
    if not _current_inv_id:
        return "ERROR: no active investigation"
    return _write_notes(_current_inv_id, content)

def read_investigation_notes() -> str:
    """Read your investigation notes. Use after context compaction to recall findings."""
    if not _current_inv_id:
        return "ERROR: no active investigation"
    return _read_notes(_current_inv_id)

def save_investigation_evidence(label: str, content: str) -> str:
    """Save a tool result as labeled evidence for the audit trail."""
    if not _current_inv_id:
        return "ERROR: no active investigation"
    return _save_evidence(_current_inv_id, label, content)

def list_investigation_evidence() -> str:
    """List all evidence files saved during this investigation."""
    if not _current_inv_id:
        return "ERROR: no active investigation"
    return _list_evidence(_current_inv_id)


def promote_priority(match_type: str, match_value: str, reason: str) -> str:
    """Teach the escalation queue that a pattern should be HIGH priority in the future.

    Call this when you discover something that should have been escalated
    faster. Next time a matching event comes in, it goes straight to HIGH.
    """
    if _escalation_queue is None:
        return "UNAVAILABLE: escalation queue not connected (one-shot mode?)"

    valid_types = ("path_prefix", "signing_id", "category", "process")
    if match_type not in valid_types:
        return f"INVALID match_type: '{match_type}'. Must be one of: {', '.join(valid_types)}"

    _escalation_queue.promote_priority({match_type: match_value}, reason)
    return f"PROMOTED: {match_type}={match_value} → HIGH priority. Reason: {reason}"


# ============================================================
# TOOL REGISTRY — used by the agent loop in escalate.py
# ============================================================

TOOLS = {
    "web_lookup": {
        "function": web_lookup,
        "description": "Fetch a page from an allowed documentation domain (Apple, Homebrew, osquery, MITRE, NVD, Objective-See, selected GitHub repos). Returns page content.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "The HTTPS URL to fetch (must be on allowlist)"}
            },
            "required": ["url"],
        },
    },
    "lookup_homebrew_formula": {
        "function": lookup_homebrew_formula,
        "description": "Look up a Homebrew formula by name. Returns description, homepage, dependencies. Use to identify what a binary installed via Homebrew actually is.",
        "parameters": {
            "type": "object",
            "properties": {
                "formula_name": {"type": "string", "description": "Homebrew formula name (e.g., 'ripgrep', 'osquery')"}
            },
            "required": ["formula_name"],
        },
    },
    "lookup_osquery_table": {
        "function": lookup_osquery_table,
        "description": "Look up an osquery table schema. Use to understand what fields mean in process events.",
        "parameters": {
            "type": "object",
            "properties": {
                "table_name": {"type": "string", "description": "osquery table name (e.g., 'process_events', 'processes')"}
            },
            "required": ["table_name"],
        },
    },
    "lookup_cve": {
        "function": lookup_cve,
        "description": "Look up a CVE by ID from the NVD/NIST database. Returns description, severity, CVSS score.",
        "parameters": {
            "type": "object",
            "properties": {
                "cve_id": {"type": "string", "description": "CVE identifier (e.g., 'CVE-2024-12345')"}
            },
            "required": ["cve_id"],
        },
    },
    "query_baseline": {
        "function": query_baseline,
        "description": "Query the local strix database for a binary's history. Returns: times seen, first/last seen, previous verdicts, typical parent process.",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string", "description": "Full path to the binary (e.g., '/usr/bin/curl')"}
            },
            "required": ["binary_path"],
        },
    },
    "check_known_signing_ids": {
        "function": check_known_signing_ids,
        "description": "Check a code signing ID against known-good (Apple, major vendors) and known-bad (macOS malware) lists.",
        "parameters": {
            "type": "object",
            "properties": {
                "signing_id": {"type": "string", "description": "The code signing identifier to check"}
            },
            "required": ["signing_id"],
        },
    },
    "system_inspect": {
        "function": system_inspect,
        "description": (
            "Run a read-only system inspection command via inspect.sh (runs as root). "
            "Use when enrichment data doesn't cover what you need — live process state, "
            "network connections, loaded services, kernel state, logs.\n\n"
            "Bulk commands (ps, netstat, lsof-net, etc.) are automatically filtered by "
            "a helper model to strip system noise — only lines relevant to your investigation "
            "are returned. Use 'focus' to steer the filter (e.g., 'connections to external IPs', "
            "'child processes spawned recently').\n\n"
            "SUBCOMMANDS (pass as 'subcommand'):\n"
            "  Process:     ps (all procs), ps-tree (parent→child), ps-pid <PID>, proc-fds <PID>\n"
            "  Network:     netstat, lsof-net, lsof-listen (listening ports), lsof-pid-net <PID>\n"
            "  LaunchD:     launchctl-list, launchctl-info <label>, launchagents, plist-read <path>\n"
            "  Files:       file-info <path>, codesign <path>, codesign-verify <path>, entitlements <path>\n"
            "  Kernel:      kextstat, sysctl [key], system-profiler <SPDataType>\n"
            "  Logs:        log-show [minutes] [predicate]\n"
            "  Network cfg: dns-config, network-config, arp-table, routes\n"
            "  Users:       who, last-logins, dscl-users\n\n"
            "Pass additional arguments (PID, path, label) in 'args' array."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "subcommand": {
                    "type": "string",
                    "description": "Inspection subcommand (e.g., 'ps-tree', 'lsof-pid-net', 'codesign')",
                },
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional arguments for the subcommand (e.g., ['1234'] for ps-pid, ['/usr/bin/curl'] for codesign)",
                },
                "focus": {
                    "type": "string",
                    "description": "Steering instruction for the noise filter on bulk commands (e.g., 'network connections to non-Apple IPs', 'processes spawned from /tmp'). Ignored for single-target commands.",
                },
            },
            "required": ["subcommand"],
        },
    },
    "apple_support_search": {
        "function": apple_support_search,
        "description": "Search Apple support documentation. Use to understand what an Apple binary or daemon does.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query (e.g., 'identityservicesd', 'coreaudiod purpose')"}
            },
            "required": ["query"],
        },
    },
    "objective_see_malware_check": {
        "function": objective_see_malware_check,
        "description": "Check Objective-See's macOS malware catalog for a binary name. Patrick Wardle maintains the most comprehensive macOS malware database.",
        "parameters": {
            "type": "object",
            "properties": {
                "binary_name": {"type": "string", "description": "Binary name to check (e.g., 'WindTail', 'Shlayer')"}
            },
            "required": ["binary_name"],
        },
    },
    "lookup_virustotal_hash": {
        "function": lookup_virustotal_hash,
        "description": "Look up a SHA256 hash on VirusTotal. Returns detection ratio and vendor verdicts. Use when you have a binary hash from forensic enrichment.",
        "parameters": {
            "type": "object",
            "properties": {
                "sha256": {"type": "string", "description": "SHA256 hash of the binary"}
            },
            "required": ["sha256"],
        },
    },
    "map_mitre_technique": {
        "function": map_mitre_technique,
        "description": "Map an observed behavior to MITRE ATT&CK techniques for macOS. Fast local lookup — no network call. Use keywords like 'shell', 'suid', 'launchagent', 'keychain', 'reverse_shell', 'unsigned', etc.",
        "parameters": {
            "type": "object",
            "properties": {
                "behavior": {"type": "string", "description": "Behavior description or keywords (e.g., 'unsigned binary in tmp executing shell')"}
            },
            "required": ["behavior"],
        },
    },
    "request_domain_access": {
        "function": request_domain_access,
        "description": "Request access to a domain not on the allowlist. Provide the FULL DOMAIN (e.g., 'example.com') and a clear reason. The operator reviews and approves/denies. Do NOT block your analysis waiting for approval.",
        "parameters": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to request (e.g., 'example.com', NOT a full URL)"},
                "reason": {"type": "string", "description": "Why you need this domain — be specific"},
            },
            "required": ["domain", "reason"],
        },
    },
    # --- Canonical manifest (Apple ground truth) ---
    "check_manifest": {
        "function": check_manifest,
        "description": "Look up a process in the canonical macOS manifest. Returns what Apple says this process SHOULD do: expected path, parent, UID, signing ID, network behavior. If the process deviates from this spec, it doesn't matter what the baseline says — it's wrong.",
        "parameters": {
            "type": "object",
            "properties": {
                "process_name": {"type": "string", "description": "Process name (e.g., 'cupsd', 'identityservicesd', 'launchctl')"}
            },
            "required": ["process_name"],
        },
    },
    # --- Prior knowledge (no model needed — plain text search) ---
    "recall_past_investigations": {
        "function": recall_past_investigations,
        "description": "Search closed investigations for prior knowledge about a binary, path, or behavior. Plain text search — no model needed. Returns matching snippets from past rulings and notes. Use FIRST to avoid re-investigating something already ruled on.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query — binary name, path, signing ID, or behavior (e.g., 'osqueryd', '/usr/local/bin/node', 'unsigned tmp execution')"}
            },
            "required": ["query"],
        },
    },
    # --- Investigation memory ---
    "write_investigation_notes": {
        "function": write_investigation_notes,
        "description": "Write findings to your investigation notes on disk. Persists across context compaction. Use to save key discoveries, hypotheses, and evidence summaries.",
        "parameters": {
            "type": "object",
            "properties": {
                "content": {"type": "string", "description": "Markdown-formatted notes to append"}
            },
            "required": ["content"],
        },
    },
    "read_investigation_notes": {
        "function": read_investigation_notes,
        "description": "Read your investigation notes from disk. Use at the start of a continued investigation to recall previous findings.",
        "parameters": {
            "type": "object",
            "properties": {},
        },
    },
    "save_investigation_evidence": {
        "function": save_investigation_evidence,
        "description": "Save a tool result or artifact as labeled evidence. Persisted to disk for the audit trail. Label should be descriptive (e.g., 'vt-hash-result', 'baseline-check').",
        "parameters": {
            "type": "object",
            "properties": {
                "label": {"type": "string", "description": "Short label for this evidence (used as filename)"},
                "content": {"type": "string", "description": "The evidence content to save"},
            },
            "required": ["label", "content"],
        },
    },
    "list_investigation_evidence": {
        "function": list_investigation_evidence,
        "description": "List all evidence files saved during this investigation.",
        "parameters": {
            "type": "object",
            "properties": {},
        },
    },
    # --- Priority feedback (teach the classifier what matters) ---
    "promote_priority": {
        "function": promote_priority,
        "description": (
            "Teach the escalation queue that a pattern should be HIGH priority in the future. "
            "Call this when you discover something that SHOULD have been flagged as urgent but wasn't. "
            "Next time a matching event arrives, it skips the LOW queue and goes straight to HIGH.\n\n"
            "match_type options:\n"
            "  path_prefix  — e.g., '/tmp/', '/var/tmp/staging/' (any binary under this path)\n"
            "  signing_id   — e.g., 'com.evil.corp' (specific signing identity)\n"
            "  category     — e.g., 'reverse_shell', 'credential_theft' (behavior category)\n"
            "  process      — e.g., 'cryptominer' (exact process name)\n\n"
            "This persists across restarts. Use it to make the system smarter over time."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "match_type": {
                    "type": "string",
                    "description": "What to match on: 'path_prefix', 'signing_id', 'category', or 'process'",
                },
                "match_value": {
                    "type": "string",
                    "description": "The value to match (e.g., '/tmp/', 'com.evil.corp', 'reverse_shell')",
                },
                "reason": {
                    "type": "string",
                    "description": "Why this should be HIGH priority — be specific, this is logged",
                },
            },
            "required": ["match_type", "match_value", "reason"],
        },
    },
}


def get_ollama_tool_definitions() -> list[dict]:
    """Return tool definitions in Ollama's tool-calling format."""
    return [
        {
            "type": "function",
            "function": {
                "name": name,
                "description": tool["description"],
                "parameters": tool["parameters"],
            },
        }
        for name, tool in TOOLS.items()
    ]


def execute_tool(name: str, arguments: dict) -> str:
    """Execute a tool by name with the given arguments."""
    tool = TOOLS.get(name)
    if not tool:
        return f"UNKNOWN_TOOL: {name}"
    try:
        func = tool["function"]
        return func(**arguments)
    except Exception as e:
        log.error("Tool %s failed: %s", name, e, exc_info=True)
        return f"TOOL_ERROR: {type(e).__name__}: {e}"
