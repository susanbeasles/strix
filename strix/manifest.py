"""Canonical macOS process manifest — how Apple says things SHOULD work.

This is NOT based on observed behavior. This is ground truth from Apple
documentation, man pages, and known macOS architecture.

If the machine's baseline says "cupsd is always spawned by node" and the
manifest says "cupsd should only be spawned by launchd" — the baseline is
lying. The machine may already be compromised.

Two-layer detection:
  1. Baseline deviation:  "this hasn't happened before on this machine"
  2. Manifest deviation:  "this shouldn't happen on ANY macOS machine"

Layer 2 catches living-off-the-land attacks where trusted Apple processes
are being misused, proxied, spoofed, or hijacked — even if the machine's
baseline has normalized that behavior because the compromise predates it.
"""

import json
import logging
from dataclasses import dataclass

log = logging.getLogger("strix.manifest")


@dataclass
class ProcessSpec:
    """Canonical specification for how a macOS process SHOULD behave."""
    name: str                           # Binary name
    path: str                           # Expected full path
    expected_parents: list[str]         # Who should spawn this
    expected_uid: int | None = None     # Expected UID (0=root, 501=user)
    expected_signing_id: str = ""       # Expected code signing identity
    platform_binary: bool = True        # Should be Apple-signed platform binary?
    network: str = "none"               # "none", "listen", "connect", "both"
    expected_ports: list[int] | None = None  # Expected listening ports
    description: str = ""               # What this process does
    entitlements: list[str] | None = None  # Expected entitlements
    should_be_running: str = "always"   # "always", "on-demand", "never", "user-triggered"


# ============================================================
# CANONICAL macOS PROCESS MANIFEST
# ============================================================
# Sources: Apple developer docs, man pages, launchd plists,
#          macOS security research (Patrick Wardle, Objective-See)
#
# This is NOT exhaustive. It covers critical system services and
# commonly-abused processes. The 30b model can use web_lookup
# to research processes not in this manifest.

MANIFEST: dict[str, ProcessSpec] = {}


def _register(*specs: ProcessSpec):
    for spec in specs:
        MANIFEST[spec.name] = spec


# --- Core system daemons (always root, always launchd) ---
_register(
    ProcessSpec(
        name="launchd",
        path="/sbin/launchd",
        expected_parents=["kernel_task"],
        expected_uid=0,
        expected_signing_id="com.apple.xpc.launchd",
        network="none",
        description="Process supervisor. PID 1. Parent of all user-space processes.",
        should_be_running="always",
    ),
    ProcessSpec(
        name="kernelmanagerd",
        path="/usr/libexec/kernelmanagerd",
        expected_parents=["launchd"],
        expected_uid=0,
        expected_signing_id="com.apple.kernelmanagerd",
        network="none",
        description="Manages kernel extensions and system extensions.",
        should_be_running="always",
    ),
    ProcessSpec(
        name="syspolicyd",
        path="/usr/libexec/syspolicyd",
        expected_parents=["launchd"],
        expected_uid=0,
        expected_signing_id="com.apple.syspolicyd",
        network="connect",
        description="System policy daemon — Gatekeeper, notarization checks. Connects to Apple for verification.",
        should_be_running="always",
    ),
    ProcessSpec(
        name="trustd",
        path="/usr/libexec/trustd",
        expected_parents=["launchd"],
        expected_uid=0,
        expected_signing_id="com.apple.trustd",
        network="connect",
        description="Certificate trust evaluation. Connects to Apple for OCSP/CRL.",
        should_be_running="always",
    ),
    ProcessSpec(
        name="securityd",
        path="/usr/sbin/securityd",
        expected_parents=["launchd"],
        expected_uid=0,
        expected_signing_id="com.apple.securityd",
        network="none",
        description="Security framework daemon. Manages keychains, code signing, crypto.",
        should_be_running="always",
    ),
    ProcessSpec(
        name="opendirectoryd",
        path="/usr/libexec/opendirectoryd",
        expected_parents=["launchd"],
        expected_uid=0,
        expected_signing_id="com.apple.opendirectoryd",
        network="connect",
        description="Directory services (LDAP, AD, local accounts). SHOULD NOT listen on network.",
        should_be_running="always",
    ),
)

# --- Network services ---
_register(
    ProcessSpec(
        name="mDNSResponder",
        path="/usr/sbin/mDNSResponder",
        expected_parents=["launchd"],
        expected_uid=65,  # _mdnsresponder
        expected_signing_id="com.apple.mDNSResponder",
        network="both",
        expected_ports=[5353],  # mDNS only
        description="Bonjour/mDNS. Should ONLY listen on 5353/UDP. Any other port is suspicious.",
        should_be_running="always",
    ),
    ProcessSpec(
        name="configd",
        path="/usr/libexec/configd",
        expected_parents=["launchd"],
        expected_uid=0,
        expected_signing_id="com.apple.configd",
        network="none",
        description="System configuration daemon (network interfaces, DNS, proxies). Should NOT make network connections itself.",
        should_be_running="always",
    ),
    ProcessSpec(
        name="networkd",
        path="/usr/libexec/networkd",
        expected_parents=["launchd"],
        expected_uid=0,
        expected_signing_id="com.apple.networkd",
        network="both",
        description="Network stack daemon. Handles TCP/UDP connections for the system.",
        should_be_running="always",
    ),
)

# --- Commonly abused services ---
_register(
    ProcessSpec(
        name="cupsd",
        path="/usr/sbin/cupsd",
        expected_parents=["launchd"],
        expected_uid=0,
        expected_signing_id="com.apple.cupsd",
        network="listen",
        expected_ports=[631],
        description="CUPS print daemon. Listens on 631 ONLY. Should NOT make outbound connections. If it's connecting to anything other than a printer, that's wrong.",
        should_be_running="on-demand",
    ),
    ProcessSpec(
        name="identityservicesd",
        path="/usr/libexec/identityservicesd",
        expected_parents=["launchd"],
        expected_uid=501,  # Current user
        expected_signing_id="com.apple.identityservicesd",
        network="connect",
        description="iMessage, FaceTime, Handoff identity services. Connects to Apple push servers. Should NOT listen on local ports or proxy traffic.",
        should_be_running="always",
    ),
    ProcessSpec(
        name="rapportd",
        path="/usr/libexec/rapportd",
        expected_parents=["launchd"],
        expected_uid=501,
        expected_signing_id="com.apple.rapportd",
        network="both",
        description="Device-to-device communication (AirDrop, Handoff). ONLY talks to local network peers via mDNS. Any internet traffic is wrong.",
        should_be_running="always",
    ),
    ProcessSpec(
        name="sharingd",
        path="/usr/libexec/sharingd",
        expected_parents=["launchd"],
        expected_uid=501,
        expected_signing_id="com.apple.sharingd",
        network="both",
        description="AirDrop, Nearby Sharing. Local network only. Should NOT make internet connections.",
        should_be_running="always",
    ),
    ProcessSpec(
        name="cloudd",
        path="/usr/libexec/cloudd",
        expected_parents=["launchd"],
        expected_uid=501,
        expected_signing_id="com.apple.cloudd",
        network="connect",
        description="CloudKit daemon. Connects to iCloud servers. Should NOT listen on any port.",
        should_be_running="always",
    ),
    ProcessSpec(
        name="bird",
        path="/usr/libexec/bird",
        expected_parents=["launchd"],
        expected_uid=501,
        expected_signing_id="com.apple.bird",
        network="connect",
        description="iCloud Drive sync daemon. Connects to Apple. Should NOT listen or accept connections.",
        should_be_running="on-demand",
    ),
)

# --- Shell and scripting ---
_register(
    ProcessSpec(
        name="bash",
        path="/bin/bash",
        expected_parents=["zsh", "bash", "Terminal", "sshd", "login", "su", "sudo", "launchd", "screen", "tmux"],
        expected_uid=None,  # Can run as any user
        expected_signing_id="com.apple.bash",
        platform_binary=True,
        network="none",
        description="Bourne-again shell. Should NOT make network connections directly. If bash is connecting to the network, something is using it as a reverse shell or C2 channel.",
        should_be_running="user-triggered",
    ),
    ProcessSpec(
        name="zsh",
        path="/bin/zsh",
        expected_parents=["zsh", "bash", "Terminal", "sshd", "login", "su", "sudo", "launchd", "screen", "tmux", "iTerm2"],
        expected_uid=None,
        expected_signing_id="com.apple.zsh",
        platform_binary=True,
        network="none",
        description="Z shell. Same rules as bash — should NOT touch the network.",
        should_be_running="user-triggered",
    ),
    ProcessSpec(
        name="osascript",
        path="/usr/bin/osascript",
        expected_parents=["bash", "zsh", "sh", "Terminal"],
        expected_uid=None,
        expected_signing_id="com.apple.osascript",
        platform_binary=True,
        network="none",
        description="AppleScript runner. Powerful — can control GUI apps, read files, send messages. If spawned by anything unexpected, that's a red flag.",
        should_be_running="user-triggered",
    ),
    ProcessSpec(
        name="python3",
        path="/opt/homebrew/bin/python3",
        expected_parents=["bash", "zsh", "sh", "launchd", "cron"],
        expected_uid=None,
        expected_signing_id="",  # Homebrew, ad-hoc signed
        platform_binary=False,
        network="connect",  # Python scripts legitimately make connections
        description="Python interpreter. Commonly abused for reverse shells and C2. Parent chain matters more than the binary itself.",
        should_be_running="user-triggered",
    ),
)

# --- SSH and remote access ---
_register(
    ProcessSpec(
        name="sshd",
        path="/usr/sbin/sshd",
        expected_parents=["launchd"],
        expected_uid=0,
        expected_signing_id="com.apple.sshd",
        platform_binary=True,
        network="listen",
        expected_ports=[22],
        description="SSH daemon. Should ONLY be running if Remote Login is enabled. If running unexpectedly, could be an attacker's persistence mechanism.",
        should_be_running="on-demand",
    ),
    ProcessSpec(
        name="ssh",
        path="/usr/bin/ssh",
        expected_parents=["bash", "zsh", "sh", "Terminal", "sshd"],
        expected_uid=None,
        expected_signing_id="com.apple.ssh",
        platform_binary=True,
        network="connect",
        description="SSH client. Normal when user-initiated. Suspicious when spawned by a daemon or script without user context.",
        should_be_running="user-triggered",
    ),
)

# --- TCC and privacy-sensitive ---
_register(
    ProcessSpec(
        name="tccd",
        path="/System/Library/PrivateFrameworks/TCC.framework/Support/tccd",
        expected_parents=["launchd"],
        expected_uid=0,
        expected_signing_id="com.apple.tccd",
        network="none",
        description="Transparency, Consent, and Control daemon. Manages app permissions. Should NEVER make network connections or be spawned by anything other than launchd.",
        should_be_running="always",
    ),
    ProcessSpec(
        name="tccutil",
        path="/usr/bin/tccutil",
        expected_parents=["bash", "zsh", "sh"],
        expected_uid=None,
        expected_signing_id="com.apple.tccutil",
        platform_binary=True,
        network="none",
        description="TCC database utility. Can reset privacy permissions. If called programmatically (not by user in terminal), investigate immediately.",
        should_be_running="user-triggered",
    ),
)

# --- LaunchServices and persistence ---
_register(
    ProcessSpec(
        name="launchctl",
        path="/bin/launchctl",
        expected_parents=["bash", "zsh", "sh", "Terminal", "launchd"],
        expected_uid=None,
        expected_signing_id="com.apple.launchctl",
        platform_binary=True,
        network="none",
        description="LaunchAgent/Daemon control. Loading new agents is a persistence mechanism. Any non-interactive launchctl load/bootstrap should be scrutinized.",
        should_be_running="user-triggered",
    ),
)


# ============================================================
# MANIFEST COMPARISON ENGINE
# ============================================================

def check_against_manifest(event: dict) -> dict | None:
    """Compare a process event against the canonical manifest.

    Returns a deviation report if the process violates its spec,
    or None if the process isn't in the manifest or passes all checks.
    """
    process_name = event.get("process", "")
    spec = MANIFEST.get(process_name)

    if not spec:
        return None  # Not in manifest — can't check

    deviations = []

    # Check path
    if spec.path and event.get("path") and event["path"] != spec.path:
        deviations.append({
            "check": "wrong_path",
            "expected": spec.path,
            "actual": event["path"],
            "severity": "critical",
            "explanation": f"{process_name} should live at {spec.path}. Found at {event['path']}. Possible masquerading or trojan.",
        })

    # Check signing ID
    if spec.expected_signing_id and event.get("signing_id"):
        if event["signing_id"] != spec.expected_signing_id:
            deviations.append({
                "check": "wrong_signing_id",
                "expected": spec.expected_signing_id,
                "actual": event["signing_id"],
                "severity": "critical",
                "explanation": f"{process_name} should be signed as {spec.expected_signing_id}. Actually signed as {event['signing_id']}. Binary may be replaced or spoofed.",
            })

    # Check platform binary flag
    if spec.platform_binary and not event.get("platform_binary"):
        deviations.append({
            "check": "not_platform_binary",
            "expected": "Apple platform binary",
            "actual": "NOT platform binary",
            "severity": "high",
            "explanation": f"{process_name} should be an Apple platform binary (kernel-verified). This copy is not. It may have been replaced.",
        })

    # Check UID
    if spec.expected_uid is not None and event.get("uid") is not None:
        if event["uid"] != spec.expected_uid:
            deviations.append({
                "check": "wrong_uid",
                "expected": spec.expected_uid,
                "actual": event["uid"],
                "severity": "high",
                "explanation": f"{process_name} should run as UID {spec.expected_uid}. Running as UID {event['uid']}. Privilege level is wrong.",
            })

    # Check parent process
    if spec.expected_parents and event.get("parent_pid"):
        # We can't easily check parent name from just the event,
        # but we can flag if the event has parent info from enrichment
        pass  # Parent check happens in correlator with DB access

    if not deviations:
        return None

    return {
        "process": process_name,
        "path": event.get("path"),
        "spec": {
            "description": spec.description,
            "expected_path": spec.path,
            "expected_uid": spec.expected_uid,
            "expected_signing_id": spec.expected_signing_id,
            "expected_parents": spec.expected_parents,
            "network": spec.network,
            "expected_ports": spec.expected_ports,
        },
        "deviations": deviations,
        "max_severity": max(d["severity"] for d in deviations),
    }


def check_parent_against_manifest(process_name: str, parent_name: str) -> dict | None:
    """Check if a parent→child relationship matches the manifest.

    This is the "Apple says this shouldn't happen" check.
    """
    spec = MANIFEST.get(process_name)
    if not spec or not spec.expected_parents:
        return None

    if parent_name in spec.expected_parents:
        return None  # Expected parent — all good

    return {
        "process": process_name,
        "parent": parent_name,
        "expected_parents": spec.expected_parents,
        "severity": "high",
        "explanation": (
            f"According to macOS architecture, {process_name} should be spawned by "
            f"{', '.join(spec.expected_parents)}. It was spawned by {parent_name}. "
            f"This is NOT normal macOS behavior regardless of what this machine's "
            f"baseline shows. {spec.description}"
        ),
    }


def get_spec(process_name: str) -> dict | None:
    """Get the canonical spec for a process (for the 30b model's reference)."""
    spec = MANIFEST.get(process_name)
    if not spec:
        return None
    return {
        "name": spec.name,
        "expected_path": spec.path,
        "expected_parents": spec.expected_parents,
        "expected_uid": spec.expected_uid,
        "expected_signing_id": spec.expected_signing_id,
        "platform_binary": spec.platform_binary,
        "network_behavior": spec.network,
        "expected_ports": spec.expected_ports,
        "description": spec.description,
        "should_be_running": spec.should_be_running,
    }
