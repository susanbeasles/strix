#!/bin/zsh
# PURPOSE: Read-only system inspection for the watchdog 30b model.
#          This script is the ONLY thing the sudoers entry allows.
#          It whitelists specific read-only subcommands. No writes. No modifications.
#
# SUDOERS ENTRY (add via visudo):
#   avespoli ALL=(root) NOPASSWD: /Users/avespoli/code/tonys-toolbox/domains/detect/watchdog/inspect.sh *
#
# USAGE: inspect.sh <subcommand> [args...]
#        Called by watchdog tools.py — not intended for direct use.

set -euo pipefail

SUBCMD="${1:-help}"
shift 2>/dev/null || true

case "$SUBCMD" in

  # --- Process inspection ---
  ps)
    # All processes, full detail
    ps aux
    ;;

  ps-tree)
    # Process tree showing parent→child relationships
    ps -axo pid,ppid,user,uid,gid,pgid,command
    ;;

  ps-pid)
    # Detailed info for a specific PID
    [[ -z "${1:-}" ]] && { echo "Usage: inspect.sh ps-pid <PID>"; exit 1; }
    ps -p "$1" -o pid,ppid,user,uid,gid,pgid,nice,vsz,rss,etime,command
    ;;

  proc-fds)
    # Open file descriptors for a PID
    [[ -z "${1:-}" ]] && { echo "Usage: inspect.sh proc-fds <PID>"; exit 1; }
    lsof -p "$1" 2>/dev/null || echo "Process $1 not found or no open files"
    ;;

  # --- Network inspection ---
  netstat)
    # All network connections
    netstat -an
    ;;

  lsof-net)
    # All network-connected processes
    lsof -i -P -n 2>/dev/null
    ;;

  lsof-listen)
    # Listening ports only
    lsof -i -P -n 2>/dev/null | grep LISTEN
    ;;

  lsof-pid-net)
    # Network connections for a specific PID
    [[ -z "${1:-}" ]] && { echo "Usage: inspect.sh lsof-pid-net <PID>"; exit 1; }
    lsof -i -P -n -p "$1" 2>/dev/null || echo "Process $1 has no network connections"
    ;;

  # --- LaunchAgent/Daemon inspection ---
  launchctl-list)
    # All loaded services
    launchctl list
    ;;

  launchctl-info)
    # Detailed info for a service
    [[ -z "${1:-}" ]] && { echo "Usage: inspect.sh launchctl-info <label>"; exit 1; }
    launchctl print "system/$1" 2>/dev/null || launchctl print "gui/$(id -u)/$1" 2>/dev/null || echo "Service $1 not found"
    ;;

  launchagents)
    # List all LaunchAgent plists and their state
    echo "=== System LaunchAgents ==="
    ls -la /Library/LaunchAgents/ 2>/dev/null || echo "(none)"
    echo ""
    echo "=== User LaunchAgents ==="
    ls -la ~/Library/LaunchAgents/ 2>/dev/null || echo "(none)"
    echo ""
    echo "=== System LaunchDaemons ==="
    ls -la /Library/LaunchDaemons/ 2>/dev/null || echo "(none)"
    ;;

  plist-read)
    # Read a plist file (read-only)
    [[ -z "${1:-}" ]] && { echo "Usage: inspect.sh plist-read <path>"; exit 1; }
    # Block paths outside expected locations
    case "$1" in
      /Library/Launch*|/System/Library/Launch*|~/Library/Launch*)
        plutil -p "$1" 2>/dev/null || echo "Cannot read $1"
        ;;
      *)
        echo "BLOCKED: plist-read only allows LaunchAgent/Daemon paths"
        exit 1
        ;;
    esac
    ;;

  # --- File metadata (read-only, no content) ---
  file-info)
    # File metadata: permissions, owner, size, timestamps, extended attrs
    [[ -z "${1:-}" ]] && { echo "Usage: inspect.sh file-info <path>"; exit 1; }
    ls -la@ "$1" 2>/dev/null
    echo "---"
    stat -f "mode=%Sp size=%z uid=%u gid=%g mtime=%m ctime=%c" "$1" 2>/dev/null
    echo "---"
    xattr -l "$1" 2>/dev/null || echo "(no xattrs)"
    ;;

  codesign)
    # Full code signing verification
    [[ -z "${1:-}" ]] && { echo "Usage: inspect.sh codesign <path>"; exit 1; }
    codesign -dvvv "$1" 2>&1
    ;;

  codesign-verify)
    # Strict verification (checks integrity, not just identity)
    [[ -z "${1:-}" ]] && { echo "Usage: inspect.sh codesign-verify <path>"; exit 1; }
    codesign --verify --verbose=4 "$1" 2>&1
    ;;

  entitlements)
    # Show entitlements for a binary
    [[ -z "${1:-}" ]] && { echo "Usage: inspect.sh entitlements <path>"; exit 1; }
    codesign -d --entitlements - "$1" 2>&1
    ;;

  # --- Kernel and system state ---
  kextstat)
    # Loaded kernel extensions
    kextstat 2>/dev/null || kmutil showloaded 2>/dev/null
    ;;

  sysctl)
    # Kernel parameters (read-only)
    [[ -z "${1:-}" ]] && { sysctl -a 2>/dev/null; exit 0; }
    sysctl "$@" 2>/dev/null
    ;;

  system-profiler)
    # System profiler (specific data type)
    [[ -z "${1:-}" ]] && { echo "Usage: inspect.sh system-profiler <SPDataType>"; exit 1; }
    system_profiler "$1" 2>/dev/null
    ;;

  # --- Log inspection ---
  log-show)
    # Show system logs (last N minutes, specific subsystem)
    MINUTES="${1:-5}"
    PREDICATE="${2:-}"
    if [[ -n "$PREDICATE" ]]; then
      log show --last "${MINUTES}m" --predicate "$PREDICATE" --style compact 2>/dev/null | tail -200
    else
      log show --last "${MINUTES}m" --style compact 2>/dev/null | tail -200
    fi
    ;;

  # --- DNS and network config ---
  dns-config)
    scutil --dns 2>/dev/null
    ;;

  network-config)
    scutil --proxy 2>/dev/null
    echo "==="
    scutil --nwi 2>/dev/null
    ;;

  arp-table)
    arp -a 2>/dev/null
    ;;

  routes)
    netstat -rn 2>/dev/null
    ;;

  # --- User and auth state ---
  who)
    who -a 2>/dev/null
    ;;

  last-logins)
    last -20 2>/dev/null
    ;;

  dscl-users)
    # List local user accounts
    dscl . -list /Users UniqueID 2>/dev/null
    ;;

  # --- Help ---
  help|--help|-h)
    echo "watchdog inspect — read-only system inspection"
    echo ""
    echo "Process:     ps, ps-tree, ps-pid <PID>, proc-fds <PID>"
    echo "Network:     netstat, lsof-net, lsof-listen, lsof-pid-net <PID>"
    echo "LaunchD:     launchctl-list, launchctl-info <label>, launchagents, plist-read <path>"
    echo "Files:       file-info <path>, codesign <path>, codesign-verify <path>, entitlements <path>"
    echo "Kernel:      kextstat, sysctl [key], system-profiler <type>"
    echo "Logs:        log-show [minutes] [predicate]"
    echo "Network cfg: dns-config, network-config, arp-table, routes"
    echo "Users:       who, last-logins, dscl-users"
    ;;

  *)
    echo "Unknown subcommand: $SUBCMD"
    echo "Run 'inspect.sh help' for available commands"
    exit 1
    ;;
esac
