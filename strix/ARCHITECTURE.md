# Watchdog — ML-Powered Process Anomaly Detection

## Philosophy

Watchdog doesn't care if an attack has been discovered before. It doesn't need a CVE, a hash, a signature, or a YARA rule. It works on one principle:

> **"This shouldn't do that."**

If a process does something it has never done before — spawns an unexpected child, talks to the network when it never has, runs as root when it's always been user-space, appears in a location it's never been — that's interesting. If multiple "interesting" things happen in sequence, that's a pattern. And the 30b model gets the full picture to decide: is this a threat no one has ever documented, or is it just Tuesday?

The known-attack chains are a bonus, not the core. The core is behavioral deviation detection on **this machine, this user, this baseline**.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        osquery (EndpointSecurity)                   │
│                                                                     │
│  Kernel-level process event monitoring via Apple ES framework       │
│  Every exec, fork, exit → /var/run/watchdog/results.log (JSONL)    │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         INGESTION LAYER                             │
│                                                                     │
│  parser.py          Tails osquery results log, extracts process     │
│                     events, handles log rotation                    │
│                                                                     │
│  enrich.py          Pre-classification forensics:                   │
│                     • Live PID verification (ps)                    │
│                     • Code signing chain (codesign -dvvv)           │
│                     • File permissions, SUID/SGID bits              │
│                     • SHA256 hash                                   │
│                     • Homebrew bottle detection                     │
│                     • Suspicious location flags (/tmp, hidden dirs) │
│                                                                     │
│  queue.py           Priority queue with dedup + fast-path cache     │
│                     Unsigned/unknown → top priority                 │
│                     Apple platform binaries → bottom                │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
┌────────────────────────┐  ┌─────────────────────────────────────────┐
│    4b FAST TRIAGE      │  │              SQLite DB                   │
│                        │  │                                         │
│  Model: qwen3:4b       │  │  process_events   Raw event log         │
│  Local Ollama          │  │  baselines         Learned normal        │
│  ~100ms per event      │  │  verdicts          All classification    │
│                        │  │                    results               │
│  Rules:                │  │                                         │
│  • Apple + signed =    │  │  This IS the behavioral profile.        │
│    probably normal     │  │  "What does normal look like on         │
│  • Unsigned = flag     │  │   THIS machine?"                        │
│  • /tmp exec = alert   │  │                                         │
│  • SUID non-system =   │  │  Every binary: how many times seen,     │
│    alert               │  │  who usually spawns it, what UID,       │
│  • Reverse shell       │  │  what signing ID, what verdict.         │
│    patterns = alert    │  └─────────────────────────────────────────┘
│                        │                    │
│  Output: JSON verdict  │                    │
│  normal/suspicious/    │                    │
│  alert + risk score    │                    │
└───────────┬────────────┘                    │
            │                                 │
            │  If suspicious/alert:           │
            ▼                                 │
┌─────────────────────────────────────────────┴───────────────────────┐
│                     30b ESCALATION AGENT                            │
│                                                                     │
│  Model: qwen3-coder:30b (Ollama, local, tool-calling)              │
│  Budget: 6 tool calls, 120 seconds, 4 rounds                      │
│                                                                     │
│  SHE INVESTIGATES. Not a classifier — an analyst.                  │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │                     HER TOOLBELT (16 tools)                │    │
│  │                                                            │    │
│  │  LOCAL (instant, no network):                              │    │
│  │  ├─ recall_past_investigations  Search prior rulings       │    │
│  │  ├─ query_baseline              Machine's behavioral DB    │    │
│  │  ├─ check_known_signing_ids     Vendor allow/deny lists    │    │
│  │  └─ map_mitre_technique         Behavior → ATT&CK         │    │
│  │                                                            │    │
│  │  NETWORK (rate-limited, allowlisted domains only):         │    │
│  │  ├─ web_lookup                  Apple, Homebrew, osquery,  │    │
│  │  │                              MITRE, Objective-See, NVD, │    │
│  │  │                              selected GitHub repos      │    │
│  │  ├─ lookup_homebrew_formula     What IS this binary?       │    │
│  │  ├─ lookup_virustotal_hash      SHA256 reputation          │    │
│  │  ├─ lookup_cve                  CVE details from NVD       │    │
│  │  ├─ apple_support_search        Apple documentation        │    │
│  │  ├─ objective_see_malware_check Patrick Wardle's DB        │    │
│  │  └─ lookup_osquery_table        Event schema reference     │    │
│  │                                                            │    │
│  │  INVESTIGATION MEMORY (persists to disk):                  │    │
│  │  ├─ write_investigation_notes   Persist findings           │    │
│  │  ├─ read_investigation_notes    Recall after compaction    │    │
│  │  ├─ save_investigation_evidence Audit trail artifacts      │    │
│  │  └─ list_investigation_evidence What's been saved          │    │
│  │                                                            │    │
│  │  ADMIN:                                                    │    │
│  │  └─ request_domain_access       Ask operator for new domain│    │
│  └────────────────────────────────────────────────────────────┘    │
│                                                                     │
│  Investigation lifecycle:                                           │
│  • Fresh context per event (no old baggage)                        │
│  • Notes + evidence persist to disk for audit                      │
│  • Past rulings searchable but NOT auto-loaded                     │
│  • Lightweight recall: headline first, full file only if relevant  │
│                                                                     │
│  Output: ruling + reasoning + evidence + ATT&CK mapping            │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               │  Ruling feeds back to DB
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         CORRELATOR                                  │
│                                                                     │
│  Runs every poll cycle. Two modes:                                 │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  KNOWN CHAINS (rule-based, ATT&CK-mapped)                    │ │
│  │                                                               │ │
│  │  7 predefined attack patterns:                                │ │
│  │  • persistence_install        Recon → plist → launchctl       │ │
│  │  • credential_harvest_exfil   Keychain → curl POST            │ │
│  │  • defense_evasion_execution  Drop to /tmp → chmod → execute  │ │
│  │  • reverse_shell              Shell + /dev/tcp + mkfifo       │ │
│  │  • discovery_spray            Automated recon burst           │ │
│  │  • privilege_escalation       SUID discovery → SUID exec      │ │
│  │  • ssh_lateral_movement       SSH key find → outbound SSH     │ │
│  │                                                               │ │
│  │  Each chain: time window, min stages, cooldown, MITRE tactic  │ │
│  │  Match → escalate to 30b with FULL sequence context           │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │  ANOMALY DETECTION (behavioral, no signatures)                │ │
│  │                                                               │ │
│  │  This is the part that catches what nobody has ever seen.     │ │
│  │                                                               │ │
│  │  It doesn't know what attacks look like.                      │ │
│  │  It knows what YOUR MACHINE looks like.                       │ │
│  │  When reality deviates from that — it flags it.               │ │
│  │                                                               │ │
│  │  Detections:                                                  │ │
│  │                                                               │ │
│  │  NOVEL BINARY BURST                                           │ │
│  │  "3 binaries I've never seen before, all within 10 minutes"   │ │
│  │  → Something is deploying tools. Staging? Recon? Dropper?     │ │
│  │                                                               │ │
│  │  WRONG PARENT                                                 │ │
│  │  "curl was always spawned by zsh. Now it's spawned by node"   │ │
│  │  → Maybe normal. Maybe process injection. 30b decides.        │ │
│  │                                                               │ │
│  │  TRUST BOUNDARY CROSSING                                      │ │
│  │  "user → root → user within 5 minutes"                        │ │
│  │  → Legit sudo stays elevated. Bouncing back hides tracks.     │ │
│  │                                                               │ │
│  │  UNSIGNED + NETWORK                                           │ │
│  │  "Unknown binary + curl in the same 30-minute window"         │ │
│  │  → Dropped tool phoning home.                                 │ │
│  │                                                               │ │
│  │  None of these require:                                       │ │
│  │  • A CVE number           • A YARA rule                       │ │
│  │  • A VirusTotal hash      • A threat intel feed               │ │
│  │  • A malware family name  • Prior documentation               │ │
│  │                                                               │ │
│  │  They only require: "this has never happened here before."    │ │
│  │                                                               │ │
│  │  The 30b model gets the sequence and decides:                 │ │
│  │  Is this a zero-day? A new TTP? Or just you doing something   │ │
│  │  weird at 3am?                                                │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  Triggered chains/anomalies → escalate to 30b with full context    │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                      STORAGE & AUDIT                                │
│                                                                     │
│  ~/.local/share/watchdog/                                           │
│  ├── process_events.db          SQLite: events, baselines, verdicts │
│  ├── escalations.jsonl          Every 30b escalation logged         │
│  ├── correlations.jsonl         Every chain/anomaly trigger logged  │
│  ├── domain_requests.jsonl      30b's requests for new domains      │
│  └── investigations/                                                │
│      └── <12-char-id>/                                              │
│          ├── meta.json          Investigation metadata              │
│          ├── notes.md           30b's running analysis notes        │
│          ├── evidence/          Saved tool results                  │
│          │   ├── vt-hash.txt                                        │
│          │   ├── baseline.txt                                       │
│          │   └── mitre-map.txt                                      │
│          └── ruling.json        Final verdict + reasoning           │
│                                                                     │
│  Everything persists. Every ruling auditable. Every tool call       │
│  logged. Investigation notes survive context compaction.            │
│  Fresh context per investigation — no cross-contamination.          │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                      SAFETY                                         │
│                                                                     │
│  forkguard             Wraps the daemon. Freezes runaway processes. │
│                        macOS notification on trip. SIGSTOP default. │
│                                                                     │
│  ulimit -u 2048        Global process cap in .zshrc                 │
│                                                                     │
│  toolbox_forkguard()   Self-check in toolbox scripts                │
│                                                                     │
│  Rate limiting          10 calls/min global, 4/min per domain       │
│                                                                     │
│  Domain allowlist       30b can ONLY reach curated domains          │
│                                                                     │
│  Tool budget            6 calls, 120s timeout per investigation     │
│                                                                     │
│  All local              Ollama only. No cloud APIs. No tokens.      │
│                         No data leaves the machine.                 │
└─────────────────────────────────────────────────────────────────────┘
```

## File Map

```
domains/detect/watchdog/
├── __main__.py          Daemon loop + CLI (daemon, scan, baseline, verdicts, status)
├── config.py            Paths, thresholds, model names
├── parser.py            osquery results log → structured events
├── enrich.py            Pre-classification forensics (codesign, perms, hash)
├── queue.py             Priority queue with dedup + fast-path cache
├── classifier.py        4b triage classifier (Ollama)
├── escalate.py          30b agent loop with tool-calling
├── tools.py             16-tool registry (web, VT, MITRE, memory, baseline)
├── investigation.py     Per-event investigation lifecycle + disk persistence
├── correlator.py        Kill chain matching + behavioral anomaly detection
├── db.py                SQLite storage (events, baselines, verdicts)
├── Modelfile            Ollama modelfile for 4b triage (qwen3:4b)
├── Modelfile.escalate   Ollama modelfile for 30b analyst (qwen3-coder:30b)
└── ARCHITECTURE.md      This file
```

## Models

| Role | Model | Size | Purpose |
|------|-------|------|---------|
| Fast triage | `watchdog` (qwen3:4b) | 2.6GB | Sub-second classification. Normal/suspicious/alert. |
| Deep analysis | `watchdog-escalate` (qwen3-coder:30b) | 18GB | Full investigation with tool use. Discovers new patterns. |

Both run locally via Ollama. No cloud. No API keys (except optional VirusTotal).
