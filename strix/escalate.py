"""Escalation agent — 30B model with tool-calling for deep process analysis.

When the 4b classifier flags something, the 30b model investigates using
tools: documentation lookups, hash checks, baseline queries, CVE lookups.
The model requests tools, we execute them, feed results back, repeat
until the model issues a final ruling.

No external API calls without allowlist. No Claude. Stays on-machine.
"""

import json
import time
import logging
import urllib.request
import urllib.error
from config import OLLAMA_URL, ESCALATION_LOG, WATCHDOG_DIR
from enrich import format_enrichment
from tools import get_ollama_tool_definitions, execute_tool, ALLOWED_DOMAINS, set_investigation_context, set_event_context
from investigation import start_investigation, close_investigation

log = logging.getLogger("watchdog.escalate")

ESCALATE_MODEL = "watchdog-escalate"

# Agent loop limits
MAX_TOOL_CALLS = 6       # Max tool invocations per event
MAX_ROUNDS = 4            # Max conversation rounds before forcing a ruling
AGENT_TIMEOUT = 120       # Total seconds before we cut her off

# Domain request log — she can ASK for domains, user reviews later
DOMAIN_REQUEST_LOG = WATCHDOG_DIR / "domain_requests.jsonl"


def escalate(event: dict, classification: dict) -> dict | None:
    """Run the escalation agent loop. Returns a ruling dict or None."""
    # Start a fresh investigation — clean context, new audit trail
    inv = start_investigation(event, classification)
    set_investigation_context(inv["id"])
    set_event_context(event)

    prompt = _build_escalation_prompt(event, classification)
    tools = get_ollama_tool_definitions()

    _log_escalation(event, classification, f"escalating_to_30b (inv={inv['id']})")

    messages = [
        {"role": "system", "content": _system_prompt()},
        {"role": "user", "content": prompt},
    ]

    tool_calls_made = 0
    start_time = time.time()

    for round_num in range(MAX_ROUNDS):
        elapsed = time.time() - start_time
        if elapsed > AGENT_TIMEOUT:
            log.warning("Agent timeout after %.0fs — forcing ruling", elapsed)
            _log_escalation(event, classification, "agent_timeout")
            break

        remaining_calls = MAX_TOOL_CALLS - tool_calls_made
        if remaining_calls <= 0:
            log.info("Tool budget exhausted (%d calls) — forcing ruling", MAX_TOOL_CALLS)
            messages.append({
                "role": "user",
                "content": "You have used all your tool calls. Issue your final ruling NOW as JSON.",
            })
            # One more round with no tools
            result = _chat(messages, tools=None)
            if result:
                ruling = _try_parse_ruling(result.get("message", {}).get("content", ""))
                if ruling:
                    return _finalize(event, classification, ruling)
            break

        # Call the model
        result = _chat(messages, tools=tools)
        if not result:
            log.error("Ollama returned no result in round %d", round_num)
            break

        msg = result.get("message", {})
        messages.append(msg)

        # Check for tool calls
        tool_calls = msg.get("tool_calls", [])

        if not tool_calls:
            # No tool calls — model is giving its ruling
            content = msg.get("content", "")
            ruling = _try_parse_ruling(content)
            if ruling:
                return _finalize(event, classification, ruling)
            # Model gave text but no JSON — ask for structured output
            if round_num < MAX_ROUNDS - 1:
                messages.append({
                    "role": "user",
                    "content": "I need your ruling as strict JSON. Output ONLY the JSON object.",
                })
            continue

        # Execute tool calls
        for tc in tool_calls:
            func = tc.get("function", {})
            tool_name = func.get("name", "")
            tool_args = func.get("arguments", {})

            # Handle domain request specially
            if tool_name == "request_domain_access":
                domain = tool_args.get("domain", "")
                reason = tool_args.get("reason", "")
                result_text = _handle_domain_request(domain, reason, event)
            else:
                log.info("Tool call: %s(%s)", tool_name, json.dumps(tool_args)[:100])
                result_text = execute_tool(tool_name, tool_args)

            tool_calls_made += 1

            messages.append({
                "role": "tool",
                "content": result_text,
            })

            log.info("Tool %s returned %d chars", tool_name, len(result_text))

    # If we got here without a ruling, close investigation as inconclusive
    log.warning("Agent loop ended without a ruling after %d rounds", MAX_ROUNDS)
    _log_escalation(event, classification, "agent_no_ruling")
    close_investigation(inv["id"], {
        "verdict": "suspicious",
        "confidence": 0.3,
        "risk_score": 0.5,
        "reasoning": "Investigation inconclusive — agent loop exhausted without ruling",
    })
    set_investigation_context("")
    set_event_context({})
    return None


def _chat(messages: list[dict], tools: list[dict] | None) -> dict | None:
    """Send a chat request to Ollama with tool definitions."""
    payload = {
        "model": ESCALATE_MODEL,
        "messages": messages,
        "stream": False,
        "keep_alive": "30m",
    }
    if tools:
        payload["tools"] = tools

    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{OLLAMA_URL}/api/chat",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=300) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        log.error("Ollama chat failed: %s", e)
        return None


def _handle_domain_request(domain: str, reason: str, event: dict) -> str:
    """Handle a domain access request from the model.

    Logs the request for user review. Does NOT auto-approve.
    """
    domain = domain.strip().lower()

    # If it's already allowed, just say so
    if domain in ALLOWED_DOMAINS:
        return f"Domain '{domain}' is already in the allowlist. Use web_lookup to fetch from it."

    # Log the request for user review
    WATCHDOG_DIR.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "domain": domain,
        "reason": reason,
        "process": event.get("process"),
        "path": event.get("path"),
        "status": "pending_review",
    }
    with open(DOMAIN_REQUEST_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

    log.info("DOMAIN REQUEST: %s — reason: %s (logged for user review)", domain, reason)

    return (
        f"Domain '{domain}' is NOT in the allowlist. Your request has been logged "
        f"for the operator to review. The operator will see:\n"
        f"  Domain: {domain}\n"
        f"  Reason: {reason}\n"
        f"  Context: analyzing {event.get('process', '?')} ({event.get('path', '?')})\n"
        f"Continue your analysis with the tools you have. Do not rely on this domain for your ruling."
    )


def _try_parse_ruling(text: str) -> dict | None:
    """Try to extract a JSON ruling from model output."""
    if not text:
        return None

    raw = _extract_json(text)
    if not raw or not raw.startswith("{"):
        return None

    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        return None

    ruling = result.get("ruling", "suspicious")
    if ruling not in ("normal", "suspicious", "alert", "false_positive"):
        ruling = "suspicious"

    return {
        "verdict": ruling,
        "confidence": min(1.0, max(0.0, float(result.get("confidence", 0.5)))),
        "risk_score": min(1.0, max(0.0, float(result.get("risk_score", 0.5)))),
        "reasoning": result.get("reasoning", "no reasoning provided"),
        "category": result.get("action", "none"),
        "source": "watchdog-escalate-30b",
        "tools_used": result.get("tools_used", []),
    }


def _finalize(event: dict, classification: dict, ruling: dict) -> dict:
    """Log and return a finalized ruling. Closes the investigation."""
    verdict = ruling["verdict"]
    log.info(
        "30b ruling: %s (risk=%.2f) — %s",
        verdict, ruling["risk_score"], ruling["reasoning"][:120]
    )

    if verdict == "false_positive":
        fp_reason = ruling.get("reasoning", "")
        ruling["reasoning"] = f"FALSE POSITIVE: {fp_reason}" if fp_reason else ruling["reasoning"]

    # Close investigation and clear context
    from tools import _current_inv_id
    if _current_inv_id:
        close_investigation(_current_inv_id, ruling)
        set_investigation_context("")
        set_event_context({})

    _log_escalation(event, classification, f"30b_ruling: {verdict}")
    return ruling


def _system_prompt() -> str:
    """System prompt for the 30b escalation agent."""
    return """You are WATCHDOG ESCALATION — a senior security analyst on a HIPAA-compliant macOS workstation.

A smaller ML model flagged a process as suspicious. You investigate with tools and issue a final ruling.

TOOLS AVAILABLE:
- recall_past_investigations: Search your past rulings. CALL THIS FIRST. If you've already investigated this binary, reuse that ruling — don't redo the work. Returns lightweight summaries, not full files.
- query_baseline: Check the local database — seen count, typical parent, prior verdicts.
- check_known_signing_ids: Check signing ID against known-good/bad lists.
- system_inspect: Live system inspection (runs as root via inspect.sh). Bulk commands (ps, netstat, lsof-net, etc.) are auto-filtered by a helper model — only relevant lines reach you. Use 'focus' to steer the filter (e.g., "connections to external IPs", "child processes of PID 1234"). Single-target commands (codesign, proc-fds, ps-pid) return unfiltered. Your context stays clean.
- map_mitre_technique: Map behaviors to ATT&CK techniques (local, instant).
- lookup_homebrew_formula: Check what a Homebrew binary is.
- lookup_virustotal_hash: Check a SHA256 against VirusTotal.
- web_lookup: Fetch docs from allowed domains (Apple, Homebrew, osquery, MITRE, Objective-See, NVD).
- lookup_osquery_table: Understand osquery event fields.
- lookup_cve: Look up a specific CVE from NVD/NIST.
- apple_support_search: Search Apple docs.
- objective_see_malware_check: Check Objective-See's macOS malware database.
- write_investigation_notes: Persist findings to disk. Use for key discoveries.
- save_investigation_evidence: Save a tool result as evidence (audit trail).
- promote_priority: Teach the system. If this event should have been HIGH priority but wasn't, call this with the pattern (path_prefix, signing_id, category, or process name) and a reason. Next time a matching event arrives, it jumps the queue. Use this to make the classifier smarter — you're training it.
- request_domain_access: Request a new domain. Operator reviews. Don't wait on it.

PROCESS:
1. Check recall_past_investigations FIRST — don't redo work.
2. Check baseline and signing ID — cheap, fast, decisive.
3. If those aren't enough, use system_inspect for live state — process tree, network connections, open files. Use 'focus' to tell your helper what to look for.
4. Map to MITRE ATT&CK techniques.
5. Only then go to network tools (web_lookup, VirusTotal) if needed.
6. Write key findings to investigation notes as you go.
7. Issue a ruling with evidence.

RULES:
- Budget: 6 tool calls, 120 seconds. Be surgical.
- NEVER dump a full web page into your context if a specific lookup tool exists.
- If recall_past_investigations returns a prior ruling on the same binary with high confidence, you can reuse it without further investigation.
- Focus on BEHAVIORS and ATT&CK techniques, not virus signatures.
- If you need a domain not on the allowlist, request it with request_domain_access. Specify the DOMAIN and WHY.

RULINGS (output as JSON):
- NORMAL: Verified safe with evidence.
- SUSPICIOUS: Something is off. Needs monitoring.
- ALERT: Active threat or policy violation. Specify action.
- FALSE_POSITIVE: The smaller model was wrong. Explain why.

{"ruling":"normal|suspicious|alert|false_positive","confidence":0.0-1.0,"risk_score":0.0-1.0,"reasoning":"evidence-based explanation","action":"none|monitor|investigate|kill|quarantine","tools_used":["tool1","tool2"]}"""


def _build_escalation_prompt(event: dict, classification: dict) -> str:
    process = event.get("process", "unknown")
    path = event.get("path", "unknown")
    pid = event.get("pid", "?")
    parent_pid = event.get("parent_pid", "?")
    uid = event.get("uid", "?")
    euid = event.get("euid", "?")
    cmdline = event.get("cmdline", "")
    cwd = event.get("cwd", "")
    signing_id = event.get("signing_id", "")
    team_id = event.get("team_id", "")
    platform_binary = event.get("platform_binary", False)
    risk = classification.get("risk_score", 0)
    reasoning = classification.get("reasoning", "none")
    category = classification.get("category", "unknown")

    platform_str = "Apple-signed platform binary" if platform_binary else "NOT an Apple platform binary"

    enrichment = event.get("enrichment", {})
    forensic = format_enrichment(enrichment) if enrichment else "No forensic data gathered"

    log_context = event.get("log_context", "")
    source = event.get("source", "osquery")

    log_section = ""
    if log_context:
        log_section = f"""
SYSTEM LOG TIMELINE (±1 minute around event):
{log_context}
"""

    return f"""WATCHDOG ESCALATION — investigate this flagged {'log event' if 'log-monitor' in source else 'process'}.

{'EVENT SOURCE: ' + source if source != 'osquery' else ''}
PROCESS EVENT:
  Name:            {process}
  Full Path:       {path}
  PID:             {pid} | Parent PID: {parent_pid}
  UID:             {uid} | Effective UID: {euid}
  Command Line:    {cmdline}
  Working Dir:     {cwd}
  Code Signing ID: {signing_id}
  Team ID:         {team_id}
  Platform Binary: {platform_str}

4b CLASSIFIER ASSESSMENT:
  Risk Score:      {risk:.2f}/1.00
  Category:        {category}
  Reasoning:       {reasoning}

FORENSIC EVIDENCE (from disk):
{forensic}
{log_section}
Investigate using your tools. Check the baseline, signing ID, and documentation as needed. Issue your ruling as JSON."""


def _extract_json(text: str) -> str:
    if "```" in text:
        parts = text.split("```")
        for part in parts:
            stripped = part.strip()
            if stripped.startswith("json"):
                stripped = stripped[4:].strip()
            if stripped.startswith("{"):
                return stripped

    start = text.find("{")
    end = text.rfind("}") + 1
    if start >= 0 and end > start:
        return text[start:end]

    return text


def _log_escalation(event: dict, classification: dict, status: str):
    WATCHDOG_DIR.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "process": event.get("process"),
        "path": event.get("path"),
        "pid": event.get("pid"),
        "risk_score": classification.get("risk_score"),
        "status": status,
    }
    with open(ESCALATION_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")
