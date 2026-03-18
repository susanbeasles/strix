"""Ollama-powered process event classifier — is this process supposed to be here?"""

import json
import urllib.request
import urllib.error
from config import OLLAMA_URL, OLLAMA_MODEL, SKETCHY_THRESHOLD
from enrich import enrich_event, format_enrichment


def classify_process(event: dict, baseline_context: str = "") -> dict:
    """Classify a process event. Returns verdict dict."""
    enriched = enrich_event(event)
    prompt = _build_prompt(enriched, baseline_context)
    try:
        return _query_ollama(prompt)
    except Exception as e:
        return {
            "verdict": "suspicious",
            "confidence": 0.0,
            "risk_score": 0.8,
            "reasoning": f"Ollama unavailable ({type(e).__name__}), flagging as suspicious",
            "category": "unknown",
        }


def _build_prompt(event: dict, baseline_context: str) -> str:
    path = event.get("path", "unknown")
    process = event.get("process", "unknown")
    pid = event.get("pid", "?")
    parent_pid = event.get("parent_pid", "?")
    uid = event.get("uid", "?")
    euid = event.get("euid", "?")
    cmdline = event.get("cmdline", "")
    cwd = event.get("cwd", "")
    signing_id = event.get("signing_id", "")
    team_id = event.get("team_id", "")
    platform_binary = event.get("platform_binary", False)
    event_type = event.get("event_type", "exec")

    platform_str = "Apple-signed platform binary" if platform_binary else "NOT an Apple platform binary"

    ctx = f"\nBaseline context: {baseline_context}" if baseline_context else ""

    # Forensic enrichment — real data from disk, not just metadata
    enrichment = event.get("enrichment", {})
    forensic = format_enrichment(enrichment) if enrichment else "No forensic data available"

    return f"""Classify this process execution event:

Process: {process}
Full Path: {path}
Event: {event_type}
PID: {pid} | Parent PID: {parent_pid}
UID: {uid} | Effective UID: {euid}
Command Line: {cmdline}
Working Directory: {cwd}
Code Signing ID: {signing_id}
Team ID: {team_id}
Platform Binary: {platform_str}
{ctx}

FORENSIC VERIFICATION (gathered from disk — this is real evidence, not metadata):
{forensic}

Classify based on the forensic evidence above. The FORENSIC VERIFICATION section contains
data gathered directly from the filesystem — trust that over metadata claims. If code signing is verified and the binary is in an expected location with no SUID bits, that is strong evidence of normalcy. If the binary is unsigned, in /tmp, or has SUID bits set, that is strong evidence of risk."""


def _query_ollama(prompt: str) -> dict:
    """Send classification request to Ollama."""
    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "keep_alive": "30m",
    }).encode()

    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
    )

    with urllib.request.urlopen(req, timeout=180) as resp:
        body = json.loads(resp.read())

    raw = body.get("response", "").strip()
    thinking = body.get("thinking", "").strip()

    raw = _extract_json(raw) if raw else ""
    if not raw or not raw.startswith("{"):
        thinking_json = _extract_json(thinking) if thinking else ""
        if thinking_json and thinking_json.startswith("{"):
            raw = thinking_json

    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        return {
            "verdict": "suspicious",
            "confidence": 0.0,
            "risk_score": 0.8,
            "reasoning": "Failed to parse model response — flagging as suspicious",
            "category": "unknown",
        }

    verdict = result.get("verdict", "suspicious")
    if verdict not in ("normal", "suspicious", "alert"):
        verdict = "suspicious"

    confidence = min(1.0, max(0.0, float(result.get("confidence", 0.5))))
    risk_score = min(1.0, max(0.0, float(result.get("risk_score", 0.5))))

    if verdict == "normal" and risk_score >= SKETCHY_THRESHOLD:
        verdict = "suspicious"

    return {
        "verdict": verdict,
        "confidence": confidence,
        "risk_score": risk_score,
        "reasoning": result.get("reasoning", "no reasoning provided"),
        "category": result.get("category", "unknown"),
    }


def _extract_json(text: str) -> str:
    """Extract JSON object from potentially markdown-wrapped response."""
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
