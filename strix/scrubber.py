"""Scrubber — queue-based 4B noise filter for the strix pipeline.

Callers never hit Ollama directly. They submit a job to the scrubber's
input queue and wait on a future. The scrubber worker thread pulls jobs
one at a time, calls the 4B, and delivers results through the future.

This prevents pile-ups when multiple threads (two 30B investigators +
log monitor) all need 4B filtering simultaneously. One at a time,
controlled flow, no blowups.

Architecture:
    caller → submit(raw, prompt) → [input queue] → worker → Ollama 4B
                                                        ↓
    caller ← future.result() ← ─ ─ ─ ─ ─ ─ ─ ─ ─ [result slot]

Used by:
  - tools.py (system_inspect filter — the 30b's helper)
  - log_monitor.py (surrounding log context filter)
  - Any future Scout that needs to strip noise from raw data
"""

import json
import logging
import threading
import urllib.request
import urllib.error
from collections import deque
from dataclasses import dataclass, field
from config import OLLAMA_URL

log = logging.getLogger("strix.scrubber")

MODEL = "watchdog"  # Same 4B used everywhere
TIMEOUT = 15        # Seconds per Ollama call
KEEP_ALIVE = "30m"  # Keep model hot between calls
WARN_DEPTH = 10     # Log a warning when queue gets this deep


@dataclass
class ScrubJob:
    """A unit of work for the scrubber."""
    raw: str                    # Raw text (for measurement, already in prompt)
    prompt: str                 # Complete prompt for the 4B
    fallback_chars: int = 2000  # Truncation fallback if 4B fails
    # Result delivery
    _result: str = field(default="", init=False, repr=False)
    _done: threading.Event = field(default_factory=threading.Event, init=False, repr=False)

    def wait(self, timeout: float = 30.0) -> str:
        """Block until the scrubber delivers a result."""
        if self._done.wait(timeout=timeout):
            return self._result
        # Timed out waiting for scrubber — return fallback
        log.warning("Scrub job timed out after %.0fs", timeout)
        return self._fallback()

    def deliver(self, result: str):
        """Called by the worker to deliver the result."""
        self._result = result
        self._done.set()

    def _fallback(self) -> str:
        if self.fallback_chars and len(self.raw) > self.fallback_chars:
            return self.raw[:self.fallback_chars] + f"\n... [scrubber timeout, truncated at {self.fallback_chars} chars]"
        return self.raw


class Scrubber:
    """Queue-based 4B worker. One instance for the whole strix process."""

    def __init__(self):
        self._deque: deque[ScrubJob | None] = deque()  # Unbounded — never drop work
        self._cond = threading.Condition()               # Notify worker when jobs arrive
        self._worker: threading.Thread | None = None
        self._running = False
        self._stats = {"submitted": 0, "completed": 0, "failed": 0, "peak_depth": 0}

    def start(self):
        """Start the scrubber worker thread."""
        if self._worker and self._worker.is_alive():
            return
        self._running = True
        self._worker = threading.Thread(
            target=self._work_loop, name="scrubber-4b", daemon=True,
        )
        self._worker.start()
        log.info("Scrubber worker started (unbounded queue)")

    def stop(self):
        """Signal the worker to stop."""
        self._running = False
        with self._cond:
            self._deque.append(None)  # Poison pill
            self._cond.notify()

    def submit(self, raw: str, prompt: str, fallback_chars: int = 2000,
               timeout: float = 0) -> str:
        """Submit a scrub job and block until the result is ready.

        This is the main API. Callers don't touch Ollama — they submit
        work here and get filtered text back.

        Timeout scales with queue depth — if there are 5 jobs ahead of you,
        you get 5 * 15s + 30s = 105s to wait. Set timeout=0 (default) for
        auto-scaling. Never drops work.
        """
        job = ScrubJob(raw=raw, prompt=prompt, fallback_chars=fallback_chars)

        # Auto-start if not running
        if not self._worker or not self._worker.is_alive():
            self.start()

        with self._cond:
            depth = len(self._deque)
            self._deque.append(job)
            self._cond.notify()

        self._stats["submitted"] += 1

        if depth > self._stats["peak_depth"]:
            self._stats["peak_depth"] = depth
        if depth >= WARN_DEPTH and depth % WARN_DEPTH == 0:
            log.warning("Scrubber queue depth: %d (jobs are backing up)", depth)

        # Auto-scale timeout: each queued job takes ~TIMEOUT seconds
        if timeout <= 0:
            timeout = 30.0 + (depth * TIMEOUT)

        return job.wait(timeout=timeout)

    def submit_async(self, raw: str, prompt: str,
                     fallback_chars: int = 2000) -> ScrubJob:
        """Submit a scrub job without blocking. Returns the job — call job.wait() later."""
        job = ScrubJob(raw=raw, prompt=prompt, fallback_chars=fallback_chars)

        if not self._worker or not self._worker.is_alive():
            self.start()

        with self._cond:
            self._deque.append(job)
            self._cond.notify()
        self._stats["submitted"] += 1
        return job

    @property
    def stats(self) -> dict:
        return {**self._stats, "pending": len(self._deque)}

    def _work_loop(self):
        """Pull jobs from the queue, call Ollama, deliver results."""
        log.info("Scrubber worker running")
        while self._running:
            with self._cond:
                while not self._deque and self._running:
                    self._cond.wait(timeout=5.0)
                if not self._deque:
                    continue
                job = self._deque.popleft()

            if job is None:
                break  # Poison pill

            try:
                result = self._call_4b(job)
                job.deliver(result)
                self._stats["completed"] += 1
            except Exception as e:
                log.error("Scrubber job failed: %s", e, exc_info=True)
                job.deliver(job._fallback())
                self._stats["failed"] += 1

        log.info("Scrubber worker stopped (stats=%s)", self._stats)

    def _call_4b(self, job: ScrubJob) -> str:
        """Make the actual Ollama call for a single job."""
        payload = {
            "model": MODEL,
            "messages": [{"role": "user", "content": job.prompt}],
            "stream": False,
            "keep_alive": KEEP_ALIVE,
        }

        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{OLLAMA_URL}/api/chat",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            result = json.loads(resp.read())
            filtered = result.get("message", {}).get("content", "").strip()
            if filtered:
                return f"[4B filtered — raw was {len(job.raw)} chars]\n{filtered}"

        # 4B returned empty — use fallback
        return job._fallback()


# --- Module-level singleton ---
# Everyone imports and uses this one instance. Started lazily on first submit.
_instance = Scrubber()


def scrub(raw: str, prompt: str, fallback_chars: int = 2000) -> str:
    """Submit a scrub job and block until result is ready.

    Convenience wrapper around the singleton. This is the function
    that tools.py and log_monitor.py import.
    """
    return _instance.submit(raw, prompt, fallback_chars)


def scrub_async(raw: str, prompt: str, fallback_chars: int = 2000) -> ScrubJob:
    """Submit a scrub job without blocking. Returns job — call job.wait() later."""
    return _instance.submit_async(raw, prompt, fallback_chars)


def scrubber_stats() -> dict:
    """Return scrubber queue stats."""
    return _instance.stats


def stop_scrubber():
    """Stop the scrubber worker. Called on daemon shutdown."""
    _instance.stop()
