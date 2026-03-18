"""Escalation queue — priority-ranked pipeline between the 4B classifier and 30B investigator.

Two priority lanes:
  HIGH — needs investigation NOW. Active threats, critical anomalies, patterns the 30b
         has explicitly flagged as high-priority via promote_priority().
  LOW  — everything else. Suspicious but not urgent.

Workers:
  Normally 1 worker pulls from the queue (HIGH first, then LOW).
  When HIGH queue depth hits SCALEUP_THRESHOLD, a second worker spins up
  and stays alive until HIGH is drained. Max 2 concurrent 30b sessions.

Locking:
  Each binary under investigation is locked by the worker processing it.
  Locks are keyed on (path, signing_id) and auto-expire after LOCK_TTL seconds.
  - A locked binary cannot be queued again (submit returns 'locked').
  - Workers skip items whose lock is held by another worker.
  - If a worker crashes, the lock expires and the binary can be re-queued.
  - Workers can only release their own locks.

Feedback loop:
  The 30b can call promote_priority() to teach the system that a certain
  pattern (path prefix, signing_id, behavior) should be HIGH next time.
  These promotions persist in a JSON file so they survive restarts.
"""

import json
import logging
import threading
import time
import heapq
from dataclasses import dataclass, field
from pathlib import Path
from config import STRIX_DIR

log = logging.getLogger("strix.escalation_queue")

# --- Tunables ---
MAX_QUEUE_DEPTH = 30         # Log warning when total queue exceeds this
SCALEUP_THRESHOLD = 3        # Spin up second worker when HIGH queue hits this
MAX_WORKERS = 2              # Hard cap on concurrent 30b sessions
LOCK_TTL = 150               # Seconds before an investigation lock auto-expires
                             # (AGENT_TIMEOUT=120 + 30s buffer for cleanup)
PROMOTIONS_FILE = STRIX_DIR / "priority_promotions.json"

# --- Priority levels ---
HIGH = 0
LOW = 1
_PRIORITY_NAMES = {HIGH: "HIGH", LOW: "LOW"}


@dataclass
class InvestigationLock:
    """A lock on a binary currently under investigation."""
    key: tuple                # (path, signing_id)
    worker: str               # Thread name that holds the lock
    acquired: float           # time.time() when acquired
    ttl: float = LOCK_TTL     # Seconds until auto-expire

    @property
    def expired(self) -> bool:
        return time.time() - self.acquired > self.ttl

    @property
    def held_by(self) -> str:
        return self.worker if not self.expired else "(expired)"


class LockTable:
    """Thread-safe lock table for active investigations.

    Prevents duplicate investigations and lets workers claim exclusivity.
    Locks auto-expire so a crashed worker doesn't block the binary forever.
    """

    def __init__(self):
        self._locks: dict[tuple, InvestigationLock] = {}
        self._mu = threading.Lock()

    def acquire(self, key: tuple, worker: str) -> bool:
        """Try to acquire a lock. Returns True if acquired, False if held by another."""
        with self._mu:
            self._reap_expired()
            existing = self._locks.get(key)
            if existing and not existing.expired:
                if existing.worker == worker:
                    return True  # Already ours — idempotent
                return False     # Held by another worker
            self._locks[key] = InvestigationLock(key=key, worker=worker, acquired=time.time())
            return True

    def release(self, key: tuple, worker: str):
        """Release a lock. Only the owning worker can release it."""
        with self._mu:
            existing = self._locks.get(key)
            if existing and (existing.worker == worker or existing.expired):
                del self._locks[key]

    def is_locked(self, key: tuple) -> bool:
        """Check if a key is currently locked (and not expired)."""
        with self._mu:
            existing = self._locks.get(key)
            if existing and not existing.expired:
                return True
            return False

    def held_by(self, key: tuple) -> str | None:
        """Return the worker holding the lock, or None."""
        with self._mu:
            existing = self._locks.get(key)
            if existing and not existing.expired:
                return existing.worker
            return None

    def active_locks(self) -> list[dict]:
        """Return all active (non-expired) locks for status display."""
        with self._mu:
            self._reap_expired()
            return [
                {
                    "key": lock.key,
                    "worker": lock.worker,
                    "age_seconds": round(time.time() - lock.acquired),
                    "ttl_remaining": round(lock.ttl - (time.time() - lock.acquired)),
                }
                for lock in self._locks.values()
            ]

    def _reap_expired(self):
        """Remove expired locks. Called under self._mu."""
        expired = [k for k, v in self._locks.items() if v.expired]
        for k in expired:
            log.warning("Lock expired: %s (was held by %s)", k, self._locks[k].worker)
            del self._locks[k]


@dataclass(order=True)
class EscalationItem:
    """Queue entry. Sorted by (priority_lane, risk_score inverted, timestamp)."""
    priority_lane: int
    neg_risk: float = field(compare=True)    # -risk_score so higher risk sorts first
    timestamp: float = field(compare=True)
    event: dict = field(compare=False)
    classification: dict = field(compare=False)
    source: str = field(default="classifier", compare=False)  # classifier, correlator-chain, correlator-anomaly


class EscalationQueue:
    """Thread-safe two-lane priority queue for 30b escalations."""

    def __init__(self):
        self._heap: list[EscalationItem] = []
        self._lock = threading.Lock()
        self._not_empty = threading.Condition(self._lock)

        # Dedup: (path, signing_id) -> item (coarser than classification queue —
        # we don't care about parent_pid at escalation level)
        self._pending: dict[tuple, EscalationItem] = {}

        # Investigation locks — prevents duplicate work on the same binary
        self.locks = LockTable()

        # Promotion rules — loaded from disk
        self._promotions: list[dict] = []
        self._load_promotions()

        # Worker management
        self._workers: list[threading.Thread] = []
        self._worker_count = 0
        self._worker_lock = threading.Lock()
        self._running = True
        self._escalate_fn = None  # Set by start_workers()
        self._result_fn = None    # Callback for recording verdicts

        # Stats
        self.stats = {
            "submitted": 0,
            "deduped": 0,
            "processed": 0,
            "dropped": 0,
            "high_priority": 0,
            "low_priority": 0,
            "scaleups": 0,
            "lock_skips": 0,
        }

    def start_workers(self, escalate_fn, result_fn):
        """Start the escalation worker pool.

        escalate_fn: callable(event, classification) -> ruling dict or None
        result_fn:   callable(event, ruling, source) -> None (record verdict)
        """
        self._escalate_fn = escalate_fn
        self._result_fn = result_fn
        self._spawn_worker("escalation-worker-1")

    def stop(self):
        """Shut down workers gracefully."""
        self._running = False
        with self._not_empty:
            self._not_empty.notify_all()

    def submit(self, event: dict, classification: dict, source: str = "classifier") -> str:
        """Submit an event for 30b escalation. Returns 'queued', 'deduped', 'locked', or 'dropped'."""
        key = _escalation_key(event)
        risk = classification.get("risk_score", 0.5)
        lane = self._assign_priority(event, classification)

        # Check if this binary is already being investigated by a worker
        holder = self.locks.held_by(key)
        if holder:
            log.info("Skipping %s — already locked by %s",
                     event.get("process", "?"), holder)
            self.stats["lock_skips"] += 1
            return "locked"

        with self._not_empty:
            # Dedup — if same binary is already queued, bump priority if needed
            if key in self._pending:
                existing = self._pending[key]
                if lane < existing.priority_lane:
                    existing.priority_lane = lane
                    existing.neg_risk = min(existing.neg_risk, -risk)
                    heapq.heapify(self._heap)
                self.stats["deduped"] += 1
                return "deduped"

            total = len(self._heap)
            if total >= MAX_QUEUE_DEPTH:
                # Queue is full — only accept HIGH priority
                if lane == LOW:
                    log.warning("Escalation queue full (%d) — dropping LOW priority: %s",
                                total, event.get("process", "?"))
                    self.stats["dropped"] += 1
                    return "dropped"
                log.warning("Escalation queue full (%d) but accepting HIGH priority: %s",
                            total, event.get("process", "?"))

            item = EscalationItem(
                priority_lane=lane,
                neg_risk=-risk,
                timestamp=time.time(),
                event=event,
                classification=classification,
                source=source,
            )
            heapq.heappush(self._heap, item)
            self._pending[key] = item
            self.stats["submitted"] += 1

            if lane == HIGH:
                self.stats["high_priority"] += 1
            else:
                self.stats["low_priority"] += 1

            self._not_empty.notify()

        # Check if we need to scale up
        self._maybe_scaleup()

        lane_name = _PRIORITY_NAMES[lane]
        log.info("Escalation queued [%s]: %s (%s) risk=%.2f | queue=%d",
                 lane_name, event.get("process", "?"), event.get("path", "?"),
                 risk, self.size)

        return "queued"

    def dequeue(self, timeout: float = 10.0) -> EscalationItem | None:
        """Get the highest-priority item. HIGH lane always drains first."""
        with self._not_empty:
            while not self._heap:
                if not self._running:
                    return None
                if not self._not_empty.wait(timeout=timeout):
                    return None
            item = heapq.heappop(self._heap)
            key = _escalation_key(item.event)
            self._pending.pop(key, None)
            return item

    def promote_priority(self, pattern: dict, reason: str):
        """Teach the queue that a pattern should be HIGH priority in the future.

        Called by the 30b when it discovers something that should have been
        HIGH but wasn't. Patterns match on: path_prefix, signing_id, category.

        Example:
            promote_priority({"path_prefix": "/tmp/"}, "unsigned binary staging from tmp")
            promote_priority({"signing_id": "evil-corp"}, "known bad actor")
            promote_priority({"category": "reverse_shell"}, "active C2")
        """
        entry = {
            "pattern": pattern,
            "reason": reason,
            "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
        self._promotions.append(entry)
        self._save_promotions()
        log.warning("Priority promotion added: %s — reason: %s", pattern, reason)

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._heap)

    @property
    def high_count(self) -> int:
        with self._lock:
            return sum(1 for item in self._heap if item.priority_lane == HIGH)

    # --- Internal ---

    def _assign_priority(self, event: dict, classification: dict) -> int:
        """Decide HIGH or LOW based on event characteristics and learned promotions."""
        risk = classification.get("risk_score", 0.5)
        verdict = classification.get("verdict", "")
        category = classification.get("category", "")
        path = event.get("path", "")
        signing_id = event.get("signing_id", "")

        # Hard rules — always HIGH
        if verdict == "alert":
            return HIGH
        if risk >= 0.9:
            return HIGH
        # Chain detections and critical anomalies are always HIGH
        if category in ("reverse_shell", "credential_theft", "data_exfil",
                        "privilege_escalation", "persistence_install"):
            return HIGH
        # Unsigned binary in a staging path running as root
        if not signing_id and ("/tmp/" in path or "/var/tmp/" in path):
            euid = event.get("euid")
            if euid == 0:
                return HIGH

        # Learned promotions from the 30b
        for promo in self._promotions:
            pat = promo.get("pattern", {})
            if "path_prefix" in pat and path.startswith(pat["path_prefix"]):
                return HIGH
            if "signing_id" in pat and signing_id == pat["signing_id"]:
                return HIGH
            if "category" in pat and category == pat["category"]:
                return HIGH
            if "process" in pat and event.get("process") == pat["process"]:
                return HIGH

        return LOW

    def _maybe_scaleup(self):
        """Spin up a second worker if HIGH queue is building up."""
        if self.high_count >= SCALEUP_THRESHOLD:
            with self._worker_lock:
                if self._worker_count < MAX_WORKERS:
                    self.stats["scaleups"] += 1
                    self._spawn_worker("escalation-worker-2")
                    log.warning("HIGH queue depth %d >= %d — scaled to %d workers",
                                self.high_count, SCALEUP_THRESHOLD, self._worker_count)

    def _spawn_worker(self, name: str):
        """Start a worker thread."""
        with self._worker_lock:
            if self._worker_count >= MAX_WORKERS:
                return
            t = threading.Thread(target=self._worker_loop, name=name, daemon=True)
            t.start()
            self._workers.append(t)
            self._worker_count += 1
            log.info("Started %s (total workers: %d)", name, self._worker_count)

    def _worker_loop(self):
        """Worker: pull from queue, run 30b, record result. Second worker exits when idle."""
        name = threading.current_thread().name
        is_scaleup = name != "escalation-worker-1"
        idle_rounds = 0

        while self._running:
            item = self.dequeue(timeout=10.0)

            if item is None:
                if is_scaleup:
                    idle_rounds += 1
                    # Second worker exits after 30s idle (HIGH queue drained)
                    if idle_rounds >= 3:
                        with self._worker_lock:
                            self._worker_count -= 1
                            log.info("%s exiting (idle, workers: %d)", name, self._worker_count)
                        return
                continue

            idle_rounds = 0
            key = _escalation_key(item.event)
            lane_name = _PRIORITY_NAMES[item.priority_lane]
            process = item.event.get("process", "?")

            # Acquire investigation lock — skip if another worker got there first
            if not self.locks.acquire(key, name):
                holder = self.locks.held_by(key)
                log.info("[%s] Skipping %s — locked by %s", name, process, holder)
                continue

            log.info("[%s] %s LOCKED + processing: %s (risk=%.2f, source=%s)",
                     name, lane_name, process, -item.neg_risk, item.source)

            try:
                ruling = self._escalate_fn(item.event, item.classification)
                self.stats["processed"] += 1

                if ruling and self._result_fn:
                    self._result_fn(item.event, ruling, item.source)

            except Exception as e:
                log.error("[%s] Escalation failed for %s: %s", name, process, e, exc_info=True)
            finally:
                self.locks.release(key, name)
                log.info("[%s] Released lock: %s", name, process)

    def _load_promotions(self):
        """Load learned priority promotions from disk."""
        if PROMOTIONS_FILE.exists():
            try:
                self._promotions = json.loads(PROMOTIONS_FILE.read_text())
                log.info("Loaded %d priority promotions from %s",
                         len(self._promotions), PROMOTIONS_FILE)
            except (json.JSONDecodeError, OSError) as e:
                log.warning("Failed to load promotions: %s", e)
                self._promotions = []

    def _save_promotions(self):
        """Persist promotions to disk."""
        STRIX_DIR.mkdir(parents=True, exist_ok=True)
        PROMOTIONS_FILE.write_text(json.dumps(self._promotions, indent=2))


def _escalation_key(event: dict) -> tuple:
    """Dedup key for escalation queue — coarser than classification."""
    return (event.get("path", ""), event.get("signing_id", ""))
