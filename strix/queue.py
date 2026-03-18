"""Priority queue for process event classification.

Events are deduplicated by (path, parent_pid, signing_id) and prioritized
by estimated risk. Unsigned binaries and unknown processes get classified
first; Apple platform binaries wait or skip via fast-path cache.
"""

import threading
import time
import heapq
from dataclasses import dataclass, field


@dataclass(order=True)
class QueueItem:
    """Priority queue entry. Lower priority number = processed first."""
    priority: float
    timestamp: float = field(compare=False)
    event: dict = field(compare=False)
    count: int = field(default=1, compare=False)


class ClassificationQueue:
    """Thread-safe priority queue with dedup and fast-path caching."""

    def __init__(self):
        self._heap: list[QueueItem] = []
        self._lock = threading.Lock()
        self._not_empty = threading.Condition(self._lock)
        # Dedup: (path, parent_pid, signing_id) -> QueueItem
        self._pending: dict[tuple, QueueItem] = {}
        # Fast-path cache: key -> verdict dict
        self._fast_cache: dict[tuple, dict] = {}
        self._verdict_history: dict[tuple, list[str]] = {}
        # Stats
        self.stats = {
            "enqueued": 0,
            "deduped": 0,
            "fast_path": 0,
            "classified": 0,
        }

    def enqueue(self, event: dict) -> str:
        """Add an event to the queue. Returns 'queued', 'deduped', or 'fast_path'."""
        key = _event_key(event)

        cached = self._fast_cache.get(key)
        if cached:
            self.stats["fast_path"] += 1
            return "fast_path"

        priority = _estimate_priority(event)

        with self._not_empty:
            if key in self._pending:
                item = self._pending[key]
                item.count += 1
                item.priority = min(item.priority, priority - 0.1 * item.count)
                heapq.heapify(self._heap)
                self.stats["deduped"] += 1
                return "deduped"

            item = QueueItem(priority=priority, timestamp=time.time(), event=event)
            heapq.heappush(self._heap, item)
            self._pending[key] = item
            self.stats["enqueued"] += 1
            self._not_empty.notify()
            return "queued"

    def dequeue(self, timeout: float = 5.0) -> QueueItem | None:
        """Get the highest-priority item. Blocks up to timeout seconds."""
        with self._not_empty:
            while not self._heap:
                if not self._not_empty.wait(timeout=timeout):
                    return None
            item = heapq.heappop(self._heap)
            key = _event_key(item.event)
            self._pending.pop(key, None)
            return item

    def record_verdict(self, event: dict, verdict: dict):
        """Record a classification result. After consistent verdicts,
        promote to fast-path cache so future identical processes skip Ollama."""
        key = _event_key(event)
        self.stats["classified"] += 1

        history = self._verdict_history.setdefault(key, [])
        history.append(verdict.get("verdict", "unknown"))

        if len(history) > 10:
            history[:] = history[-10:]

        # Promote to fast-path after 3+ consistent verdicts
        if len(history) >= 3 and len(set(history[-3:])) == 1:
            self._fast_cache[key] = verdict

    def get_cached_verdict(self, event: dict) -> dict | None:
        return self._fast_cache.get(_event_key(event))

    def invalidate_cache(self, event: dict):
        key = _event_key(event)
        self._fast_cache.pop(key, None)
        self._verdict_history.pop(key, None)

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._heap)

    @property
    def cache_size(self) -> int:
        return len(self._fast_cache)


def _event_key(event: dict) -> tuple:
    """Dedup key: (path, parent_pid, signing_id).

    Same binary launched by different parents is a different security event.
    Same binary with different signing identities is definitely different.
    """
    path = event.get("path", "unknown")
    parent_pid = event.get("parent_pid")
    signing_id = event.get("signing_id", "")
    return (path, parent_pid, signing_id)


def _estimate_priority(event: dict) -> float:
    """Estimate risk priority without calling Ollama. Lower = higher priority.

    Scale: 0.0 (classify immediately) to 1.0 (low priority)
    """
    path = event.get("path", "")
    signing_id = event.get("signing_id", "")
    team_id = event.get("team_id", "")
    platform_binary = event.get("platform_binary", False)
    uid = event.get("uid")
    euid = event.get("euid")
    cmdline = event.get("cmdline", "")

    score = 0.5

    # Apple platform binaries are kernel-verified — lower priority
    if platform_binary:
        score += 0.25

    # Has Apple team ID — somewhat trusted
    if team_id:
        score += 0.1

    # Unsigned binary — highest priority
    if not signing_id:
        score -= 0.3

    # Running as root (uid 0 or euid 0)
    if uid == 0 or euid == 0:
        score -= 0.15

    # SUID — euid differs from uid
    if uid is not None and euid is not None and uid != euid:
        score -= 0.2

    # Binary outside standard paths
    standard_prefixes = ("/usr/", "/bin/", "/sbin/", "/System/", "/Library/Apple/")
    if path and not any(path.startswith(p) for p in standard_prefixes):
        score -= 0.15

    # Suspicious command-line patterns
    if cmdline:
        suspicious_patterns = ("curl ", "wget ", "nc ", "ncat ", "bash -c", "python -c",
                               "base64", "eval ", "/dev/tcp", "mkfifo")
        for pat in suspicious_patterns:
            if pat in cmdline:
                score -= 0.3
                break

    # /tmp or /var/tmp execution — classic staging area
    if path and ("/tmp/" in path or "/var/tmp/" in path):
        score -= 0.25

    return max(0.0, min(1.0, score))
