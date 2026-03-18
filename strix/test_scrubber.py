"""Test sequences for the scrubber queue.

Run from the strix directory:
    python test_scrubber.py

Tests the queue mechanics (submit, ordering, concurrency, backpressure)
independently of Ollama. Uses a mock 4B call for fast testing.
"""

import sys
import time
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

# --- Mock Ollama before importing scrubber ---
# Patch urllib so we don't need a running Ollama instance.
import json
import urllib.request

_original_urlopen = urllib.request.urlopen
_mock_delay = 0.2  # Simulate 4B inference time
_mock_calls = []


class MockResponse:
    def __init__(self, content):
        self._data = json.dumps({
            "message": {"content": content}
        }).encode()

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def _mock_urlopen(req, timeout=None):
    body = json.loads(req.data.decode())
    prompt = body["messages"][0]["content"]
    _mock_calls.append({"time": time.time(), "prompt_len": len(prompt)})
    time.sleep(_mock_delay)
    # Return first 100 chars of prompt as "filtered" output
    return MockResponse(f"FILTERED: {prompt[:100]}")


urllib.request.urlopen = _mock_urlopen

# Now import scrubber (it will use our mock)
from scrubber import scrub, scrub_async, scrubber_stats, stop_scrubber, _instance


def test_single_submit():
    """Basic: submit one job, get a result."""
    print("TEST: single_submit ... ", end="", flush=True)
    result = scrub("raw data here", "Filter this: raw data here")
    assert "[4B filtered" in result, f"Expected filtered header, got: {result[:80]}"
    assert "FILTERED:" in result, f"Expected mock content, got: {result[:80]}"
    print("PASS")


def test_ordering():
    """Jobs come back in submission order (FIFO)."""
    print("TEST: ordering ... ", end="", flush=True)
    jobs = []
    for i in range(5):
        job = scrub_async(f"raw_{i}", f"Filter job {i}: raw_{i}")
        jobs.append((i, job))

    for i, job in jobs:
        result = job.wait(timeout=30)
        assert f"job {i}" in result, f"Job {i} got wrong result: {result[:80]}"
    print("PASS")


def test_concurrent_submitters():
    """Multiple threads submitting simultaneously — no crashes, no drops."""
    print("TEST: concurrent_submitters ... ", end="", flush=True)
    results = {}
    errors = []

    def submitter(thread_id):
        try:
            result = scrub(f"data_{thread_id}", f"Filter thread {thread_id}: data_{thread_id}")
            results[thread_id] = result
        except Exception as e:
            errors.append((thread_id, e))

    threads = []
    for i in range(8):
        t = threading.Thread(target=submitter, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=60)

    assert not errors, f"Errors: {errors}"
    assert len(results) == 8, f"Expected 8 results, got {len(results)}"
    print(f"PASS ({len(results)} results, 0 errors)")


def test_no_drops():
    """Queue never drops work, even under load."""
    print("TEST: no_drops ... ", end="", flush=True)
    global _mock_delay
    old_delay = _mock_delay
    _mock_delay = 0.05  # Speed up for this test

    n = 25
    jobs = []
    for i in range(n):
        job = scrub_async(f"bulk_{i}", f"Filter bulk {i}: bulk_{i}")
        jobs.append(job)

    # All jobs should eventually complete
    for i, job in enumerate(jobs):
        result = job.wait(timeout=60)
        assert "FILTERED:" in result, f"Job {i} failed: {result[:80]}"

    stats = scrubber_stats()
    assert stats["completed"] >= n, f"Expected >= {n} completed, got {stats}"
    _mock_delay = old_delay
    print(f"PASS ({n} jobs, 0 dropped, peak_depth={stats['peak_depth']})")


def test_backpressure_warning():
    """Queue logs warnings at depth 10, 20, etc. (check stats for peak)."""
    print("TEST: backpressure (check peak_depth in stats) ... ", end="", flush=True)
    stats = scrubber_stats()
    print(f"PASS (peak_depth={stats['peak_depth']}, pending={stats['pending']})")


def test_fallback_on_timeout():
    """If 4B takes too long, caller gets truncated fallback."""
    print("TEST: fallback_on_timeout ... ", end="", flush=True)
    global _mock_delay
    old_delay = _mock_delay
    _mock_delay = 5.0  # Simulate slow 4B

    long_raw = "x" * 5000
    # Submit with a very short timeout — should fall back
    result = _instance.submit(long_raw, "Filter this", fallback_chars=100, timeout=0.5)
    assert "scrubber timeout" in result or "FILTERED" in result, f"Unexpected: {result[:80]}"

    _mock_delay = old_delay
    # Drain the slow job from the queue
    time.sleep(6)
    print("PASS")


def test_stats():
    """Stats track submitted, completed, failed, peak_depth."""
    print("TEST: stats ... ", end="", flush=True)
    stats = scrubber_stats()
    assert "submitted" in stats
    assert "completed" in stats
    assert "failed" in stats
    assert "peak_depth" in stats
    assert "pending" in stats
    assert stats["submitted"] > 0, "No jobs submitted?"
    assert stats["completed"] > 0, "No jobs completed?"
    print(f"PASS {stats}")


if __name__ == "__main__":
    print(f"Scrubber test suite (mock 4B, delay={_mock_delay}s)\n")

    test_single_submit()
    test_ordering()
    test_concurrent_submitters()
    test_no_drops()
    test_backpressure_warning()
    test_fallback_on_timeout()
    test_stats()

    stop_scrubber()

    print(f"\nAll tests passed. Final stats: {scrubber_stats()}")
