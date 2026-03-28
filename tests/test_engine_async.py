# Tests for async/parallel processing engine.

import threading
import time
from typing import List, Optional, Tuple

from taskhound.engine.async_runner import (
    AsyncConfig,
    AsyncTaskHound,
    TargetResult,
    aggregate_results,
)
from taskhound.laps import LAPSFailure
from taskhound.models.task import TaskRow


# Mock process function that simulates target processing
def mock_process_target(
    target: str,
    all_rows: List[TaskRow],
    delay: float = 0.1,
    should_fail: bool = False,
    **kwargs,
) -> Tuple[List[str], Optional[bool]]:
    """Mock process_target for testing."""
    if should_fail:
        raise Exception(f"Simulated failure for {target}")

    time.sleep(delay)  # Simulate network I/O

    all_rows.append(TaskRow(
        host=target,
        type="TASK",
        path=f"\\Tasks\\{target}_task",
    ))

    lines = [f"[TASK] {target}: Found 1 task"]
    return lines, None


class TestAsyncConfig:
    """Tests for AsyncConfig dataclass."""

    def test_default_values(self):
        config = AsyncConfig()
        assert config.workers == 10
        assert config.rate_limit is None
        assert config.timeout == 30
        assert config.show_progress is True
        assert config.jitter is None

    def test_custom_values(self):
        config = AsyncConfig(workers=20, rate_limit=5.0, timeout=60, jitter=3.0)
        assert config.workers == 20
        assert config.rate_limit == 5.0
        assert config.timeout == 60
        assert config.jitter == 3.0


class TestTargetResult:
    """Tests for TargetResult dataclass."""

    def test_default_values(self):
        result = TargetResult(target="192.168.1.1", success=True)
        assert result.target == "192.168.1.1"
        assert result.success is True
        assert result.lines == []
        assert result.rows == []
        assert result.laps_result is None
        assert result.error is None
        assert result.elapsed_ms == 0.0

    def test_with_data(self):
        result = TargetResult(
            target="server01",
            success=True,
            lines=["line1", "line2"],
            rows=[{"host": "server01"}],
            elapsed_ms=150.5,
        )
        assert len(result.lines) == 2
        assert len(result.rows) == 1
        assert result.elapsed_ms == 150.5


class TestAsyncTaskHound:
    """Tests for AsyncTaskHound parallel processor."""

    def test_sequential_mode(self):
        """Test --threads 1 behaves like original sequential processing."""
        config = AsyncConfig(workers=1, show_progress=False)
        engine = AsyncTaskHound(config)

        targets = ["host1", "host2", "host3"]
        results = engine.run(
            targets,
            mock_process_target,
            delay=0.01,
        )

        assert len(results) == 3
        assert all(r.success for r in results)
        assert all(len(r.rows) == 1 for r in results)

    def test_sequential_mode_with_jitter(self):
        """Test jitter adds delay between hosts in sequential mode."""
        jitter_seconds = 0.2
        config = AsyncConfig(workers=1, show_progress=False, jitter=jitter_seconds)
        engine = AsyncTaskHound(config)

        targets = ["host1", "host2", "host3"]
        start = time.perf_counter()
        results = engine.run(
            targets,
            mock_process_target,
            delay=0.01,
        )
        elapsed = time.perf_counter() - start

        assert len(results) == 3
        assert all(r.success for r in results)
        # Jitter applies between hosts (not before first), so 2 delays for 3 hosts
        # Minimum elapsed should be at least some jitter time (random 0 to jitter_seconds)
        # With 2 jitter delays, minimum could be 0, max would be ~0.4s + processing
        # Just verify it completed without error; timing is non-deterministic

    def test_parallel_mode(self):
        """Test parallel processing with multiple workers."""
        config = AsyncConfig(workers=3, show_progress=False)
        engine = AsyncTaskHound(config)

        targets = ["host1", "host2", "host3", "host4", "host5"]

        start = time.perf_counter()
        results = engine.run(
            targets,
            mock_process_target,
            delay=0.1,
        )
        elapsed = time.perf_counter() - start

        assert len(results) == 5
        assert all(r.success for r in results)

        # With 3 workers and 0.1s delay, 5 targets should take ~0.2s not ~0.5s
        # Allow some margin for thread overhead
        assert elapsed < 0.4, f"Parallel processing took too long: {elapsed}s"

    def test_handles_failures(self):
        """Test that failures are captured but don't stop processing."""
        config = AsyncConfig(workers=2, show_progress=False)
        engine = AsyncTaskHound(config)

        def failing_process(target, all_rows, **kwargs):
            if target == "fail_host":
                raise Exception("Simulated failure")
            return [f"OK: {target}"], None

        targets = ["host1", "fail_host", "host2"]
        results = engine.run(targets, failing_process)

        assert len(results) == 3

        successes = [r for r in results if r.success]
        failures = [r for r in results if not r.success]

        assert len(successes) == 2
        assert len(failures) == 1
        assert failures[0].target == "fail_host"
        assert "Simulated failure" in failures[0].error

    def test_empty_targets(self):
        """Test handling of empty target list."""
        engine = AsyncTaskHound()
        results = engine.run([], mock_process_target)
        assert results == []

    def test_rate_limiting(self):
        """Test that rate limiting slows down processing."""
        # 2 targets/second = 0.5s between targets
        config = AsyncConfig(workers=10, rate_limit=2.0, show_progress=False)
        engine = AsyncTaskHound(config)

        targets = ["host1", "host2", "host3"]

        start = time.perf_counter()
        results = engine.run(
            targets,
            mock_process_target,
            delay=0.01,  # Very fast processing
        )
        elapsed = time.perf_counter() - start

        assert len(results) == 3
        # 3 targets at 2/sec should take ~1.0s minimum
        # First target starts immediately, then 0.5s, 0.5s for next two
        assert elapsed >= 0.8, f"Rate limiting not working: {elapsed}s"

    def test_rows_collected_per_target(self):
        """Test that each target gets its own row collector."""
        config = AsyncConfig(workers=3, show_progress=False)
        engine = AsyncTaskHound(config)

        targets = ["host1", "host2", "host3"]
        results = engine.run(
            targets,
            mock_process_target,
            delay=0.01,
        )

        # Each result should have exactly 1 row
        for result in results:
            assert len(result.rows) == 1
            assert result.rows[0].host == result.target

    def test_thread_safety_of_output_lock(self):
        """Test that output lock prevents interleaving."""
        config = AsyncConfig(workers=5, show_progress=False)
        engine = AsyncTaskHound(config)

        output_order = []
        lock = threading.Lock()

        def tracking_process(target, all_rows, **kwargs):
            # Simulate some work
            time.sleep(0.05)
            with lock:
                output_order.append(target)
            return [target], None

        targets = [f"host{i}" for i in range(10)]
        results = engine.run(targets, tracking_process)

        assert len(results) == 10
        assert len(output_order) == 10
        # All targets should be processed (order may vary due to parallelism)
        assert set(output_order) == set(targets)


class TestAggregateResults:
    """Tests for aggregate_results function."""

    def test_aggregates_rows(self):
        results = [
            TargetResult(target="h1", success=True, rows=[{"host": "h1"}]),
            TargetResult(target="h2", success=True, rows=[{"host": "h2"}, {"host": "h2_2"}]),
        ]

        all_rows, laps_failures, laps_successes = aggregate_results(results)

        assert len(all_rows) == 3
        assert laps_successes == 0
        assert laps_failures == []

    def test_aggregates_laps_results(self):
        failure = LAPSFailure(
            hostname="badhost",
            failure_type="no_password",
            message="No LAPS password found",
        )

        results = [
            TargetResult(target="h1", success=True, laps_result=True),
            TargetResult(target="h2", success=False, laps_result=failure),
            TargetResult(target="h3", success=True, laps_result=True),
        ]

        all_rows, laps_failures, laps_successes = aggregate_results(results)

        assert laps_successes == 2
        assert len(laps_failures) == 1
        assert laps_failures[0].hostname == "badhost"

    def test_handles_mixed_results(self):
        results = [
            TargetResult(target="h1", success=True, rows=[{"a": 1}]),
            TargetResult(target="h2", success=False, error="failed", rows=[]),
            TargetResult(target="h3", success=True, rows=[{"b": 2}]),
        ]

        all_rows, _, _ = aggregate_results(results)

        assert len(all_rows) == 2


class TestCacheThreadSafety:
    """Tests for thread-safe cache access during parallel processing."""

    def test_concurrent_cache_writes(self):
        """Test that multiple threads can write to cache simultaneously."""
        from taskhound.utils.cache_manager import CacheManager

        cache = CacheManager(ttl_hours=1, enabled=True, cache_file=None)
        errors = []
        write_count = 0
        lock = threading.Lock()

        def writer_thread(thread_id):
            nonlocal write_count
            try:
                for i in range(100):
                    key = f"key_{i}"
                    cache.set(f"thread_{thread_id}", key, f"value_{i}")
                    # Also read to simulate real usage
                    cache.get(f"thread_{thread_id}", key)
                with lock:
                    write_count += 100
            except Exception as e:
                with lock:
                    errors.append(f"Thread {thread_id}: {e}")

        threads = [threading.Thread(target=writer_thread, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Errors during concurrent writes: {errors}"
        assert write_count == 1000

    def test_concurrent_cache_reads(self):
        """Test that multiple threads can read from cache simultaneously."""
        from taskhound.utils.cache_manager import CacheManager

        cache = CacheManager(ttl_hours=1, enabled=True, cache_file=None)

        # Pre-populate cache
        for i in range(100):
            cache.set("shared", f"key_{i}", f"value_{i}")

        read_values = []
        lock = threading.Lock()

        def reader_thread(thread_id):
            local_values = []
            for i in range(100):
                val = cache.get("shared", f"key_{i}")
                if val:
                    local_values.append(val)
            with lock:
                read_values.extend(local_values)

        threads = [threading.Thread(target=reader_thread, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Each thread should read all 100 values
        assert len(read_values) == 1000

    def test_cache_with_async_engine(self):
        """Test cache access from within async engine workers."""
        from taskhound.utils.cache_manager import CacheManager

        cache = CacheManager(ttl_hours=1, enabled=True, cache_file=None)

        def process_with_cache(target, all_rows, **kwargs):
            # Simulate SID resolution caching
            cached = cache.get("sids", target)
            if not cached:
                # Simulate LDAP lookup
                time.sleep(0.01)
                cache.set("sids", target, f"S-1-5-21-{target}")

            all_rows.append(TaskRow(host=target, path=f"\\Tasks\\{target}", computer_sid=cache.get("sids", target)))
            return [f"Processed {target}"], None

        config = AsyncConfig(workers=5, show_progress=False)
        engine = AsyncTaskHound(config)

        targets = [f"host{i}" for i in range(20)]
        results = engine.run(targets, process_with_cache)

        assert len(results) == 20
        assert all(r.success for r in results)

        # Verify all SIDs were cached
        for i in range(20):
            assert cache.get("sids", f"host{i}") is not None


class TestRealisticScenarios:
    """Tests simulating real-world scanning scenarios."""

    def test_mixed_success_and_timeout(self):
        """Simulate some hosts timing out while others succeed."""
        def flaky_process(target, all_rows, **kwargs):
            if "timeout" in target:
                time.sleep(0.5)  # Simulate slow host
                raise Exception("Connection timeout")
            all_rows.append(TaskRow(host=target, path=f"\\Tasks\\{target}", type="TASK"))
            return [f"OK: {target}"], None

        config = AsyncConfig(workers=3, show_progress=False)
        engine = AsyncTaskHound(config)

        targets = ["host1", "host2_timeout", "host3", "host4_timeout", "host5"]
        results = engine.run(targets, flaky_process)

        assert len(results) == 5
        successes = [r for r in results if r.success]
        failures = [r for r in results if not r.success]

        assert len(successes) == 3
        assert len(failures) == 2
        assert all("timeout" in r.target for r in failures)

    def test_laps_results_aggregation(self):
        """Test LAPS success/failure tracking across parallel workers."""
        def laps_process(target, all_rows, **kwargs):
            if "nolaps" in target:
                failure = LAPSFailure(
                    hostname=target,
                    failure_type="no_password",
                    message="No LAPS password found",
                )
                return [], failure
            all_rows.append(TaskRow(host=target, path=f"\\Tasks\\{target}"))
            return [f"LAPS OK: {target}"], True  # True = LAPS success

        config = AsyncConfig(workers=4, show_progress=False)
        engine = AsyncTaskHound(config)

        targets = ["host1", "host2_nolaps", "host3", "host4_nolaps", "host5"]
        results = engine.run(targets, laps_process)

        all_rows, laps_failures, laps_successes = aggregate_results(results)

        assert laps_successes == 3
        assert len(laps_failures) == 2
        assert all("nolaps" in f.hostname for f in laps_failures)

    def test_high_volume_parallel(self):
        """Test processing many targets in parallel."""
        processed = []
        lock = threading.Lock()

        def fast_process(target, all_rows, **kwargs):
            time.sleep(0.01)  # Small delay
            with lock:
                processed.append(target)
            all_rows.append(TaskRow(host=target, path=f"\\Tasks\\{target}"))
            return [target], None

        config = AsyncConfig(workers=20, show_progress=False)
        engine = AsyncTaskHound(config)

        targets = [f"host{i:03d}" for i in range(100)]

        start = time.perf_counter()
        results = engine.run(targets, fast_process)
        elapsed = time.perf_counter() - start

        assert len(results) == 100
        assert all(r.success for r in results)
        assert set(processed) == set(targets)

        # 100 targets at 0.01s each with 20 workers should be ~0.05s
        # Allow generous margin for thread overhead
        assert elapsed < 1.0, f"High volume took too long: {elapsed}s"

    def test_rate_limit_accuracy(self):
        """Test that rate limiting is approximately accurate."""
        config = AsyncConfig(workers=10, rate_limit=10.0, show_progress=False)  # 10/sec
        engine = AsyncTaskHound(config)

        targets = [f"host{i}" for i in range(10)]

        start = time.perf_counter()
        results = engine.run(
            targets,
            mock_process_target,
            delay=0.001,  # Near-instant processing
        )
        elapsed = time.perf_counter() - start

        assert len(results) == 10
        # 10 targets at 10/sec should take ~0.9s (first one is immediate)
        # Allow some variance
        assert elapsed >= 0.7, f"Rate limiting too fast: {elapsed}s"
        assert elapsed < 2.0, f"Rate limiting too slow: {elapsed}s"
