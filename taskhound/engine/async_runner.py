# Async/parallel processing for multi-target scanning.
#
# This module provides ThreadPoolExecutor-based parallel processing for
# scanning multiple hosts. Uses threading (not asyncio) because SMB/RPC
# operations are blocking I/O.
#
# Thread-safety considerations:
# - CacheManager.session uses RLock for thread-safe dict access
# - SQLite WAL mode handles concurrent writes
# - Rich console handles thread-safe output
# - LAPS cache is read-only during parallel phase (pre-populated in CLI)
# - SID resolution is dynamic with benign race conditions (same value written)

import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from ..laps import LAPSFailure
from ..models.task import TaskRow
from ..utils.console import (
    console,
    good,
    info,
    print_scan_complete,
    status,
    warn,
)


@dataclass
class AsyncConfig:
    """Configuration for async/parallel processing."""

    workers: int = 10
    """Number of concurrent worker threads."""

    rate_limit: Optional[float] = None
    """Maximum targets per second. None = unlimited."""

    timeout: int = 30
    """Per-target timeout in seconds."""

    show_progress: bool = True
    """Show progress bar during processing."""

    jitter: Optional[float] = None
    """Random delay (0 to N seconds) between hosts. Only for sequential mode."""


@dataclass
class TargetResult:
    """Result from processing a single target."""

    target: str
    """Target IP or hostname."""

    success: bool
    """Whether processing succeeded."""

    skipped: bool = False
    """Whether target was skipped (e.g., dual-homed duplicate)."""

    lines: List[str] = field(default_factory=list)
    """Output lines from processing."""

    rows: List[TaskRow] = field(default_factory=list)
    """Structured data rows for export."""

    laps_result: Optional[Union[bool, LAPSFailure]] = None
    """LAPS authentication result if applicable."""

    error: Optional[str] = None
    """Error message if processing failed."""

    elapsed_ms: float = 0.0
    """Processing time in milliseconds."""


class AsyncTaskHound:
    """
    Parallel task scanner using ThreadPoolExecutor.

    Usage:
        async_engine = AsyncTaskHound(config=AsyncConfig(workers=20))
        results = async_engine.run(targets, process_fn, **kwargs)

    The process_fn should have the signature:
        def process_fn(target: str, all_rows: List[Dict], **kwargs) -> Tuple[List[str], Optional[LAPSResult]]
    """

    def __init__(self, config: Optional[AsyncConfig] = None):
        """
        Initialize async engine.

        Args:
            config: Async configuration. Uses defaults if not provided.
        """
        self.config = config or AsyncConfig()
        self._output_lock = threading.Lock()
        self._rate_semaphore: Optional[threading.Semaphore] = None
        self._rate_thread: Optional[threading.Thread] = None
        self._stop_rate_limiter = threading.Event()

        # Statistics
        self._completed = 0
        self._succeeded = 0
        self._failed = 0
        self._skipped = 0
        self._total = 0
        self._lock = threading.Lock()

        # Rich progress bar
        self._progress: Optional[Progress] = None
        self._task_id: Optional[TaskID] = None

    def _start_rate_limiter(self) -> None:
        """Start background thread that releases rate limiter tokens."""
        if self.config.rate_limit is None or self.config.rate_limit <= 0:
            return

        # Semaphore starts empty; background thread adds tokens at rate_limit/sec
        self._rate_semaphore = threading.Semaphore(0)
        self._stop_rate_limiter.clear()

        def token_generator():
            interval = 1.0 / self.config.rate_limit
            while not self._stop_rate_limiter.is_set():
                self._rate_semaphore.release()
                time.sleep(interval)

        self._rate_thread = threading.Thread(target=token_generator, daemon=True)
        self._rate_thread.start()

    def _stop_rate_limiter_thread(self) -> None:
        """Stop the rate limiter background thread."""
        if self._rate_thread:
            self._stop_rate_limiter.set()
            self._rate_thread.join(timeout=1.0)
            self._rate_thread = None
            self._rate_semaphore = None

    def _acquire_rate_token(self) -> None:
        """Wait for a rate limiter token before processing."""
        if self._rate_semaphore:
            self._rate_semaphore.acquire()

    def _process_single(
        self,
        target: str,
        process_fn: Callable,
        kwargs: Dict[str, Any],
    ) -> TargetResult:
        """
        Process a single target with rate limiting and error handling.

        Args:
            target: Target to process
            process_fn: Function to call for processing
            kwargs: Keyword arguments to pass to process_fn

        Returns:
            TargetResult with processing outcome
        """
        # Wait for rate limiter token
        self._acquire_rate_token()

        start_time = time.perf_counter()
        result = TargetResult(target=target, success=False)

        # Each worker gets its own row collector
        target_rows: List[TaskRow] = []

        try:
            # Call the actual processing function
            lines, laps_result = process_fn(
                target=target,
                all_rows=target_rows,
                **kwargs
            )

            # Check if processing actually succeeded by looking at rows
            # process_target adds TaskRow.failure() rows on connection errors
            has_failure = any(
                row.type == "FAILURE"
                for row in target_rows
            )

            # Check if target was skipped (dual-homed duplicate)
            # process_target adds TaskRow.skipped() rows for dual-homed hosts
            has_skipped = any(
                row.type == "SKIPPED"
                for row in target_rows
            )

            result.success = not has_failure and not has_skipped
            result.lines = lines
            result.rows = target_rows
            result.laps_result = laps_result

            # Mark as skipped only if explicitly flagged via SKIPPED row
            # (not just because results are empty after filtering)
            if has_skipped:
                result.skipped = True

            if has_failure:
                # Extract error reason from failure row
                for row in target_rows:
                    if row.type == "FAILURE":
                        result.error = row.reason or "Unknown failure"
                        break

        except Exception as e:
            result.error = str(e)
            result.rows = target_rows  # May have partial data

            # Log error with output lock
            with self._output_lock:
                warn(f"{target}: Processing failed: {e}")

        finally:
            # Clean up thread-local cache connection to avoid ResourceWarning
            from ..utils.cache_manager import get_cache
            cache = get_cache()
            if cache:
                cache.close_thread_connection()

        result.elapsed_ms = (time.perf_counter() - start_time) * 1000

        # Update progress
        with self._lock:
            self._completed += 1
            if result.skipped:
                self._skipped += 1
            elif result.success:
                self._succeeded += 1
            else:
                self._failed += 1

        # Update Rich progress bar
        if self._progress and self._task_id is not None:
            # Build status text
            if result.skipped:
                status_text = f"[yellow][~][/] {target} [dim](skipped)[/]"
            elif result.success:
                task_count = len([r for r in result.rows if r.type not in ("FAILURE", None)])
                len([r for r in result.rows if r.type in ("TIER-0", "PRIV")])
                status_text = f"[green][+][/] {target} ({task_count} tasks)"
            else:
                error_short = (result.error or "Error")[:30]
                status_text = f"[red][-][/] {target}: {error_short}"

            self._progress.update(self._task_id, advance=1, status=status_text)

        return result

    def run(
        self,
        targets: List[str],
        process_fn: Callable,
        **kwargs,
    ) -> List[TargetResult]:
        """
        Process multiple targets in parallel.

        Args:
            targets: List of target IPs or hostnames
            process_fn: Function to process each target. Should have signature:
                        process_fn(target, all_rows, **kwargs) -> (lines, laps_result)
            **kwargs: Additional arguments passed to process_fn

        Returns:
            List of TargetResult objects in completion order
        """
        if not targets:
            return []

        # Handle single-threaded mode (--threads 1)
        if self.config.workers == 1:
            return self._run_sequential(targets, process_fn, kwargs)

        self._total = len(targets)
        self._completed = 0
        self._succeeded = 0
        self._failed = 0
        self._skipped = 0
        results: List[TargetResult] = []
        start_time = time.perf_counter()

        status(f"[*] Starting parallel scan: {len(targets)} targets, {self.config.workers} workers")
        if self.config.rate_limit:
            info(f"Rate limit: {self.config.rate_limit} targets/second")

        # Start rate limiter if configured
        self._start_rate_limiter()

        # Create Rich progress bar
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]Scanning[/]"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TextColumn("│"),
            TimeRemainingColumn(),
            TextColumn("[dim]{task.fields[status]}[/]"),
            console=console,
            transient=False,
        )

        try:
            with progress:
                self._progress = progress
                self._task_id = progress.add_task(
                    "Scanning", total=len(targets), status=""
                )

                with ThreadPoolExecutor(max_workers=self.config.workers) as executor:
                    # Submit all tasks
                    futures = {
                        executor.submit(self._process_single, target, process_fn, kwargs): target
                        for target in targets
                    }

                    # Collect results as they complete
                    for future in as_completed(futures):
                        target = futures[future]
                        try:
                            result = future.result()
                            results.append(result)
                        except Exception as e:
                            # Should not happen since _process_single catches exceptions
                            results.append(TargetResult(
                                target=target,
                                success=False,
                                error=f"Unexpected error: {e}"
                            ))
        finally:
            self._progress = None
            self._task_id = None
            self._stop_rate_limiter_thread()

        # Print completion summary
        total_time = time.perf_counter() - start_time
        avg_time = (total_time / len(targets)) * 1000 if targets else 0
        print_scan_complete(self._succeeded, self._failed, total_time, avg_time, self._skipped)

        return results

    def _run_sequential(
        self,
        targets: List[str],
        process_fn: Callable,
        kwargs: Dict[str, Any],
    ) -> List[TargetResult]:
        """
        Run targets sequentially (--threads 1 mode).

        Behaves identically to the original non-async engine but with Rich progress.
        """
        self._total = len(targets)
        self._completed = 0
        self._succeeded = 0
        self._failed = 0
        self._skipped = 0
        results: List[TargetResult] = []
        start_time = time.perf_counter()

        jitter_msg = f" (jitter: 0-{self.config.jitter}s)" if self.config.jitter else ""
        info(f"Sequential scan: {len(targets)} targets{jitter_msg}")

        # Create Rich progress bar for sequential mode too
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]Scanning[/]"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TextColumn("│"),
            TimeRemainingColumn(),
            TextColumn("[dim]{task.fields[status]}[/]"),
            console=console,
            transient=False,
        )

        with progress:
            task_id = progress.add_task("Scanning", total=len(targets), status="")

            for target in targets:
                # Apply jitter delay before scanning (skip first target)
                if self.config.jitter and results:  # Skip delay for first target
                    jitter_delay = random.uniform(0, self.config.jitter)
                    progress.update(task_id, status=f"[dim]Waiting {jitter_delay:.1f}s...[/]")
                    time.sleep(jitter_delay)

                result = TargetResult(target=target, success=False)
                target_rows: List[TaskRow] = []
                target_start = time.perf_counter()

                try:
                    lines, laps_result = process_fn(
                        target=target,
                        all_rows=target_rows,
                        **kwargs
                    )

                    # Check for failure rows
                    has_failure = any(
                        row.type == "FAILURE"
                        for row in target_rows
                    )

                    # Check if target was skipped (dual-homed duplicate)
                    has_skipped = any(
                        row.type == "SKIPPED"
                        for row in target_rows
                    )

                    result.success = not has_failure and not has_skipped
                    result.lines = lines
                    result.rows = target_rows
                    result.laps_result = laps_result

                    # Mark as skipped only if explicitly flagged via SKIPPED row
                    if has_skipped:
                        result.skipped = True

                    if has_failure:
                        for row in target_rows:
                            if row.type == "FAILURE":
                                result.error = row.reason or "Unknown failure"
                                break

                except Exception as e:
                    result.error = str(e)
                    result.rows = target_rows
                    warn(f"{target}: Processing failed: {e}")

                result.elapsed_ms = (time.perf_counter() - target_start) * 1000
                results.append(result)

                self._completed += 1
                if result.skipped:
                    self._skipped += 1
                    status_text = f"[yellow][~][/] {target} [dim](skipped)[/]"
                elif result.success:
                    self._succeeded += 1
                    task_count = len([r for r in result.rows if r.type not in ("FAILURE", None)])
                    status_text = f"[green][+][/] {target} ({task_count} tasks)"
                else:
                    self._failed += 1
                    error_short = (result.error or "Error")[:30]
                    status_text = f"[red][-][/] {target}: {error_short}"

                progress.update(task_id, advance=1, status=status_text)

        # Print completion summary
        total_time = time.perf_counter() - start_time
        avg_time = (total_time / len(targets)) * 1000 if targets else 0
        print_scan_complete(self._succeeded, self._failed, total_time, avg_time, self._skipped)

        return results

    def print_results_threadsafe(self, lines: List[str], print_fn: Callable[[List[str]], None]) -> None:
        """
        Print results with output lock to prevent interleaving.

        Args:
            lines: Lines to print
            print_fn: Function to print lines (typically print_results from cli.py)
        """
        with self._output_lock:
            print_fn(lines)


def aggregate_results(results: List[TargetResult]) -> Tuple[List[TaskRow], List[LAPSFailure], int]:
    """
    Aggregate results from parallel processing.

    Args:
        results: List of TargetResult objects

    Returns:
        Tuple of (all_rows, laps_failures, laps_successes)
    """
    all_rows: List[TaskRow] = []
    laps_failures: List[LAPSFailure] = []
    laps_successes = 0

    for result in results:
        all_rows.extend(result.rows)

        if result.laps_result is not None:
            if result.laps_result is True:
                laps_successes += 1
            elif isinstance(result.laps_result, LAPSFailure):
                laps_failures.append(result.laps_result)

    return all_rows, laps_failures, laps_successes


def print_summary(
    results: List[TargetResult],
    laps_failures: List[LAPSFailure],
    laps_successes: int,
    total_time_ms: float,
) -> None:
    """
    Print summary statistics after parallel processing.

    Args:
        results: List of TargetResult objects
        laps_failures: List of LAPS failures
        laps_successes: Count of LAPS successes
        total_time_ms: Total processing time in milliseconds
    """
    total = len(results)
    succeeded = sum(1 for r in results if r.success)
    failed = total - succeeded

    avg_time = sum(r.elapsed_ms for r in results) / total if total > 0 else 0

    good(f"\n{'=' * 60}")
    good(f"Scan Complete: {succeeded}/{total} targets succeeded")
    if failed > 0:
        warn(f"  Failed: {failed} targets")

    # LAPS summary if applicable
    if laps_successes > 0 or laps_failures:
        total_laps = laps_successes + len(laps_failures)
        info(f"  LAPS: {laps_successes}/{total_laps} successful")
        if laps_failures:
            for failure in laps_failures:
                warn(f"    - {failure.hostname}: {failure.failure_type}")

    info(f"  Total time: {total_time_ms / 1000:.2f}s")
    info(f"  Avg per target: {avg_time:.0f}ms")
    good(f"{'=' * 60}\n")
