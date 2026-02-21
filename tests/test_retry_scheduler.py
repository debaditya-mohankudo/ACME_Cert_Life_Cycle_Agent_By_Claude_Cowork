"""
Tests for the retry_scheduler node.

These tests verify that the scheduler correctly applies backoff delays
before allowing a retry to proceed.
"""
import asyncio
import time

import pytest

from agent.nodes.retry_scheduler import retry_scheduler, retry_scheduler_async


class TestRetrySchedulerSync:
    """Synchronous retry_scheduler tests."""

    def test_no_scheduled_retry_passes_through(self):
        """If retry_not_before is None, scheduler passes through immediately."""
        state = {"retry_not_before": None}
        result = retry_scheduler(state)
        assert result == {}

    def test_past_retry_time_doesnt_wait(self):
        """If retry_not_before is in the past, scheduler proceeds immediately."""
        past_time = time.time() - 10  # 10 seconds ago
        state = {"retry_not_before": past_time}

        start = time.time()
        result = retry_scheduler(state)
        elapsed = time.time() - start

        assert result == {"retry_not_before": None}
        assert elapsed < 0.5  # Should be nearly instant

    def test_future_retry_time_waits(self):
        """If retry_not_before is in the future, scheduler waits."""
        wait_duration = 0.5  # 500ms
        future_time = time.time() + wait_duration
        state = {"retry_not_before": future_time}

        start = time.time()
        result = retry_scheduler(state)
        elapsed = time.time() - start

        assert result == {"retry_not_before": None}
        assert elapsed >= wait_duration
        assert elapsed < wait_duration + 0.2  # Allow 200ms tolerance

    def test_clears_retry_not_before(self):
        """After applying backoff, retry_not_before is cleared from state."""
        past_time = time.time() - 1
        state = {"retry_not_before": past_time}
        result = retry_scheduler(state)
        assert result["retry_not_before"] is None

    def test_long_backoff(self):
        """Test with longer backoff duration (1 second)."""
        wait_duration = 1.0
        future_time = time.time() + wait_duration
        state = {"retry_not_before": future_time}

        start = time.time()
        result = retry_scheduler(state)
        elapsed = time.time() - start

        assert elapsed >= wait_duration
        assert elapsed < wait_duration + 0.3


class TestRetrySchedulerAsync:
    """Asynchronous retry_scheduler_async tests."""

    @pytest.mark.asyncio
    async def test_async_no_scheduled_retry(self):
        """Async scheduler passes through if no retry scheduled."""
        state = {"retry_not_before": None}
        result = await retry_scheduler_async(state)
        assert result == {}

    @pytest.mark.asyncio
    async def test_async_past_retry_time_doesnt_wait(self):
        """Async scheduler proceeds immediately if retry time is past."""
        past_time = time.time() - 10
        state = {"retry_not_before": past_time}

        start = time.time()
        result = await retry_scheduler_async(state)
        elapsed = time.time() - start

        assert result == {"retry_not_before": None}
        assert elapsed < 0.5

    @pytest.mark.asyncio
    async def test_async_future_retry_time_waits(self):
        """Async scheduler awaits if retry time is in the future."""
        wait_duration = 0.5
        future_time = time.time() + wait_duration
        state = {"retry_not_before": future_time}

        start = time.time()
        result = await retry_scheduler_async(state)
        elapsed = time.time() - start

        assert result == {"retry_not_before": None}
        assert elapsed >= wait_duration
        assert elapsed < wait_duration + 0.2

    @pytest.mark.asyncio
    async def test_async_non_blocking_during_backoff(self):
        """
        Async scheduler should not block other tasks during backoff.

        This is the key advantage of async: while scheduler awaits,
        other tasks can run concurrently.
        """
        wait_duration = 1.0
        future_time = time.time() + wait_duration
        state = {"retry_not_before": future_time}

        # Create a concurrent task that should run during backoff
        other_task_completed = False

        async def other_task():
            nonlocal other_task_completed
            await asyncio.sleep(0.3)  # Complete before scheduler finishes
            other_task_completed = True

        # Run both concurrently
        start = time.time()
        await asyncio.gather(
            retry_scheduler_async(state),
            other_task(),
        )
        total_time = time.time() - start

        # Key assertion: total time should be ~max(backoff, other_task)
        # Not sum(backoff, other_task), which would indicate blocking
        assert other_task_completed
        assert total_time >= wait_duration
        assert total_time < wait_duration + 0.3  # Should finish quickly after scheduler


class TestRetrySchedulerIntegration:
    """Integration tests with agent state."""

    def test_retry_scheduler_with_error_handler_state(self):
        """Test scheduler with state produced by error_handler."""
        # Simulate error_handler output
        import time as time_module
        now = time_module.time()

        state = {
            "current_domain": "api.example.com",
            "retry_count": 1,
            "retry_delay_seconds": 5,
            "retry_not_before": now + 0.2,  # 200ms wait
        }

        start = time_module.time()
        result = retry_scheduler(state)
        elapsed = time_module.time() - start

        assert result["retry_not_before"] is None
        assert elapsed >= 0.2

    @pytest.mark.asyncio
    async def test_multiple_domain_retries_concurrent(self):
        """
        Test that multiple domains can be retried concurrently
        without blocking each other (async advantage).
        """
        import time as time_module

        now = time_module.time()

        # Two domains, both need to retry
        domain_states = {
            "api.example.com": {"retry_not_before": now + 0.5},
            "web.example.com": {"retry_not_before": now + 0.5},
        }

        # Run both retries concurrently
        start = time_module.time()
        results = await asyncio.gather(
            retry_scheduler_async(domain_states["api.example.com"]),
            retry_scheduler_async(domain_states["web.example.com"]),
        )
        elapsed = time_module.time() - start

        # Both should complete in ~0.5s (concurrent)
        # NOT 1.0s (sequential)
        assert elapsed >= 0.5
        assert elapsed < 0.7  # Allow tolerance
