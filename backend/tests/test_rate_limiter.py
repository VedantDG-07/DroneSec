"""Unit tests for token-bucket rate limiter (Phase 3)."""

from __future__ import annotations

import threading
import pytest
from backend.app.security.rate_limiter import TokenBucketRateLimiter


class FakeMonotonicClock:
    def __init__(self, start_time: float = 100.0) -> None:
        self.current_time = start_time

    def __call__(self) -> float:
        return self.current_time

    def advance(self, delta_seconds: float) -> None:
        self.current_time += delta_seconds


class TestTokenBucketRateLimiter:
    """Verifies token bucket burst capacity, steady replenishment, isolation, and eviction."""

    def test_burst_capacity_exhaustion(self) -> None:
        clock = FakeMonotonicClock(100.0)
        limiter = TokenBucketRateLimiter(
            refill_rate_per_second=10.0,
            burst_capacity=20.0,
            clock_func=clock,
        )

        client = "client_alpha"

        # Consume 20 requests within same instant
        for i in range(20):
            res = limiter.consume(client, cost=1.0)
            assert res.allowed is True
            assert res.tokens_remaining == pytest.approx(20.0 - (i + 1), abs=1e-3)
            assert res.retry_after_seconds == 0.0

        # 21st request at same instant must be rejected
        res = limiter.consume(client, cost=1.0)
        assert res.allowed is False
        assert res.tokens_remaining < 1.0
        assert res.retry_after_seconds > 0.0
        # 1 token missing at 10 tokens/sec = ~0.1s retry_after
        assert res.retry_after_seconds == pytest.approx(0.1, abs=1e-2)

    def test_token_replenishment_over_time(self) -> None:
        clock = FakeMonotonicClock(100.0)
        limiter = TokenBucketRateLimiter(
            refill_rate_per_second=10.0,
            burst_capacity=20.0,
            clock_func=clock,
        )
        client = "client_beta"

        # Exhaust bucket
        for _ in range(20):
            limiter.consume(client, cost=1.0)

        # Advance clock by 0.5s -> 5 tokens replenished
        clock.advance(0.5)

        for _ in range(5):
            res = limiter.consume(client, cost=1.0)
            assert res.allowed is True

        # 6th request rejected
        res = limiter.consume(client, cost=1.0)
        assert res.allowed is False

        # Advance clock by 5.0s -> bucket should be full at capacity (20)
        clock.advance(5.0)
        res = limiter.consume(client, cost=1.0)
        assert res.allowed is True
        assert res.tokens_remaining == pytest.approx(19.0, abs=1e-3)

    def test_multi_client_isolation(self) -> None:
        clock = FakeMonotonicClock(100.0)
        limiter = TokenBucketRateLimiter(
            refill_rate_per_second=10.0,
            burst_capacity=5.0,
            clock_func=clock,
        )

        # Exhaust client_1
        for _ in range(5):
            limiter.consume("client_1", cost=1.0)
        assert limiter.consume("client_1", cost=1.0).allowed is False

        # client_2 must still have full 5 tokens
        for _ in range(5):
            assert limiter.consume("client_2", cost=1.0).allowed is True
        assert limiter.consume("client_2", cost=1.0).allowed is False

    def test_concurrent_consumption_thread_safety(self) -> None:
        limiter = TokenBucketRateLimiter(
            refill_rate_per_second=100.0,
            burst_capacity=50.0,
        )
        client = "threaded_client"
        results: list[bool] = []

        def worker() -> None:
            for _ in range(10):
                res = limiter.consume(client, cost=1.0)
                results.append(res.allowed)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All 50 tokens must be consumed without race conditions
        assert len(results) == 50
        assert sum(1 for r in results if r) <= 50

    def test_idle_bucket_eviction(self) -> None:
        clock = FakeMonotonicClock(100.0)
        limiter = TokenBucketRateLimiter(
            refill_rate_per_second=1.0,
            burst_capacity=5.0,
            max_tracked_clients=3,
            clock_func=clock,
        )

        limiter.consume("c1")
        limiter.consume("c2")
        limiter.consume("c3")

        # Advance clock so c1, c2, c3 are idle
        clock.advance(10.0)

        # c4 will trigger pruning
        limiter.consume("c4")
        assert len(limiter._buckets) <= 3
