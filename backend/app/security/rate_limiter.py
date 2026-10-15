"""Token-bucket rate limiter for denial-of-service defense per docs/security-design.md."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional


DEFAULT_RATE_LIMIT_PER_SECOND: float = 10.0
DEFAULT_BURST_CAPACITY: float = 20.0
BUCKET_EXPIRY_SECONDS: float = 300.0


@dataclass(frozen=True)
class RateLimitResult:
    """Outcome of a rate-limit consumption request."""

    allowed: bool
    tokens_remaining: float
    retry_after_seconds: float


class _TokenBucket:
    """Internal state representation for an individual client token bucket."""

    def __init__(self, capacity: float, refill_rate: float, now: float) -> None:
        self.capacity = float(capacity)
        self.refill_rate = float(refill_rate)
        self.tokens = float(capacity)
        self.last_update = float(now)

    def refill(self, now: float) -> None:
        elapsed = max(0.0, now - self.last_update)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_update = now

    def consume(self, cost: float, now: float) -> RateLimitResult:
        self.refill(now)
        if self.tokens >= cost:
            self.tokens -= cost
            return RateLimitResult(allowed=True, tokens_remaining=self.tokens, retry_after_seconds=0.0)

        missing = cost - self.tokens
        retry_after = missing / self.refill_rate if self.refill_rate > 0 else 1.0
        return RateLimitResult(allowed=False, tokens_remaining=self.tokens, retry_after_seconds=retry_after)


class TokenBucketRateLimiter:
    """Thread-safe Token Bucket rate limiter with monotonic time and bounded storage.
    
    Guarantees:
    1. Sustained rate limiting (default: 10 requests/sec).
    2. Burst tolerance (default: 20 requests).
    3. Monotonic timing prevents system clock drift tampering.
    4. Automatically purges idle buckets to bound memory footprint.
    """

    def __init__(
        self,
        refill_rate_per_second: float = DEFAULT_RATE_LIMIT_PER_SECOND,
        burst_capacity: float = DEFAULT_BURST_CAPACITY,
        clock_func: Optional[Callable[[], float]] = None,
        max_tracked_clients: int = 10_000,
        refill_rate: Optional[float] = None,
        capacity: Optional[float] = None,
    ) -> None:
        self.refill_rate = float(
            refill_rate if refill_rate is not None else refill_rate_per_second
        )
        self.burst_capacity = float(
            capacity if capacity is not None else burst_capacity
        )
        self.clock = clock_func or time.monotonic
        self.max_clients = max_tracked_clients

        self._buckets: dict[str, _TokenBucket] = {}
        self._lock = threading.Lock()

    def consume(self, client_key: str, cost: float = 1.0) -> RateLimitResult:
        """Attempt to consume tokens for the given client identifier."""
        now = self.clock()

        with self._lock:
            # Housekeeping if client limit reached
            if len(self._buckets) >= self.max_clients and client_key not in self._buckets:
                self._purge_stale_buckets(now)

            if client_key not in self._buckets:
                self._buckets[client_key] = _TokenBucket(
                    capacity=self.burst_capacity,
                    refill_rate=self.refill_rate,
                    now=now,
                )

            bucket = self._buckets[client_key]
            return bucket.consume(cost, now)

    def _purge_stale_buckets(self, now: float) -> None:
        """Evict buckets that have been inactive for more than BUCKET_EXPIRY_SECONDS."""
        stale_keys = [
            k for k, b in self._buckets.items() if (now - b.last_update) > BUCKET_EXPIRY_SECONDS
        ]
        for k in stale_keys:
            self._buckets.pop(k, None)

        # Hard clamp if still above limit
        if len(self._buckets) >= self.max_clients:
            oldest_key = min(self._buckets, key=lambda k: self._buckets[k].last_update)
            self._buckets.pop(oldest_key, None)

    def reset(self, client_key: Optional[str] = None) -> None:
        """Reset rate limiter state (for a specific client or all)."""
        with self._lock:
            if client_key:
                self._buckets.pop(client_key, None)
            else:
                self._buckets.clear()
