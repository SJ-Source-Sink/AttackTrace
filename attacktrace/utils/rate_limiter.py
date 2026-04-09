"""
Rate limiting utilities for API calls and network requests.
"""

import asyncio
import time
from collections import deque
from typing import Optional


class RateLimiter:
    """
    Async rate limiter using sliding window algorithm.

    Usage:
        limiter = RateLimiter(rate=10, per=1.0)  # 10 requests per second

        async with limiter:
            await make_request()
    """

    def __init__(self, rate: int, per: float = 1.0):
        """
        Initialize rate limiter.

        Args:
            rate: Maximum number of requests allowed
            per: Time window in seconds
        """
        self.rate = rate
        self.per = per
        self.timestamps: deque = deque()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire permission to make a request."""
        async with self._lock:
            now = time.monotonic()

            # Remove timestamps outside the window
            while self.timestamps and now - self.timestamps[0] > self.per:
                self.timestamps.popleft()

            # Check if we're at the rate limit
            if len(self.timestamps) >= self.rate:
                # Calculate sleep time
                sleep_time = self.timestamps[0] + self.per - now
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
                    now = time.monotonic()
                    # Clean up again after sleeping
                    while self.timestamps and now - self.timestamps[0] > self.per:
                        self.timestamps.popleft()

            self.timestamps.append(now)

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


class AdaptiveRateLimiter:
    """
    Rate limiter that adapts based on response status.

    Slows down when getting rate limited (429s) and speeds up
    when requests succeed.
    """

    def __init__(
        self,
        initial_rate: int = 10,
        min_rate: int = 1,
        max_rate: int = 100,
        per: float = 1.0,
    ):
        self.current_rate = initial_rate
        self.min_rate = min_rate
        self.max_rate = max_rate
        self.per = per
        self._limiter = RateLimiter(initial_rate, per)
        self._lock = asyncio.Lock()
        self._consecutive_success = 0

    async def acquire(self) -> None:
        """Acquire permission to make a request."""
        await self._limiter.acquire()

    async def report_success(self) -> None:
        """Report a successful request."""
        async with self._lock:
            self._consecutive_success += 1
            # Speed up after 10 consecutive successes
            if self._consecutive_success >= 10:
                self._consecutive_success = 0
                new_rate = min(self.max_rate, int(self.current_rate * 1.2))
                if new_rate != self.current_rate:
                    self.current_rate = new_rate
                    self._limiter = RateLimiter(self.current_rate, self.per)

    async def report_rate_limited(self) -> None:
        """Report that we got rate limited."""
        async with self._lock:
            self._consecutive_success = 0
            new_rate = max(self.min_rate, int(self.current_rate * 0.5))
            if new_rate != self.current_rate:
                self.current_rate = new_rate
                self._limiter = RateLimiter(self.current_rate, self.per)
            # Also add a backoff delay
            await asyncio.sleep(5.0)

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


class TokenBucket:
    """
    Token bucket rate limiter.

    Allows bursting up to bucket size while maintaining average rate.
    """

    def __init__(self, rate: float, bucket_size: int):
        """
        Initialize token bucket.

        Args:
            rate: Tokens per second to add
            bucket_size: Maximum tokens in bucket
        """
        self.rate = rate
        self.bucket_size = bucket_size
        self.tokens = bucket_size
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: int = 1) -> None:
        """Acquire tokens from the bucket."""
        async with self._lock:
            now = time.monotonic()

            # Add tokens based on time passed
            elapsed = now - self.last_update
            self.tokens = min(self.bucket_size, self.tokens + elapsed * self.rate)
            self.last_update = now

            # Wait if not enough tokens
            if self.tokens < tokens:
                wait_time = (tokens - self.tokens) / self.rate
                await asyncio.sleep(wait_time)
                self.tokens = tokens  # Will be decremented below

            self.tokens -= tokens

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass
