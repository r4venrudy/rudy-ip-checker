"""Async sliding-window limiter for shared third-party API quotas."""

import asyncio
import math
import time
from collections import deque


class SlidingWindowRateLimiter:
    def __init__(self, limit, window_seconds, clock=time.monotonic, sleep=asyncio.sleep):
        if type(limit) is not int or limit < 1:
            raise ValueError("limit must be a positive integer")
        valid_window = (
            not isinstance(window_seconds, bool)
            and isinstance(window_seconds, (int, float))
            and math.isfinite(window_seconds)
            and window_seconds > 0
        )
        if not valid_window:
            raise ValueError("window_seconds must be positive")
        self.limit = limit
        self.window_seconds = float(window_seconds)
        self.clock = clock
        self.sleep = sleep
        self._started = deque()
        self._lock = asyncio.Lock()

    async def acquire(self):
        """Wait until starting this request will stay within the rolling quota."""
        async with self._lock:
            while True:
                now = self.clock()
                while self._started and now - self._started[0] >= self.window_seconds:
                    self._started.popleft()
                if len(self._started) < self.limit:
                    self._started.append(now)
                    return
                await self.sleep(self.window_seconds - (now - self._started[0]))
