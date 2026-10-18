import asyncio
import unittest

from rudy_runtime.rate_limit import SlidingWindowRateLimiter


class SlidingWindowRateLimiterTests(unittest.IsolatedAsyncioTestCase):
    def test_invalid_limits_are_rejected(self):
        for limit, window in (
            (0, 60), (-1, 60), (1.5, 60), (1, 0), (1, -1),
            (1, float("nan")), (1, float("inf")), (1, True),
        ):
            with self.subTest(limit=limit, window=window), self.assertRaises(ValueError):
                SlidingWindowRateLimiter(limit, window)

    async def test_requests_wait_for_the_oldest_slot_in_a_rolling_window(self):
        now = [0.0]

        async def sleep(seconds):
            now[0] += seconds

        limiter = SlidingWindowRateLimiter(4, 60, clock=lambda: now[0], sleep=sleep)
        started = []

        async def request():
            await limiter.acquire()
            started.append(now[0])

        await asyncio.gather(*(request() for _ in range(5)))
        self.assertEqual(started, [0.0, 0.0, 0.0, 0.0, 60.0])

    async def test_cancelled_wait_does_not_consume_a_future_slot(self):
        now = [0.0]

        async def sleep(_seconds):
            await asyncio.Event().wait()

        limiter = SlidingWindowRateLimiter(1, 60, clock=lambda: now[0], sleep=sleep)
        await limiter.acquire()
        waiting = asyncio.create_task(limiter.acquire())
        await asyncio.sleep(0)
        waiting.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await waiting

        now[0] = 60.0
        await limiter.acquire()


if __name__ == "__main__":
    unittest.main()
