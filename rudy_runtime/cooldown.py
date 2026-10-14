"""Per-user cooldown so one person cannot use up the Shodan and VirusTotal quotas with back-to-back lookups."""

import time


class Cooldown:
    def __init__(self, seconds, clock=time.monotonic):
        self.seconds = seconds
        self.clock = clock
        self._last = {}

    def take(self, user_id):
        """Return 0 and record the use when allowed, otherwise the seconds left to wait."""
        now = self.clock()
        left = self._last.get(user_id, float("-inf")) + self.seconds - now
        if left > 0:
            return left
        self._last[user_id] = now
        if len(self._last) > 1000:
            self._last = {u: t for u, t in self._last.items() if now - t < self.seconds}
        return 0
