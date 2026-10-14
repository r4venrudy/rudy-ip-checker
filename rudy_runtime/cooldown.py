"""Per-user cooldown so one person cannot use up the Shodan and VirusTotal quotas with back-to-back lookups."""

import time


def seconds_from_env(value, default):
    """Parse COOLDOWN_SECONDS: empty means the default, negative or invalid falls back to the default too,
    so a typo in the environment cannot stop the bot from starting."""
    try:
        seconds = int(value) if value not in (None, "") else default
    except ValueError:
        return default
    return seconds if seconds >= 0 else default


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
