import unittest

from rudy_runtime.cooldown import Cooldown


class CooldownTests(unittest.TestCase):
    def test_user_waits_and_others_are_free(self):
        now = [100.0]
        cd = Cooldown(30, clock=lambda: now[0])
        self.assertEqual(cd.take(1), 0)
        self.assertEqual(cd.take(2), 0)
        now[0] += 10
        self.assertEqual(cd.take(1), 20)
        now[0] += 20
        self.assertEqual(cd.take(1), 0)

    def test_zero_disables(self):
        cd = Cooldown(0, clock=lambda: 5.0)
        self.assertEqual(cd.take(1), 0)
        self.assertEqual(cd.take(1), 0)
