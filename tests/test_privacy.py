import unittest

from rudy_runtime.privacy import private_by_default


class PrivateByDefaultTests(unittest.TestCase):
    def test_missing_option_is_private(self):
        self.assertTrue(private_by_default(None))

    def test_explicit_private_remains_private(self):
        self.assertTrue(private_by_default(True))

    def test_public_reply_requires_explicit_opt_out(self):
        self.assertFalse(private_by_default(False))
