import unittest
from rudy_runtime.formatting import clean_banner
class BannerControlsTests(unittest.TestCase):
 def test_terminal_controls_are_not_forwarded(self):
  self.assertEqual(clean_banner('\x1b[31mSSH-2.0\x1b[0m\x00\x07'),'SSH-2.0')
  self.assertEqual(clean_banner('hello\r\nworld'),'hello world')
