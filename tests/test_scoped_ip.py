import unittest
from rudy_runtime.formatting import canonical_ip
class ScopedAddressTests(unittest.TestCase):
 def test_zone_ids_are_not_public_api_addresses(self):
  self.assertIsNone(canonical_ip('2001:4860:4860::8888%eth0'))
  self.assertIsNone(canonical_ip('fe80::1%12'))
  self.assertEqual(canonical_ip('2001:4860:4860::8888'),'2001:4860:4860::8888')
