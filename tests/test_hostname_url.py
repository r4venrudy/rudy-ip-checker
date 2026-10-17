import unittest
from rudy_runtime.formatting import hostname_from
class HostnameUrlTests(unittest.TestCase):
 def test_query_fragment_and_idn(self):
  for value in ['https://Example.com?q=1','example.com#section','https://example.com:8443?query']:
   self.assertEqual(hostname_from(value),'example.com')
  self.assertEqual(hostname_from('пример.рф'),'xn--e1afmkfd.xn--p1ai')
  for value in ['https://user:pass@example.com','https://example.com:bad','https://example.com:0','ftp://example.com','example.com\\evil']:
   self.assertIsNone(hostname_from(value),value)
