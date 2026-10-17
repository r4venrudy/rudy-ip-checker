import unittest
from rudy_runtime.formatting import summarize_greynoise,build_report
class GreyNoiseUnknownTests(unittest.TestCase):
 def test_empty_responses_do_not_imply_no_scanning(self):
  self.assertEqual(summarize_greynoise({}),['GreyNoise: no data'])
  self.assertIn('GreyNoise: no data',build_report('8.8.8.8',{'GreyNoise':{}},set()))
  self.assertEqual(summarize_greynoise({'noise':False,'riot':False}),['Not seen scanning the internet'])
  self.assertIn('AbuseIPDB: no data',build_report('8.8.8.8',{'AbuseIPDB':None},set()))
