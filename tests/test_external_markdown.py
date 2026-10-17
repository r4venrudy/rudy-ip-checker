import unittest
from rudy_runtime.formatting import summarize_virustotal,summarize_abuseipdb,summarize_shodan
class ExternalMarkdownTests(unittest.TestCase):
 def test_engine_and_usage_values_are_escaped(self):
  out=summarize_virustotal({'data':{'attributes':{'last_analysis_stats':{'malicious':1},'last_analysis_results':{'*engine*':{'category':'malicious'}}}}})
  self.assertIn(r'Flagged by: \*engine\*',out)
  self.assertIn(r'Usage type: \*host\*',summarize_abuseipdb({'data':{'abuseConfidenceScore':0,'usageType':'*host*'}}))
  self.assertIn(r'Known CVEs: \*label\*',summarize_shodan({'vulns':['*label*']}))
