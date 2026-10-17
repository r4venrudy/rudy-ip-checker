import unittest
from rudy_runtime.formatting import summarize_virustotal
class AnalysisTimestampTests(unittest.TestCase):
 def test_unrepresentable_dates_preserve_analysis_counts(self):
  for stamp in [10**30,-10**30,True]:
   out=summarize_virustotal({'data':{'attributes':{'last_analysis_stats':{'malicious':2},'last_analysis_date':stamp}}})
   self.assertIn('2 malicious',out[0])
   self.assertFalse(any(line.startswith('Last analysed:') for line in out))
