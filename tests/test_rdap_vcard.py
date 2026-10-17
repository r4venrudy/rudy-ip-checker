import unittest
from rudy_runtime.formatting import summarize_rdap
class SparseVcardTests(unittest.TestCase):
 def test_partial_registry_cards_do_not_drop_the_report(self):
  for card in [[],['vcard'],['vcard',None],['vcard',[['email'],None,7]],'invalid']:
   result=summarize_rdap({'name':'NET','entities':[{'roles':['abuse'],'vcardArray':card}]})
   self.assertIn('Network: NET',result)
