import unittest
from rudy_runtime.formatting import summarize_rdap
class NestedContactTests(unittest.TestCase):
 def test_deep_abuse_contacts_are_found(self):
  abuse={'roles':['abuse'],'vcardArray':['vcard',[['email',{},'text','abuse@example.com']]]}
  tree={'entities':[{'entities':[{'entities':[abuse]}]}]}
  self.assertIn('Abuse contact: abuse@example.com',summarize_rdap(tree))
  # In-memory cycles should not hang a formatter; JSON itself cannot encode them.
  cycle={'entities':[]}; cycle['entities'].append(cycle)
  self.assertEqual(summarize_rdap(cycle),[])

class ContactPrecedenceTests(unittest.TestCase):
 def test_registry_entity_order_is_preserved(self):
  def contact(name): return {'roles':['registrant'],'vcardArray':['vcard',[['fn',{},'text',name]]]}
  self.assertIn('Owner: First',summarize_rdap({'entities':[contact('First'),contact('Second')]}))
