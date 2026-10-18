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

class MalformedOptionalRdapTests(unittest.TestCase):
 def test_invalid_event_entries_and_shapes_do_not_abort_the_report(self):
  result=summarize_rdap({
   'name':'NET',
   'events':[None,'registration',{'eventAction':'registration'}, {'eventAction':'last changed','eventDate':'2025-04-03T00:00:00Z'}],
   'entities':[{'roles':'abuse','vcardArray':['vcard',[['email',{},'text','wrong@example.com']]]},
               {'roles':['registrant'],'vcardArray':['vcard',[['fn',{},'text','Correct Owner']]]}],
  })
  self.assertIn('Network: NET',result)
  self.assertIn('Last changed: 2025-04-03',result)
  self.assertIn('Owner: Correct Owner',result)
  self.assertFalse(any('wrong@example.com' in line for line in result))

 def test_non_array_optional_collections_are_ignored(self):
  self.assertEqual(summarize_rdap({'events':{'eventAction':'registration'},'entities':{'roles':['abuse']}}),[])
