import unittest
from rudy_runtime.formatting import split_message
class MessageLimitTests(unittest.TestCase):
 def test_invalid_limits_raise_instead_of_looping(self):
  # Float fails immediately on the old implementation; following cases cover the loop regression.
  for limit in [1.5,0,-1,True,2001]:
   with self.assertRaises(ValueError): split_message('abc',limit)
  self.assertTrue(all(len(c)<=1 for c in split_message('abc',1)))
