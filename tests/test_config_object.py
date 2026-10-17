import unittest
from rudy_runtime.config import load_config
from pathlib import Path
import tempfile
class ConfigObjectTests(unittest.TestCase):
 def test_bom_and_invalid_root(self):
  with tempfile.TemporaryDirectory() as directory:
   file=Path(directory)/'config.json'
   file.write_text('\ufeff{"TOKEN":"dummy"}',encoding='utf-8')
   self.assertEqual(load_config({'TOKEN':'DISCORD_TOKEN'},env={},filename=file)['TOKEN'],'dummy')
   for value in ['null','[]','"private"']:
    file.write_text(value,encoding='utf-8')
    with self.assertRaisesRegex(ValueError,'Configuration must be a JSON object'):
     load_config({'TOKEN':'DISCORD_TOKEN'},env={},filename=file)
