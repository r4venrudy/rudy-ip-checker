import json
import tempfile
import unittest
from pathlib import Path
from rudy_runtime.config import load_config

class StrictConfigurationJsonTests(unittest.TestCase):
    def test_non_json_constants_and_duplicate_keys_are_not_silently_interpreted(self):
        cases=['{"TOKEN":"first","TOKEN":"second"}', r'{"TOKEN":"first","\u0054OKEN":"second"}', '{"TOKEN":"dummy","nested":{"x":1,"x":2}}']
        cases += ['{"TOKEN":"dummy","extra":'+value+'}' for value in ['NaN','Infinity','-Infinity']]
        with tempfile.TemporaryDirectory() as temp:
            filename=Path(temp)/'config.json'
            for raw in cases:
                filename.write_text(raw,encoding='utf-8');original=filename.read_bytes()
                with self.assertRaisesRegex(ValueError,'duplicate|NaN|Infinity'):
                    load_config({'TOKEN':'DISCORD_TOKEN'},env={},filename=filename)
                self.assertEqual(filename.read_bytes(),original)
            filename.write_text('{"TOKEN":"dummy","nested":{"x":1},"array":[{"x":2},{"x":3}]}')
            self.assertEqual(load_config({'TOKEN':'DISCORD_TOKEN'},env={},filename=filename)['TOKEN'],'dummy')
