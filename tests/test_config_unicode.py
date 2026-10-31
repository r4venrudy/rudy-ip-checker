import json
import tempfile
import unittest
from pathlib import Path
from rudy_runtime.config import load_config

class CredentialUnicodeTests(unittest.TestCase):
    def test_unpaired_surrogates_are_errors_and_valid_unicode_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            filename=Path(temp)/'config.json'
            for value in ['dummy-\ud800','dummy-\udfff','dummy-\udfff\ud800']:
                with self.assertRaisesRegex(ValueError,'Unicode'):
                    load_config({'TOKEN':'DISCORD_TOKEN'},env={'DISCORD_TOKEN':value},filename=filename)
                filename.write_text(json.dumps({'TOKEN':value}),encoding='utf-8')
                with self.assertRaisesRegex(ValueError,'Unicode'):
                    load_config({'TOKEN':'DISCORD_TOKEN'},env={},filename=filename)
            value='dummy-\u00e9-\U0001f600';filename.write_text(json.dumps({'TOKEN':value}),encoding='utf-8')
            self.assertEqual(load_config({'TOKEN':'DISCORD_TOKEN'},env={},filename=filename)['TOKEN'],value)
