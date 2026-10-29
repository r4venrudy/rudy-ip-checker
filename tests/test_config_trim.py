import json
import tempfile
import unittest
from pathlib import Path
from rudy_runtime.config import load_config

class TrimConfigTests(unittest.TestCase):
    def test_environment_and_file_tokens_are_normalized(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'config.json'
            path.write_text(json.dumps({'TOKEN':' file-dummy '}),encoding='utf-8')
            self.assertEqual(load_config({'TOKEN':'DISCORD_TOKEN'},env={},filename=path)['TOKEN'],'file-dummy')
            self.assertEqual(load_config({'TOKEN':'DISCORD_TOKEN'},env={'DISCORD_TOKEN':' \tdummy-env\n'},filename=path)['TOKEN'],'dummy-env')
            with self.assertRaisesRegex(ValueError,'Missing configuration'):
                load_config({'TOKEN':'DISCORD_TOKEN'},env={'DISCORD_TOKEN':'  YOUR_TOKEN  '},filename=path)
