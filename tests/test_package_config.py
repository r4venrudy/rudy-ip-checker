import json
import tempfile
import unittest
from pathlib import Path
from rudy_runtime.config import load_config

class ConfigTests(unittest.TestCase):
    def test_missing_names_only(self):
        with self.assertRaisesRegex(ValueError, 'Missing configuration: DISCORD_TOKEN'):
            load_config({'TOKEN':'DISCORD_TOKEN'}, env={}, filename='/does-not-exist-rudy')

    def test_env_precedence_and_no_file_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'config.json'
            path.write_text(json.dumps({'TOKEN':'old-dummy'}), encoding='utf-8')
            original=path.read_bytes()
            self.assertEqual(load_config({'TOKEN':'DISCORD_TOKEN'}, env={'DISCORD_TOKEN':'new-dummy'}, filename=path)['TOKEN'], 'new-dummy')
            self.assertEqual(path.read_bytes(), original)

    def test_placeholder_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Missing configuration'):
            load_config({'TOKEN':'DISCORD_TOKEN'}, env={'DISCORD_TOKEN':'YOUR_TOKEN'}, filename='/does-not-exist-rudy')
