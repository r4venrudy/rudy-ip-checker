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

    def test_rudy_config_env_points_to_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'custom.json'
            path.write_text(json.dumps({'TOKEN':'from-file'}), encoding='utf-8')
            self.assertEqual(load_config({'TOKEN':'DISCORD_TOKEN'}, env={'RUDY_CONFIG':str(path)})['TOKEN'], 'from-file')

    def test_shipped_config_json_is_rejected_until_edited(self):
        repo=Path(__file__).resolve().parent.parent
        with self.assertRaisesRegex(ValueError, 'Missing configuration'):
            load_config({'TOKEN':'DISCORD_TOKEN'}, env={}, filename=repo/'config.json')

    def test_placeholder_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Missing configuration'):
            load_config({'TOKEN':'DISCORD_TOKEN'}, env={'DISCORD_TOKEN':'YOUR_TOKEN'}, filename='/does-not-exist-rudy')
