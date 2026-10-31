import json
import tempfile
import unittest
from pathlib import Path
from rudy_runtime.config import load_config

class SelectedConfigTests(unittest.TestCase):
    def test_selected_environment_path_requires_a_regular_file(self):
        with tempfile.TemporaryDirectory() as temp:
            missing=Path(temp)/'missing.json'
            for selected in [missing,Path(temp)]:
                with self.assertRaisesRegex(ValueError,'RUDY_CONFIG'):
                    load_config({'TOKEN':'DISCORD_TOKEN'},env={'RUDY_CONFIG':str(selected),'DISCORD_TOKEN':'dummy-env'})
            explicit=Path(temp)/'explicit.json';explicit.write_text('{"TOKEN":"dummy-file"}')
            self.assertEqual(load_config({'TOKEN':'DISCORD_TOKEN'},env={'RUDY_CONFIG':str(missing)},filename=explicit)['TOKEN'],'dummy-file')
            self.assertEqual(load_config({'TOKEN':'DISCORD_TOKEN'},env={'DISCORD_TOKEN':'dummy-env'},filename=missing)['TOKEN'],'dummy-env')
