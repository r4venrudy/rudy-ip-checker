import json
import tempfile
import unittest
from pathlib import Path
from rudy_runtime.config import load_config

class PlaceholderCaseTests(unittest.TestCase):
    def test_placeholder_spelling_is_case_insensitive(self):
        for value in ['your_token','YoUr_ToKeN','discord token','Your Client ID']:
            with self.assertRaisesRegex(ValueError,'Missing configuration: DISCORD_TOKEN'):
                load_config({'TOKEN':'DISCORD_TOKEN'},env={'DISCORD_TOKEN':value},filename='/does-not-exist-rudy')
        self.assertEqual(load_config({'TOKEN':'DISCORD_TOKEN'},env={'DISCORD_TOKEN':'dummy-valid-token'},filename='/does-not-exist-rudy')['TOKEN'],'dummy-valid-token')
